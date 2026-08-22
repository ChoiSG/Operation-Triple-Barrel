from __future__ import annotations

import itertools
import json
import threading
from dataclasses import dataclass, field as dataclass_field
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

import pefile

from .artifacts import sha256_bytes, sha256_file
from .config import (
    KEYED_DECODERS,
    XOR_KEY_MAX_BYTES,
    XOR_KEY_MIN_BYTES,
    BuildConfig,
    REQUIRED_SLOTS,
    Recipe,
)
from .injectables import ImportSlot, collect_import_slots, plan_iat_repairs
from .modules import ModuleError, ModuleManifest, ModuleRegistry
from .profiles import ExecutionProfile, resolve_profile, resolve_toolchain_name
from .pe.invocation import (
    InvocationError,
    find_backdoor_site,
    resolve_invocation_target,
)
from .pe.planner import (
    HostLayout,
    PLACEMENT_ALGORITHM,
    PlacementPlanner,
    PlacementRequest,
    conflicting_exclusions,
    discover_host_layout,
)
from .pe.ranges import Range, align_up
from .toolchains import create_toolchain
from .toolchains.base import Toolchain, ToolchainStatus


COMPATIBILITY_SCHEMA = 3
CLASS_COMPATIBLE = "compatible"
CLASS_REPAIRABLE = "compatible_with_repair"
CLASS_INCOMPATIBLE = "incompatible"
IMAGE_DLLCHARACTERISTICS_GUARD_CF = pefile.DLL_CHARACTERISTICS[
    "IMAGE_DLLCHARACTERISTICS_GUARD_CF"
]


class CompatibilityError(ValueError):
    def __init__(self, report: "CompatibilityReport"):
        self.report = report
        candidates = [
            item
            for item in report.reasons
            if item.level == "error"
            or (item.level == "action" and not report.buildable)
        ]
        prefixes = {
            "INPUT_": 0,
            "OUTPUT_": 10,
            "MODULE_": 20,
            "GUARDRAIL_": 30,
            "PAYLOAD_KIND_": 30,
            "HOST_KIND_": 30,
            "PAYLOAD_ALIGNMENT_": 30,
            "XOR_KEY_": 30,
            "PAYLOAD_": 40,
            "HOST_": 50,
            "IAT_": 60,
            "TOOLCHAIN_": 70,
            "SIGNING_": 80,
        }

        def priority(item: CompatibilityReason) -> int:
            return next(
                (
                    value
                    for prefix, value in prefixes.items()
                    if item.code.startswith(prefix)
                ),
                100,
            )

        reason = min(
            enumerate(candidates),
            key=lambda item: (priority(item[1]), item[0]),
            default=(0, None),
        )
        selected = reason[1]
        super().__init__(
            selected.message
            if selected is not None
            else "build configuration is incompatible"
        )


@dataclass(frozen=True)
class CompatibilityReason:
    code: str
    message: str
    field: str | None = None
    level: str = "error"
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "level": self.level,
            "details": self.details,
        }


@dataclass(frozen=True)
class PayloadFacts:
    path: Path
    exists: bool
    size: int
    sha256: str | None
    kind: str
    machine: int | None = None
    pe32_plus: bool | None = None
    is_dll: bool | None = None
    entrypoint_rva: int | None = None
    image_size: int | None = None
    section_count: int | None = None
    has_relocations: bool | None = None
    has_tls: bool | None = None
    has_delay_imports: bool | None = None
    has_clr: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "exists": self.exists,
            "size": self.size,
            "sha256": self.sha256,
            "kind": self.kind,
            "machine": (
                f"0x{self.machine:04X}" if self.machine is not None else None
            ),
            "pe32_plus": self.pe32_plus,
            "is_dll": self.is_dll,
            "entrypoint_rva": self.entrypoint_rva,
            "image_size": self.image_size,
            "section_count": self.section_count,
            "has_relocations": self.has_relocations,
            "has_tls": self.has_tls,
            "has_delay_imports": self.has_delay_imports,
            "has_clr": self.has_clr,
        }


@dataclass(frozen=True)
class HostFacts:
    path: Path
    exists: bool
    size: int
    sha256: str | None
    machine: int | None = None
    pe32_plus: bool | None = None
    host_kind: str | None = None
    entrypoint_rva: int | None = None
    section_name: str | None = None
    section_rva: int | None = None
    section_characteristics: int | None = None
    code_capacity: int = 0
    dll_characteristics: int | None = None
    guard_cf_enabled: bool | None = None
    import_dlls: tuple[str, ...] = ()
    import_names: dict[str, tuple[str, ...]] = dataclass_field(default_factory=dict)
    import_slots: dict[str, tuple[ImportSlot, ...]] = dataclass_field(
        default_factory=dict, repr=False
    )
    layout: HostLayout | None = dataclass_field(default=None, repr=False)
    entry_invocation: dict[str, Any] | None = None
    entry_backdoor: dict[str, Any] | None = None
    export_invocation: dict[str, Any] | None = None
    export_backdoor: dict[str, Any] | None = None
    invocation_errors: dict[str, str] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "exists": self.exists,
            "size": self.size,
            "sha256": self.sha256,
            "machine": (
                f"0x{self.machine:04X}" if self.machine is not None else None
            ),
            "pe32_plus": self.pe32_plus,
            "host_kind": self.host_kind,
            "entrypoint_rva": self.entrypoint_rva,
            "section_name": self.section_name,
            "section_rva": self.section_rva,
            "section_characteristics": self.section_characteristics,
            "code_capacity": self.code_capacity,
            "dll_characteristics": self.dll_characteristics,
            "guard_cf_enabled": self.guard_cf_enabled,
            "import_dlls": list(self.import_dlls),
            "imports": {
                dll: list(names)
                for dll, names in sorted(self.import_names.items())
            },
            "layout": self.layout.to_summary() if self.layout is not None else None,
            "entry_invocation": self.entry_invocation,
            "entry_backdoor": self.entry_backdoor,
            "export_invocation": self.export_invocation,
            "export_backdoor": self.export_backdoor,
            "invocation_errors": dict(sorted(self.invocation_errors.items())),
        }

@dataclass(frozen=True)
class SigningFacts:
    enabled: bool
    required: bool
    ready: bool
    implementation: str | None
    tool: str | None
    diagnostic: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "required": self.required,
            "ready": self.ready,
            "implementation": self.implementation,
            "tool": self.tool,
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True)
class _RecipeEvaluation:
    recipe: Recipe
    selected: tuple[ModuleManifest, ...]
    classification: str
    buildable: bool
    reasons: tuple[CompatibilityReason, ...]
    warnings: tuple[CompatibilityReason, ...]
    required_imports: tuple[tuple[str, str], ...]
    missing_imports: tuple[str, ...]
    planned_repairs: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class CompatibilityReport:
    classification: str
    buildable: bool
    input_digest: str
    normalized_config: dict[str, Any]
    selected_modules: tuple[dict[str, Any], ...]
    payload: PayloadFacts
    injectable: HostFacts
    toolchain: dict[str, Any]
    signing: SigningFacts
    required_imports: tuple[str, ...]
    missing_imports: tuple[str, ...]
    planned_repairs: tuple[dict[str, Any], ...]
    reasons: tuple[CompatibilityReason, ...]
    warnings: tuple[CompatibilityReason, ...]
    recommendation: dict[str, Any] | None
    choices: dict[str, dict[str, dict[str, Any]]]
    placement_plan: dict[str, Any] | None = None
    invocation_plan: dict[str, Any] | None = None
    schema: int = COMPATIBILITY_SCHEMA

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(
            item.code
            for item in (*self.reasons, *self.warnings)
        )

    def require_buildable(self) -> None:
        if not self.buildable:
            raise CompatibilityError(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "classification": self.classification,
            "buildable": self.buildable,
            "input_digest": self.input_digest,
            "normalized_config": self.normalized_config,
            "selected_modules": [dict(item) for item in self.selected_modules],
            "payload": self.payload.to_dict(),
            "injectable": self.injectable.to_dict(),
            "toolchain": self.toolchain,
            "signing": self.signing.to_dict(),
            "required_imports": list(self.required_imports),
            "missing_imports": list(self.missing_imports),
            "planned_repairs": [
                dict(item) for item in self.planned_repairs
            ],
            "reasons": [item.to_dict() for item in self.reasons],
            "warnings": [item.to_dict() for item in self.warnings],
            "reason_codes": list(self.reason_codes),
            "recommendation": self.recommendation,
            "choices": self.choices,
            "placement_plan": self.placement_plan,
            "invocation_plan": self.invocation_plan,
        }

SigningProbe = Callable[[str, Toolchain, bool, bool], SigningFacts]


class CompatibilityCache:
    def __init__(self, max_entries: int = 32):
        self.max_entries = max_entries
        self._lock = threading.RLock()
        self._payloads: dict[
            tuple[Any, ...],
            tuple[PayloadFacts, list[CompatibilityReason]],
        ] = {}
        self._hosts: dict[
            tuple[Any, ...],
            tuple[HostFacts, list[CompatibilityReason]],
        ] = {}
        self._toolchains: dict[
            str,
            tuple[Toolchain, ToolchainStatus],
        ] = {}
        self._signing: dict[
            tuple[str, str, bool, bool],
            SigningFacts,
        ] = {}

    @staticmethod
    def _file_key(path: Path, *values: Any) -> tuple[Any, ...]:
        resolved = path.resolve()
        try:
            stat = resolved.stat()
            identity = (True, stat.st_size, stat.st_mtime_ns)
        except OSError:
            identity = (False, None, None)
        return (str(resolved), *values, *identity)

    def _retain(self, cache: dict[Any, Any], key: Any, value: Any) -> Any:
        if len(cache) >= self.max_entries and key not in cache:
            cache.clear()
        cache[key] = value
        return value

    def inspect_payload(
        self,
        path: Path,
        kind: str,
    ) -> tuple[PayloadFacts, list[CompatibilityReason]]:
        key = self._file_key(path, kind)
        with self._lock:
            cached = self._payloads.get(key)
            if cached is not None:
                return cached
            return self._retain(
                self._payloads,
                key,
                _inspect_payload(path, kind),
            )

    def inspect_host(
        self,
        path: Path,
        dll_export: str | None,
    ) -> tuple[HostFacts, list[CompatibilityReason]]:
        key = self._file_key(path, dll_export)
        with self._lock:
            cached = self._hosts.get(key)
            if cached is not None:
                return cached
            return self._retain(
                self._hosts,
                key,
                _inspect_host(path, dll_export),
            )

    def toolchain(
        self,
        name: str,
    ) -> tuple[Toolchain, ToolchainStatus]:
        with self._lock:
            cached = self._toolchains.get(name)
            if cached is not None:
                return cached
            toolchain = create_toolchain(name)
            value = (toolchain, toolchain.doctor())
            self._toolchains[name] = value
            return value

    def signing(
        self,
        profile_name: str,
        toolchain: Toolchain,
        enabled: bool,
        required: bool,
    ) -> SigningFacts:
        key = (profile_name, toolchain.name, enabled, required)
        with self._lock:
            cached = self._signing.get(key)
            if cached is not None:
                return cached
            value = _default_signing_probe(
                profile_name,
                toolchain,
                enabled,
                required,
            )
            self._signing[key] = value
            return value


def _reason(
    code: str,
    message: str,
    field_name: str | None = None,
    *,
    level: str = "error",
    **details: Any,
) -> CompatibilityReason:
    return CompatibilityReason(
        code=code,
        message=message,
        field=field_name,
        level=level,
        details=details,
    )


def _inspect_payload(
    path: Path,
    kind: str,
) -> tuple[PayloadFacts, list[CompatibilityReason]]:
    resolved = path.resolve()
    if not resolved.is_file():
        return (
            PayloadFacts(resolved, False, 0, None, kind),
            [
                _reason(
                    "INPUT_PAYLOAD_MISSING",
                    f"payload does not exist: {path}",
                    "payload",
                )
            ],
        )

    try:
        size = resolved.stat().st_size
        digest = sha256_file(resolved)
    except OSError as exc:
        return (
            PayloadFacts(resolved, True, 0, None, kind),
            [
                _reason(
                    "INPUT_PAYLOAD_UNREADABLE",
                    f"payload cannot be read: {exc}",
                    "payload",
                )
            ],
        )
    if kind != "dll":
        return PayloadFacts(resolved, True, size, digest, kind), []

    if resolved.suffix.lower() != ".dll":
        extension_reason = _reason(
            "PAYLOAD_DLL_EXTENSION",
            "DLL payload input must use a .dll extension",
            "payload",
        )
    else:
        extension_reason = None

    try:
        image = pefile.PE(str(resolved), fast_load=False)
    except (OSError, pefile.PEFormatError, ValueError) as exc:
        reasons = [extension_reason] if extension_reason is not None else []
        reasons.append(
            _reason(
                "PAYLOAD_PE_INVALID",
                f"DLL payload is not a valid PE: {exc}",
                "payload",
            )
        )
        return PayloadFacts(resolved, True, size, digest, kind), reasons

    try:
        machine = int(image.FILE_HEADER.Machine)
        pe32_plus = int(image.OPTIONAL_HEADER.Magic) == 0x20B
        is_dll = bool(image.FILE_HEADER.Characteristics & 0x2000)
        entrypoint = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
        directories = image.OPTIONAL_HEADER.DATA_DIRECTORY

        def directory_present(name: str) -> bool:
            directory = directories[pefile.DIRECTORY_ENTRY[name]]
            return bool(directory.VirtualAddress or directory.Size)

        has_relocations = directory_present("IMAGE_DIRECTORY_ENTRY_BASERELOC")
        has_tls = directory_present("IMAGE_DIRECTORY_ENTRY_TLS")
        has_delay_imports = directory_present(
            "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"
        )
        has_clr = directory_present("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR")
        facts = PayloadFacts(
            path=resolved,
            exists=True,
            size=size,
            sha256=digest,
            kind=kind,
            machine=machine,
            pe32_plus=pe32_plus,
            is_dll=is_dll,
            entrypoint_rva=entrypoint,
            image_size=int(image.OPTIONAL_HEADER.SizeOfImage),
            section_count=int(image.FILE_HEADER.NumberOfSections),
            has_relocations=has_relocations,
            has_tls=has_tls,
            has_delay_imports=has_delay_imports,
            has_clr=has_clr,
        )
    finally:
        image.close()

    reasons = [extension_reason] if extension_reason is not None else []
    if machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        reasons.append(
            _reason(
                "PAYLOAD_ARCH_NOT_AMD64",
                "DLL payload must be AMD64",
                "payload",
            )
        )
    if not pe32_plus:
        reasons.append(
            _reason(
                "PAYLOAD_NOT_PE32_PLUS",
                "DLL payload must be PE32+",
                "payload",
            )
        )
    if not is_dll:
        reasons.append(
            _reason(
                "PAYLOAD_NOT_DLL",
                "DLL payload is not marked as a DLL",
                "payload",
            )
        )
    if entrypoint == 0:
        reasons.append(
            _reason(
                "PAYLOAD_DLL_ENTRYPOINT_MISSING",
                "DLL payload has no entry point",
                "payload",
            )
        )
    if not has_relocations:
        reasons.append(
            _reason(
                "PAYLOAD_DLL_RELOCATIONS_MISSING",
                "DLL payload requires a base-relocation directory",
                "payload",
            )
        )
    if has_tls:
        reasons.append(
            _reason(
                "PAYLOAD_DLL_TLS_UNSUPPORTED",
                "DLL payload uses unsupported TLS callbacks",
                "payload",
            )
        )
    if has_delay_imports:
        reasons.append(
            _reason(
                "PAYLOAD_DLL_DELAY_IMPORTS_UNSUPPORTED",
                "DLL payload uses unsupported delay imports",
                "payload",
            )
        )
    if has_clr:
        reasons.append(
            _reason(
                "PAYLOAD_DLL_CLR_UNSUPPORTED",
                "DLL payload uses unsupported .NET/CLR metadata",
                "payload",
            )
        )
    return facts, reasons


def _inspect_host(
    path: Path,
    dll_export: str | None = None,
) -> tuple[HostFacts, list[CompatibilityReason]]:
    resolved = path.resolve()
    if not resolved.is_file():
        return (
            HostFacts(resolved, False, 0, None),
            [
                _reason(
                    "INPUT_HOST_MISSING",
                    f"host does not exist: {path}",
                    "injectable",
                )
            ],
        )

    try:
        size = resolved.stat().st_size
        digest = sha256_file(resolved)
    except OSError as exc:
        return (
            HostFacts(resolved, True, 0, None),
            [
                _reason(
                    "INPUT_HOST_UNREADABLE",
                    f"host cannot be read: {exc}",
                    "injectable",
                )
            ],
        )
    try:
        image = pefile.PE(str(resolved), fast_load=False)
        image.parse_data_directories()
    except (OSError, pefile.PEFormatError, ValueError) as exc:
        return (
            HostFacts(resolved, True, size, digest),
            [
                _reason(
                    "HOST_PE_INVALID",
                    f"invalid injectable PE: {exc}",
                    "injectable",
                )
            ],
        )

    try:
        machine = int(image.FILE_HEADER.Machine)
        pe32_plus = int(image.OPTIONAL_HEADER.Magic) == 0x20B
        dll_characteristics = int(image.OPTIONAL_HEADER.DllCharacteristics)
        guard_cf_enabled = bool(
            dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF
        )
        host_kind = (
            "dll" if image.FILE_HEADER.Characteristics & 0x2000 else "exe"
        )
        entrypoint = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
        section_name: str | None = None
        section_rva: int | None = None
        section_characteristics: int | None = None
        code_capacity = 0
        for section in image.sections:
            span = max(
                int(section.Misc_VirtualSize),
                int(section.SizeOfRawData),
            )
            if (
                section.Characteristics
                & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
                and int(section.VirtualAddress)
                <= entrypoint
                < int(section.VirtualAddress) + span
            ):
                section_name = section.Name.rstrip(b"\0").decode(
                    "ascii", errors="replace"
                )
                section_rva = int(section.VirtualAddress)
                section_characteristics = int(section.Characteristics)
                code_capacity = min(
                    int(section.Misc_VirtualSize),
                    int(section.SizeOfRawData),
                )
                break
        slots = collect_import_slots(image)
        import_names = {
            dll: tuple(sorted({slot.name for slot in values}, key=str.casefold))
            for dll, values in sorted(slots.items())
        }
        layout = discover_host_layout(image)
        invocation_errors: dict[str, str] = {}
        entry_invocation: dict[str, Any] | None = None
        entry_backdoor: dict[str, Any] | None = None
        export_invocation: dict[str, Any] | None = None
        export_backdoor: dict[str, Any] | None = None
        try:
            target = resolve_invocation_target(
                image,
                "dllmain" if host_kind == "dll" else "entrypoint",
                require_function_bounds=False,
            )
            entry_invocation = target.to_dict()
            try:
                bounded_target = resolve_invocation_target(
                    image,
                    "dllmain" if host_kind == "dll" else "entrypoint",
                )
                entry_invocation = bounded_target.to_dict()
                site = find_backdoor_site(image, bounded_target)
                conflicts = conflicting_exclusions(
                    layout,
                    Range(site.rva, site.rva + site.size),
                    {f"entry_function:0x{bounded_target.rva:X}"},
                )
                if conflicts:
                    raise InvocationError(
                        "selected entry backdoor branch overlaps protected "
                        f"{conflicts[0].reason} metadata"
                    )
                entry_backdoor = site.to_dict()
            except InvocationError as exc:
                invocation_errors["entry_backdoor"] = str(exc)
        except InvocationError as exc:
            invocation_errors["entry"] = str(exc)
        if host_kind == "dll" and dll_export:
            try:
                target = resolve_invocation_target(
                    image,
                    "export",
                    dll_export,
                    require_function_bounds=False,
                )
                export_invocation = target.to_dict()
                try:
                    bounded_target = resolve_invocation_target(
                        image,
                        "export",
                        dll_export,
                    )
                    export_invocation = bounded_target.to_dict()
                    site = find_backdoor_site(image, bounded_target)
                    conflicts = conflicting_exclusions(
                        layout,
                        Range(site.rva, site.rva + site.size),
                        {
                            f"export_function:0x{bounded_target.rva:X}"
                        },
                    )
                    if conflicts:
                        raise InvocationError(
                            "selected export backdoor branch overlaps protected "
                            f"{conflicts[0].reason} metadata"
                        )
                    export_backdoor = site.to_dict()
                except InvocationError as exc:
                    invocation_errors["export_backdoor"] = str(exc)
            except (InvocationError, UnicodeDecodeError) as exc:
                invocation_errors["export"] = str(exc)
        facts = HostFacts(
            path=resolved,
            exists=True,
            size=size,
            sha256=digest,
            machine=machine,
            pe32_plus=pe32_plus,
            host_kind=host_kind,
            entrypoint_rva=entrypoint,
            section_name=section_name,
            section_rva=section_rva,
            section_characteristics=section_characteristics,
            code_capacity=code_capacity,
            dll_characteristics=dll_characteristics,
            guard_cf_enabled=guard_cf_enabled,
            import_dlls=tuple(sorted(slots)),
            import_names=import_names,
            import_slots={
                dll: tuple(values) for dll, values in sorted(slots.items())
            },
            layout=layout,
            entry_invocation=entry_invocation,
            entry_backdoor=entry_backdoor,
            export_invocation=export_invocation,
            export_backdoor=export_backdoor,
            invocation_errors=invocation_errors,
        )
    finally:
        image.close()

    reasons: list[CompatibilityReason] = []
    if machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        reasons.append(
            _reason(
                "HOST_ARCH_NOT_AMD64",
                "host must be AMD64",
                "injectable",
            )
        )
    if not pe32_plus:
        reasons.append(
            _reason(
                "HOST_NOT_PE32_PLUS",
                "host must be PE32+",
                "injectable",
            )
        )
    if resolved.suffix.lower() != f".{host_kind}":
        reasons.append(
            _reason(
                "HOST_EXTENSION_MISMATCH",
                f"{host_kind.upper()} host must use a .{host_kind} extension",
                "injectable",
            )
        )
    if section_name is None:
        reasons.append(
            _reason(
                "HOST_ENTRY_SECTION_MISSING",
                "could not locate executable entry-point section",
                "injectable",
            )
        )
    elif code_capacity <= 0:
        reasons.append(
            _reason(
                "HOST_CODE_CAPACITY_EMPTY",
                "executable section has no mapped raw capacity",
                "injectable",
            )
        )
    return facts, reasons


def _required_imports(
    selected: tuple[ModuleManifest, ...],
) -> tuple[tuple[tuple[str, str], ...], list[CompatibilityReason]]:
    by_name: dict[str, tuple[str, str]] = {}
    reasons: list[CompatibilityReason] = []
    for module in selected:
        for declaration in module.required_imports:
            if "!" not in declaration:
                reasons.append(
                    _reason(
                        "IMPORT_DECLARATION_INVALID",
                        f"{module.qualified_name}: import must be DLL!Function: "
                        f"{declaration}",
                        module.slot,
                    )
                )
                continue
            dll, name = declaration.split("!", 1)
            if not dll or not name:
                reasons.append(
                    _reason(
                        "IMPORT_DECLARATION_INVALID",
                        f"{module.qualified_name}: import must be DLL!Function: "
                        f"{declaration}",
                        module.slot,
                    )
                )
                continue
            previous = by_name.get(name.lower())
            if previous is not None and previous[0].lower() != dll.lower():
                reasons.append(
                    _reason(
                        "IMPORT_DECLARATION_CONFLICT",
                        f"conflicting DLL declarations for imported API {name}",
                        module.slot,
                    )
                )
                continue
            by_name[name.lower()] = (dll, name)
    values = tuple(
        sorted(by_name.values(), key=lambda item: (item[0].lower(), item[1].lower()))
    )
    return values, reasons


def _guardrail_reasons(
    module: ModuleManifest,
    value: str | None,
) -> list[CompatibilityReason]:
    if module.name == "none":
        if value is not None and value.strip():
            return [
                _reason(
                    "GUARDRAIL_VALUE_UNUSED",
                    "guardrail_value requires a non-none guardrail",
                    "guardrail_value",
                )
            ]
        return []
    if value is None or not value.strip():
        return [
            _reason(
                "GUARDRAIL_VALUE_REQUIRED",
                f"{module.qualified_name} requires --guardrail-value",
                "guardrail_value",
            )
        ]
    if "\x00" in value:
        return [
            _reason(
                "GUARDRAIL_VALUE_NUL",
                "guardrail_value cannot contain a NUL character",
                "guardrail_value",
            )
        ]
    if len(value.encode("utf-16-le")) // 2 > 255:
        return [
            _reason(
                "GUARDRAIL_VALUE_TOO_LONG",
                "guardrail_value cannot exceed 255 UTF-16 code units",
                "guardrail_value",
            )
        ]
    environment_name = module.config.get("environment_name")
    if not isinstance(environment_name, str) or not environment_name:
        return [
            _reason(
                "GUARDRAIL_METADATA_INVALID",
                f"{module.qualified_name}: environment_name must be a "
                "non-empty string",
                "guardrail",
            )
        ]
    return []


def _effective_iat_policy(
    config: BuildConfig,
) -> tuple[str | None, list[CompatibilityReason]]:
    if config.iat_policy not in {"auto", "reuse_only"}:
        return None, [
            _reason(
                "IAT_POLICY_INVALID",
                "iat_policy must be auto or reuse_only",
                "iat_policy",
            )
        ]
    try:
        return config.effective_iat_policy, []
    except ValueError as exc:
        return None, [
            _reason(
                "IAT_POLICY_CONFLICT",
                str(exc),
                "iat_policy",
            )
        ]


def _effective_payload_location(
    config: BuildConfig,
    memory: ModuleManifest,
) -> tuple[str | None, list[CompatibilityReason]]:
    if config.payload_location not in {"auto", "code", "rdata"}:
        return None, [
            _reason(
                "PAYLOAD_LOCATION_INVALID",
                "payload_location must be auto, code, or rdata",
                "payload_location",
            )
        ]
    mode = str(memory.config.get("placement_mode", "in_place"))
    if mode not in {"in_place", "allocation", "split_image"}:
        return None, [
            _reason(
                "PAYLOAD_LOCATION_METADATA_INVALID",
                f"{memory.qualified_name}: placement_mode must be in_place, "
                "allocation, or split_image",
                "memory",
            )
        ]
    effective = (
        ("rdata" if mode in {"allocation", "split_image"} else "code")
        if config.payload_location == "auto"
        else config.payload_location
    )
    if mode == "in_place" and effective != "code":
        return None, [
            _reason(
                "PAYLOAD_LOCATION_MEMORY_MISMATCH",
                f"{memory.qualified_name} executes from the image and "
                "requires an executable code placement",
                "payload_location",
                memory_mode=mode,
                requested=config.payload_location,
            )
        ]
    if mode == "split_image" and effective != "rdata":
        return None, [
            _reason(
                "PAYLOAD_LOCATION_MEMORY_MISMATCH",
                f"{memory.qualified_name} separates encoded data from its "
                "execution destination and requires read-only placement",
                "payload_location",
                memory_mode=mode,
                requested=config.payload_location,
            )
        ]
    return effective, []


def _placement_capacity_reason(
    host: HostFacts,
    payload_size: int,
    location: str | None,
    memory: ModuleManifest,
) -> CompatibilityReason | None:
    if host.layout is None or location is None or payload_size <= 0:
        return None
    eligible = []
    for interval in host.layout.intervals:
        section = interval.section
        if location == "code":
            accepted = section.executable
        else:
            accepted = section.readable and not section.writable and not section.executable
        if accepted:
            eligible.append(interval)
    largest = max((item.size for item in eligible), default=0)
    if largest < payload_size:
        return _reason(
            "PAYLOAD_PLACEMENT_UNAVAILABLE",
            f"no inspected {location} range can hold the {payload_size:,}-byte "
            "payload",
            "payload_location",
            payload_size=payload_size,
            location=location,
            largest_candidate=largest,
        )
    if memory.config.get("placement_mode") == "split_image":
        largest_code = max(
            (
                item.size
                for item in host.layout.intervals
                if item.section.executable
            ),
            default=0,
        )
        if largest_code < payload_size:
            return _reason(
                "EXECUTION_DESTINATION_UNAVAILABLE",
                f"no inspected code range can hold the {payload_size:,}-byte "
                "split-image execution destination",
                "memory",
                payload_size=payload_size,
                largest_candidate=largest_code,
            )
    return None


def _evaluate_recipe(
    config: BuildConfig,
    recipe: Recipe,
    registry: ModuleRegistry,
    payload: PayloadFacts,
    host: HostFacts,
) -> _RecipeEvaluation:
    reasons: list[CompatibilityReason] = []
    warnings: list[CompatibilityReason] = []
    try:
        selected = tuple(registry.select(recipe))
    except ModuleError as exc:
        return _RecipeEvaluation(
            recipe=recipe,
            selected=(),
            classification=CLASS_INCOMPATIBLE,
            buildable=False,
            reasons=(
                _reason(
                    "MODULE_SELECTION_INVALID",
                    str(exc),
                    "recipe",
                ),
            ),
            warnings=(),
            required_imports=(),
            missing_imports=(),
            planned_repairs=(),
        )

    guardrail = next(item for item in selected if item.slot == "guardrail")
    memory = next(item for item in selected if item.slot == "memory")
    execute = next(item for item in selected if item.slot == "execute")
    pe_invoke = next(item for item in selected if item.slot == "pe_invoke")

    reasons.extend(_guardrail_reasons(guardrail, config.guardrail_value))
    iat_policy, iat_policy_reasons = _effective_iat_policy(config)
    reasons.extend(iat_policy_reasons)
    payload_location, location_reasons = _effective_payload_location(
        config, memory
    )
    reasons.extend(location_reasons)
    capacity_reason = _placement_capacity_reason(
        host, payload.size, payload_location, memory
    )
    if capacity_reason is not None:
        reasons.append(capacity_reason)
    expected_payload_kind = execute.config.get("payload_kind", "raw")
    if expected_payload_kind != config.payload_kind:
        reasons.append(
            _reason(
                "PAYLOAD_KIND_MISMATCH",
                f"{execute.qualified_name} requires payload kind "
                f"{expected_payload_kind}, not {config.payload_kind}",
                "execute",
                expected=expected_payload_kind,
                actual=config.payload_kind,
            )
        )

    host_kind = pe_invoke.config.get("host_kind", "exe")
    if host_kind not in {"exe", "dll"}:
        reasons.append(
            _reason(
                "HOST_KIND_METADATA_INVALID",
                f"{pe_invoke.qualified_name}: host_kind must be exe or dll",
                "pe_invoke",
            )
        )
    else:
        if config.output.suffix.lower() != f".{host_kind}":
            reasons.append(
                _reason(
                    "OUTPUT_KIND_MISMATCH",
                    f"{pe_invoke.qualified_name} requires a .{host_kind} output",
                    "output",
                    expected=host_kind,
                    actual=config.output.suffix.lower(),
                )
            )
        if host.host_kind is not None and host.host_kind != host_kind:
            reasons.append(
                _reason(
                    "HOST_KIND_MISMATCH",
                    f"host is {host.host_kind.upper()}, but recipe requires "
                    f"{host_kind.upper()}",
                    "pe_invoke",
                    expected=host_kind,
                    actual=host.host_kind,
                )
            )

    payload_alignment = memory.config.get("payload_alignment", 16)
    if (
        not isinstance(payload_alignment, int)
        or payload_alignment < 16
        or payload_alignment & (payload_alignment - 1)
    ):
        reasons.append(
            _reason(
                "PAYLOAD_ALIGNMENT_INVALID",
                f"{memory.qualified_name}: payload_alignment must be a power "
                "of two >= 16",
                "memory",
            )
        )

    execution_alignment = memory.config.get(
        "execution_alignment", payload_alignment
    )
    if (
        memory.config.get("placement_mode") == "split_image"
        and (
            not isinstance(execution_alignment, int)
            or execution_alignment < 4096
            or execution_alignment & (execution_alignment - 1)
        )
    ):
        reasons.append(
            _reason(
                "EXECUTION_ALIGNMENT_INVALID",
                f"{memory.qualified_name}: execution_alignment must be a "
                "power of two >= 4096",
                "memory",
            )
        )

    if recipe.decoder in KEYED_DECODERS and not (
        XOR_KEY_MIN_BYTES <= len(config.xor_key) <= XOR_KEY_MAX_BYTES
    ):
        reasons.append(
            _reason(
                "XOR_KEY_INVALID",
                f"{recipe.decoder} requires {XOR_KEY_MIN_BYTES} to "
                f"{XOR_KEY_MAX_BYTES} bytes of key material",
                "xor_key",
            )
        )

    if execute.fixture_only:
        warnings.append(
            _reason(
                "MODULE_FIXTURE_ONLY",
                f"{execute.qualified_name} is intended only for controlled fixtures",
                "execute",
                level="warning",
            )
        )
    if pe_invoke.host_behavior == "callback_only_destructive":
        warnings.append(
            _reason(
                "HOST_BEHAVIOR_CALLBACK_ONLY_DESTRUCTIVE",
                f"{pe_invoke.qualified_name} is callback-only and destructive "
                "to normal host behavior",
                "pe_invoke",
                level="warning",
            )
        )
    if pe_invoke.host_behavior == "entrypoint_replaced":
        warnings.append(
            _reason(
                "HOST_BEHAVIOR_ENTRYPOINT_REPLACED",
                f"{pe_invoke.qualified_name} replaces AddressOfEntryPoint "
                "and is retained only as an explicit destructive control",
                "pe_invoke",
                level="warning",
            )
        )

    invocation_strategy = str(
        pe_invoke.config.get("invocation_strategy", "overwrite")
    )
    invocation_target = str(
        pe_invoke.config.get(
            "invocation_target",
            "dllmain" if host_kind == "dll" else "entrypoint",
        )
    )
    if invocation_strategy not in {
        "overwrite",
        "backdoor",
        "target_overwrite",
    }:
        reasons.append(
            _reason(
                "INVOCATION_STRATEGY_METADATA_INVALID",
                f"{pe_invoke.qualified_name}: invocation_strategy must be "
                "overwrite, target_overwrite, or backdoor",
                "pe_invoke",
            )
        )
    if invocation_target not in {"entrypoint", "dllmain", "export"}:
        reasons.append(
            _reason(
                "INVOCATION_TARGET_METADATA_INVALID",
                f"{pe_invoke.qualified_name}: unsupported invocation target "
                f"{invocation_target!r}",
                "pe_invoke",
            )
        )
    if invocation_target == "export":
        if not config.dll_export or not config.dll_export.strip():
            reasons.append(
                _reason(
                    "DLL_EXPORT_REQUIRED",
                    f"{pe_invoke.qualified_name} requires --dll-export",
                    "dll_export",
                )
            )
        elif host.export_invocation is None:
            reasons.append(
                _reason(
                    "DLL_EXPORT_UNAVAILABLE",
                    host.invocation_errors.get(
                        "export",
                        f"named export {config.dll_export!r} is unavailable",
                    ),
                    "dll_export",
                )
            )
        elif (
            invocation_strategy in {"overwrite", "target_overwrite"}
            and int(host.export_invocation["function_end_rva"])
            - int(host.export_invocation["function_start_rva"])
            <= 1
        ):
            reasons.append(
                _reason(
                    "DLL_EXPORT_BOUNDS_UNAVAILABLE",
                    host.invocation_errors.get(
                        "export_backdoor",
                        "named export has no unambiguous bounded runtime function",
                    ),
                    "dll_export",
                )
            )
        elif invocation_strategy == "backdoor" and host.export_backdoor is None:
            reasons.append(
                _reason(
                    "DLL_EXPORT_BACKDOOR_UNAVAILABLE",
                    host.invocation_errors.get(
                        "export_backdoor",
                        "named export has no supported backdoor site",
                    ),
                    "pe_invoke",
                )
            )
    elif (
        invocation_strategy == "target_overwrite"
        and (
            host.entry_invocation is None
            or int(host.entry_invocation["function_end_rva"])
            - int(host.entry_invocation["function_start_rva"])
            <= 1
        )
    ):
        reasons.append(
            _reason(
                "FUNCTION_OVERWRITE_UNAVAILABLE",
                host.invocation_errors.get(
                    "entry",
                    "entry function has no unambiguous bounded runtime function",
                ),
                "pe_invoke",
            )
        )
    elif invocation_strategy == "backdoor" and host.entry_backdoor is None:
        reasons.append(
            _reason(
                "FUNCTION_BACKDOOR_UNAVAILABLE",
                host.invocation_errors.get(
                    "entry_backdoor",
                    "entry function has no supported backdoor site",
                ),
                "pe_invoke",
            )
        )

    required, import_reasons = _required_imports(selected)
    reasons.extend(import_reasons)
    available = {
        (dll.lower(), name.lower())
        for dll, names in host.import_names.items()
        for name in names
    }
    missing_pairs = [
        (dll, name)
        for dll, name in required
        if (dll.lower(), name.lower()) not in available
    ]
    missing = tuple(f"{dll}!{name}" for dll, name in missing_pairs)
    planned_repairs: tuple[dict[str, Any], ...] = ()
    if missing and host.exists and host.machine is not None:
        _, raw_repairs, repair_error = plan_iat_repairs(
            {
                dll: list(slots)
                for dll, slots in host.import_slots.items()
            },
            required,
        )
        planned_repairs = tuple(dict(item) for item in raw_repairs)
        if repair_error is not None:
            reasons.append(
                _reason(
                    "IAT_REPAIR_UNAVAILABLE",
                    repair_error,
                    "iat_policy",
                    missing_imports=list(missing),
                )
            )

    errors = [item for item in reasons if item.level == "error"]
    if errors:
        classification = CLASS_INCOMPATIBLE
        buildable = False
    elif missing:
        buildable = iat_policy == "auto"
        classification = (
            CLASS_REPAIRABLE if buildable else CLASS_INCOMPATIBLE
        )
        reasons.append(
            _reason(
                (
                    "IAT_REPAIR_PLANNED"
                    if buildable
                    else "IAT_REUSE_ONLY_MISSING"
                ),
                (
                    f"{len(missing)} required import(s) will use deterministic "
                    "same-DLL name-slot repair"
                    if buildable
                    else f"{len(missing)} required import(s) are absent and "
                    "iat_policy=reuse_only forbids repair"
                ),
                "iat_policy",
                level="action" if buildable else "error",
                missing_imports=list(missing),
            )
        )
        warnings.append(
            _reason(
                "IAT_REPAIR_CHANGES_HOST_IMPORTS",
                "IAT repair replaces existing import names and can change "
                "original host behavior",
                "iat_policy",
                level="warning",
            )
        )
    else:
        classification = CLASS_COMPATIBLE
        buildable = True

    return _RecipeEvaluation(
        recipe=recipe,
        selected=selected,
        classification=classification,
        buildable=buildable,
        reasons=tuple(reasons),
        warnings=tuple(warnings),
        required_imports=required,
        missing_imports=missing,
        planned_repairs=planned_repairs,
    )


def _default_signing_probe(
    profile_name: str,
    toolchain: Toolchain,
    enabled: bool,
    required: bool,
) -> SigningFacts:
    del toolchain
    if enabled:
        from .signing import SigningError, discover_signing_backend

        try:
            backend = discover_signing_backend(profile_name)
        except SigningError as exc:
            return SigningFacts(
                enabled=True,
                required=required,
                ready=False,
                implementation=None,
                tool=None,
                diagnostic=str(exc),
            )
        return SigningFacts(
            enabled=True,
            required=required,
            ready=True,
            implementation=backend.name,
            tool=str(backend.tool_path),
            diagnostic=None,
        )
    return SigningFacts(
        enabled=False,
        required=required,
        ready=True,
        implementation=None,
        tool=None,
        diagnostic=None,
    )


def _path_reasons(
    config: BuildConfig,
    profile: ExecutionProfile | None,
) -> list[CompatibilityReason]:
    reasons: list[CompatibilityReason] = []
    resolved_output = config.output.resolve()
    resolved_host = config.host.resolve()
    resolved_build_dir = (config.artifact_dir / "build").resolve()
    unsigned_evidence = (
        config.artifact_dir
        / f"deterministic-unsigned-output{config.output.suffix.lower()}"
    ).resolve()
    if resolved_output == resolved_host:
        reasons.append(
            _reason(
                "OUTPUT_OVERWRITES_HOST",
                "output must not overwrite the injectable input",
                "output",
            )
        )
    if (
        resolved_output == resolved_build_dir
        or resolved_build_dir in resolved_output.parents
    ):
        reasons.append(
            _reason(
                "OUTPUT_INTERNAL_BUILD_COLLISION",
                "output must be outside the internal artifact build directory",
                "output",
            )
        )
    if resolved_output == unsigned_evidence:
        reasons.append(
            _reason(
                "OUTPUT_UNSIGNED_EVIDENCE_COLLISION",
                "output must not overwrite deterministic unsigned evidence",
                "output",
            )
        )
    return reasons


def _choice_matrix(
    config: BuildConfig,
    registry: ModuleRegistry,
    payload: PayloadFacts,
    host: HostFacts,
) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    values = config.recipe.as_dict()
    baseline = _evaluate_recipe(
        config,
        config.recipe,
        registry,
        payload,
        host,
    )
    baseline_errors = {
        (item.code, item.field, item.message)
        for item in baseline.reasons
        if item.level == "error"
    }
    owned_fields = {
        "guardrail": {"guardrail", "guardrail_value"},
        "anti_emulation": {"anti_emulation"},
        "memory": {"memory", "payload_location"},
        "decoder": {"decoder", "xor_key"},
        "execute": {"execute", "payload_kind"},
        "pe_invoke": {
            "pe_invoke",
            "dll_export",
            "output",
        },
        "payload_location": {"memory", "payload_location"},
        "iat_policy": {"iat_policy"},
    }

    def describe(
        control: str,
        evaluation: _RecipeEvaluation,
    ) -> dict[str, Any]:
        relevant = [
            item
            for item in (*evaluation.reasons, *evaluation.warnings)
            if item.field in owned_fields[control]
            or (
                item.level == "error"
                and (item.code, item.field, item.message)
                not in baseline_errors
            )
        ]
        blocking = [
            item for item in relevant if item.level == "error"
        ]
        return {
            "classification": evaluation.classification,
            "buildable": evaluation.buildable,
            "currently_incompatible": bool(blocking),
            "requires_iat_repair": bool(evaluation.missing_imports),
            "reason_codes": [item.code for item in relevant],
            "messages": [item.message for item in blocking],
        }

    for slot in REQUIRED_SLOTS:
        result[slot] = {}
        for name in sorted(registry.modules[slot]):
            candidate_values = dict(values)
            candidate_values[slot] = name
            candidate = Recipe(**candidate_values)
            evaluation = _evaluate_recipe(
                config, candidate, registry, payload, host
            )
            result[slot][name] = describe(slot, evaluation)

    result["payload_location"] = {}
    for location in ("auto", "code", "rdata"):
        candidate_config = replace(
            config,
            payload_location=location,
        )
        evaluation = _evaluate_recipe(
            candidate_config,
            candidate_config.recipe,
            registry,
            payload,
            host,
        )
        result["payload_location"][location] = describe(
            "payload_location",
            evaluation,
        )

    result["iat_policy"] = {}
    for policy in ("auto", "reuse_only"):
        candidate_config = replace(
            config,
            iat_policy=policy,
            repair_missing_iat=None,
        )
        evaluation = _evaluate_recipe(
            candidate_config,
            candidate_config.recipe,
            registry,
            payload,
            host,
        )
        result["iat_policy"][policy] = describe(
            "iat_policy",
            evaluation,
        )
    return result


def _recommendation(
    config: BuildConfig,
    registry: ModuleRegistry,
    payload: PayloadFacts,
    host: HostFacts,
    global_errors: list[CompatibilityReason],
    current_evaluation: _RecipeEvaluation,
) -> dict[str, Any] | None:
    if global_errors:
        return None

    current_recipe = config.recipe.as_dict()
    current_policy, _ = _effective_iat_policy(config)
    current_policy = current_policy or config.iat_policy
    fields: set[str] = set()
    for reason in (
        *current_evaluation.reasons,
        *current_evaluation.warnings,
    ):
        if reason.field in REQUIRED_SLOTS:
            fields.add(str(reason.field))
        if reason.code.startswith("PAYLOAD_LOCATION_") or reason.code == (
            "PAYLOAD_PLACEMENT_UNAVAILABLE"
        ):
            fields.update({"memory", "payload_location"})
        if reason.code.startswith("EXECUTION_"):
            fields.add("memory")
        if reason.code.startswith("PAYLOAD_KIND_"):
            fields.add("execute")
        if reason.code.startswith("GUARDRAIL_"):
            fields.add("guardrail")
        if reason.code.startswith("IAT_"):
            fields.add("iat_policy")
            if reason.code in {
                "IAT_REPAIR_UNAVAILABLE",
                "IAT_REUSE_ONLY_MISSING",
            }:
                fields.update(REQUIRED_SLOTS)
        if reason.code in {
            "OUTPUT_KIND_MISMATCH",
            "HOST_KIND_MISMATCH",
            "HOST_KIND_METADATA_INVALID",
            "FUNCTION_OVERWRITE_UNAVAILABLE",
            "FUNCTION_BACKDOOR_UNAVAILABLE",
            "DLL_EXPORT_REQUIRED",
            "DLL_EXPORT_UNAVAILABLE",
            "DLL_EXPORT_BOUNDS_UNAVAILABLE",
            "DLL_EXPORT_BACKDOOR_UNAVAILABLE",
            "INVOCATION_STRATEGY_METADATA_INVALID",
            "INVOCATION_TARGET_METADATA_INVALID",
            "HOST_BEHAVIOR_CALLBACK_ONLY_DESTRUCTIVE",
            "HOST_BEHAVIOR_ENTRYPOINT_REPLACED",
        }:
            fields.add("pe_invoke")
        if reason.code == "MODULE_FIXTURE_ONLY":
            fields.add("execute")
        if reason.code.startswith("XOR_KEY_"):
            fields.add("decoder")
    if current_evaluation.missing_imports:
        fields.add("iat_policy")

    field_order = (*REQUIRED_SLOTS, "payload_location", "iat_policy")
    ordered_fields = [field for field in field_order if field in fields]
    option_values: dict[str, tuple[str, ...]] = {
        slot: tuple(sorted(registry.modules[slot]))
        for slot in REQUIRED_SLOTS
    }
    option_values["payload_location"] = ("auto", "code", "rdata")
    option_values["iat_policy"] = ("auto", "reuse_only")

    candidates: list[
        tuple[
            tuple[int, int, tuple[str, ...]],
            _RecipeEvaluation,
            BuildConfig,
            bool,
        ]
    ] = []

    def consider(candidate_config: BuildConfig) -> None:
        recipe = candidate_config.recipe
        evaluation = _evaluate_recipe(
            candidate_config,
            recipe,
            registry,
            payload,
            host,
        )
        if evaluation.classification == CLASS_INCOMPATIBLE:
            return
        if any(module.fixture_only for module in evaluation.selected):
            return
        if any(
            module.host_behavior in {
                "callback_only_destructive",
                "entrypoint_replaced",
            }
            for module in evaluation.selected
        ):
            return
        requires_repair = bool(evaluation.missing_imports)
        candidate_policy, _ = _effective_iat_policy(candidate_config)
        candidate_policy = candidate_policy or candidate_config.iat_policy
        changed = [
            f"{slot}={getattr(recipe, slot)}"
            for slot in REQUIRED_SLOTS
            if current_recipe[slot] != getattr(recipe, slot)
        ]
        if candidate_config.payload_location != config.payload_location:
            changed.append(
                f"payload_location={candidate_config.payload_location}"
            )
        if candidate_policy != current_policy:
            changed.append(f"iat_policy={candidate_policy}")
        score = (
            1 if requires_repair else 0,
            len(changed),
            tuple(changed),
        )
        candidates.append(
            (
                score,
                evaluation,
                candidate_config,
                requires_repair,
            )
        )

    consider(config)
    for depth in range(1, min(2, len(ordered_fields)) + 1):
        for selected_fields in itertools.combinations(
            ordered_fields,
            depth,
        ):
            values = [
                tuple(
                    value
                    for value in option_values[field]
                    if value
                    != (
                        current_recipe[field]
                        if field in REQUIRED_SLOTS
                        else (
                            config.payload_location
                            if field == "payload_location"
                            else current_policy
                        )
                    )
                )
                for field in selected_fields
            ]
            for replacements in itertools.product(*values):
                recipe_values = dict(current_recipe)
                payload_location = config.payload_location
                iat_policy = current_policy
                for field, value in zip(
                    selected_fields,
                    replacements,
                    strict=True,
                ):
                    if field in REQUIRED_SLOTS:
                        recipe_values[field] = value
                    elif field == "payload_location":
                        payload_location = value
                    else:
                        iat_policy = value
                consider(
                    replace(
                        config,
                        recipe=Recipe(**recipe_values),
                        payload_location=payload_location,
                        iat_policy=iat_policy,
                        repair_missing_iat=None,
                    )
                )

    if not candidates:
        return None
    (
        _,
        evaluation,
        recommended_config,
        requires_repair,
    ) = sorted(candidates, key=lambda item: item[0])[0]
    recipe = evaluation.recipe.as_dict()
    changes = [
        {
            "field": slot,
            "from": current_recipe[slot],
            "to": recipe[slot],
        }
        for slot in REQUIRED_SLOTS
        if current_recipe[slot] != recipe[slot]
    ]
    if config.payload_location != recommended_config.payload_location:
        changes.append(
            {
                "field": "payload_location",
                "from": config.payload_location,
                "to": recommended_config.payload_location,
            }
        )
    recommended_policy, _ = _effective_iat_policy(recommended_config)
    recommended_policy = recommended_policy or recommended_config.iat_policy
    if current_policy != recommended_policy:
        changes.append(
            {
                "field": "iat_policy",
                "from": current_policy,
                "to": recommended_policy,
            }
        )
    return {
        "recipe": recipe,
        "payload_location": recommended_config.payload_location,
        "iat_policy": recommended_policy,
        "repair_missing_iat": requires_repair,
        "classification": evaluation.classification,
        "changes": changes,
        "reason": (
            "selected settings are already the reason-directed recommendation"
            if not changes
            else "smallest compatible change set for the reported reasons; "
            "unchanged IAT is preferred"
        ),
    }


def analyze_compatibility(
    config: BuildConfig,
    *,
    registry: ModuleRegistry | None = None,
    toolchain: Toolchain | None = None,
    toolchain_status: ToolchainStatus | None = None,
    signing_probe: SigningProbe = _default_signing_probe,
    cache: CompatibilityCache | None = None,
    authoritative: bool = True,
) -> CompatibilityReport:
    reasons: list[CompatibilityReason] = []
    warnings: list[CompatibilityReason] = []

    profile: ExecutionProfile | None = None
    try:
        profile = resolve_profile(config.profile)
    except ValueError as exc:
        reasons.append(
            _reason("PROFILE_INVALID", str(exc), "profile")
        )

    toolchain_name: str | None = None
    if profile is not None:
        try:
            toolchain_name = resolve_toolchain_name(
                config.toolchain, profile
            )
        except ValueError as exc:
            reasons.append(
                _reason("TOOLCHAIN_INVALID", str(exc), "toolchain")
            )

    actual_registry = registry
    if actual_registry is None:
        try:
            actual_registry = ModuleRegistry(config.modules_root).discover()
            actual_registry.validate_all()
        except (OSError, ValueError, ModuleError) as exc:
            reasons.append(
                _reason(
                    "MODULE_REGISTRY_INVALID",
                    str(exc),
                    "recipe",
                )
            )
            actual_registry = ModuleRegistry(config.modules_root)
    else:
        try:
            actual_registry.validate_all()
        except (OSError, ValueError, ModuleError) as exc:
            reasons.append(
                _reason(
                    "MODULE_REGISTRY_INVALID",
                    str(exc),
                    "recipe",
                )
            )

    if config.payload_kind not in {"raw", "dll"}:
        reasons.append(
            _reason(
                "PAYLOAD_KIND_UNSUPPORTED",
                f"unsupported payload kind {config.payload_kind!r}",
                "payload_kind",
            )
        )
    if cache is None:
        payload, payload_reasons = _inspect_payload(
            config.payload,
            config.payload_kind,
        )
        host, host_reasons = _inspect_host(
            config.host,
            config.dll_export,
        )
    else:
        payload, payload_reasons = cache.inspect_payload(
            config.payload,
            config.payload_kind,
        )
        host, host_reasons = cache.inspect_host(
            config.host,
            config.dll_export,
        )
    reasons.extend(_path_reasons(config, profile))
    reasons.extend(payload_reasons)
    reasons.extend(host_reasons)
    if host.guard_cf_enabled:
        warnings.append(
            _reason(
                "HOST_CFG_WILL_BE_DISABLED",
                "host enables Control Flow Guard; the build will clear its "
                "Guard CF opt-in because injected carrier, payload, and "
                "payload-created code are absent from the original Guard CF "
                "function table",
                "injectable",
                level="warning",
                dll_characteristics=host.dll_characteristics,
            )
        )
    if payload.exists and payload.size == 0:
        reasons.append(
            _reason(
                "PAYLOAD_EMPTY",
                "payload is empty",
                "payload",
            )
        )

    evaluation = _evaluate_recipe(
        config, config.recipe, actual_registry, payload, host
    )
    reasons.extend(evaluation.reasons)
    warnings.extend(evaluation.warnings)

    placement_plan: dict[str, Any] | None = None
    invocation_plan: dict[str, Any] | None = None
    if authoritative and evaluation.selected:
        memory = next(
            item for item in evaluation.selected if item.slot == "memory"
        )
        pe_invoke = next(
            item for item in evaluation.selected if item.slot == "pe_invoke"
        )
        payload_location, _ = _effective_payload_location(config, memory)
        if (
            host.layout is not None
            and payload_location is not None
            and payload.size > 0
            and not any(
                item.code.startswith("PAYLOAD_LOCATION_")
                for item in reasons
            )
        ):
            payload_alignment = int(
                memory.config.get("payload_alignment", 16)
            )
            placement_mode = str(
                memory.config.get("placement_mode", "in_place")
            )
            execution_alignment = int(
                memory.config.get(
                    "execution_alignment", payload_alignment
                )
            )
            page_isolation = bool(
                memory.config.get("page_isolation", False)
            )
            reserve_size = (
                align_up(payload.size, payload_alignment)
                if page_isolation and placement_mode == "in_place"
                else None
            )
            try:
                planner = PlacementPlanner(host.layout)
                payload_request = PlacementRequest(
                    "payload",
                    payload.size,
                    payload_alignment,
                    payload_location,
                    reserve_size=reserve_size,
                )
                payload_decision = planner.allocate(payload_request)
                reservations: list[dict[str, Any]] = []
                if reserve_size is not None:
                    protected = Range(
                        payload_decision.start,
                        payload_decision.start + int(reserve_size or 0),
                    )
                    reservations.append(
                        {
                            "name": "payload_execution_pages",
                            "start_rva": protected.start,
                            "end_rva": protected.end,
                            "size": protected.size,
                        }
                    )
                decisions = [payload_decision]
                if placement_mode == "split_image":
                    destination_reserve_size = (
                        align_up(payload.size, execution_alignment)
                        if page_isolation
                        else None
                    )
                    destination_decision = planner.allocate(
                        PlacementRequest(
                            "destination",
                            payload.size,
                            execution_alignment,
                            "code",
                            reserve_size=destination_reserve_size,
                        )
                    )
                    decisions.append(destination_decision)
                    if destination_reserve_size is not None:
                        reservations.append(
                            {
                                "name": "payload_execution_pages",
                                "start_rva": destination_decision.start,
                                "end_rva": (
                                    destination_decision.start
                                    + destination_reserve_size
                                ),
                                "size": destination_reserve_size,
                            }
                        )
                carrier_request = PlacementRequest(
                    "carrier_reserve",
                    64 * 1024,
                    16,
                    "code",
                )
                carrier_decision = planner.allocate(carrier_request)
                decisions.append(carrier_decision)
                placement_plan = {
                    "algorithm": PLACEMENT_ALGORITHM,
                    "layout_digest": host.layout.digest,
                    "carrier_reserve_size": 64 * 1024,
                    "placement_mode": placement_mode,
                    "allocations": [item.to_dict() for item in decisions],
                    "reservations": reservations,
                    "candidate_interval_count": len(host.layout.intervals),
                    "exclusion_count": len(host.layout.exclusions),
                }
            except ValueError as exc:
                reasons.append(
                    _reason(
                        "PLACEMENT_PLAN_UNAVAILABLE",
                        str(exc),
                        "payload_location",
                    )
                )
        strategy = str(
            pe_invoke.config.get("invocation_strategy", "overwrite")
        )
        target_kind = str(
            pe_invoke.config.get(
                "invocation_target",
                "dllmain"
                if pe_invoke.config.get("host_kind", "exe") == "dll"
                else "entrypoint",
            )
        )
        target = (
            host.export_invocation
            if target_kind == "export"
            else host.entry_invocation
        )
        site = (
            host.export_backdoor
            if target_kind == "export"
            else host.entry_backdoor
        )
        invocation_plan = {
            "strategy": strategy,
            "target_kind": target_kind,
            "target": target,
            "backdoor_site": site if strategy == "backdoor" else None,
            "preserves_address_of_entry_point": strategy in {
                "backdoor",
                "target_overwrite",
            },
            "original_host_code_continues": False,
        }

    actual_toolchain = toolchain
    status = toolchain_status
    if toolchain_name is not None:
        try:
            if (
                cache is not None
                and actual_toolchain is None
                and status is None
            ):
                actual_toolchain, status = cache.toolchain(toolchain_name)
            else:
                actual_toolchain = actual_toolchain or create_toolchain(
                    toolchain_name
                )
                status = status or actual_toolchain.doctor()
        except Exception as exc:
            status = ToolchainStatus(
                name=toolchain_name,
                ready=False,
                identity="unavailable",
                tools={},
                diagnostics=(str(exc),),
            )
        if status.name != toolchain_name:
            reasons.append(
                _reason(
                    "TOOLCHAIN_STATUS_MISMATCH",
                    f"toolchain status is for {status.name}, expected "
                    f"{toolchain_name}",
                    "toolchain",
                )
            )
        if not status.ready:
            diagnostic = "; ".join(status.diagnostics) or "not ready"
            reasons.append(
                _reason(
                    "TOOLCHAIN_UNAVAILABLE",
                    f"{toolchain_name} toolchain is unavailable: {diagnostic}",
                    "toolchain",
                )
            )

    effective_signing = bool(
        config.self_sign or (profile is not None and profile.signing_required)
    )
    if (
        profile is not None
        and actual_toolchain is not None
        and toolchain_name is not None
    ):
        if cache is not None and signing_probe is _default_signing_probe:
            signing = cache.signing(
                profile.name,
                actual_toolchain,
                effective_signing,
                profile.signing_required,
            )
        else:
            signing = signing_probe(
                profile.name,
                actual_toolchain,
                effective_signing,
                profile.signing_required,
            )
    else:
        signing = SigningFacts(
            enabled=effective_signing,
            required=bool(profile and profile.signing_required),
            ready=not effective_signing,
            implementation=None,
            tool=None,
            diagnostic=(
                None
                if not effective_signing
                else "toolchain/profile resolution failed"
            ),
        )
    if signing.enabled and not signing.ready:
        reasons.append(
            _reason(
                "SIGNING_UNAVAILABLE",
                f"signing is unavailable: {signing.diagnostic or 'not ready'}",
                "self_sign",
            )
        )

    error_reasons = [item for item in reasons if item.level == "error"]
    action_blocked = not evaluation.buildable
    classification = (
        CLASS_INCOMPATIBLE
        if error_reasons
        else evaluation.classification
    )
    buildable = not error_reasons and not action_blocked

    profile_name = profile.name if profile is not None else config.profile
    normalized_iat_policy, _ = _effective_iat_policy(config)
    normalized = {
        "root": str(config.root.resolve()),
        "payload": str(config.payload.resolve()),
        "payload_kind": config.payload_kind,
        "injectable": str(config.host.resolve()),
        "output": str(config.output.resolve()),
        "artifact_dir": str(config.artifact_dir.resolve()),
        "profile": profile_name,
        "toolchain": toolchain_name or config.toolchain,
        "recipe": config.recipe.as_dict(),
        "guardrail_expected_sha256": (
            sha256_bytes(config.guardrail_value.encode("utf-8"))
            if config.guardrail_value is not None
            else None
        ),
        "xor_key_hex": (
            config.xor_key.hex()
            if config.recipe.decoder in KEYED_DECODERS
            else None
        ),
        "self_sign_requested": config.self_sign,
        "signing_effective": effective_signing,
        "iat_policy": normalized_iat_policy or config.iat_policy,
        "payload_location": config.payload_location,
        "dll_export": config.dll_export,
        "repair_missing_iat_alias": config.repair_missing_iat,
    }
    toolchain_facts = {
        "name": toolchain_name or config.toolchain,
        "ready": bool(status and status.ready),
        "identity": status.identity if status is not None else "unavailable",
        "tools": (
            dict(sorted(status.tools.items())) if status is not None else {}
        ),
        "diagnostics": (
            list(status.diagnostics) if status is not None else []
        ),
        "metadata": status.metadata if status is not None else None,
    }
    input_digest = ""
    if authoritative:
        registry_facts = [
            {
                "qualified_name": module.qualified_name,
                "digest": module.digest,
                "fixture_only": module.fixture_only,
                "host_behavior": module.host_behavior,
            }
            for slot in REQUIRED_SLOTS
            for module in sorted(
                actual_registry.modules.get(slot, {}).values(),
                key=lambda item: item.name,
            )
        ]
        digest_config = {
            key: value
            for key, value in normalized.items()
            if key not in {"output", "artifact_dir"}
        }
        digest_config["output_suffix"] = config.output.suffix.lower()
        digest_config["output_policy_reason_codes"] = [
            item.code
            for item in reasons
            if item.field in {"output", "artifact_dir"}
        ]
        digest_material = {
            "schema": COMPATIBILITY_SCHEMA,
            "config": digest_config,
            "registry": registry_facts,
            "payload": payload.to_dict(),
            "injectable": host.to_dict(),
            "toolchain": toolchain_facts,
            "signing": signing.to_dict(),
            "required_imports": [
                f"{dll}!{name}" for dll, name in evaluation.required_imports
            ],
            "planned_repairs": [
                dict(item) for item in evaluation.planned_repairs
            ],
            "placement_plan": placement_plan,
            "invocation_plan": invocation_plan,
        }
        input_digest = sha256_bytes(
            json.dumps(
                digest_material,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )

    selected_modules = tuple(
        {
            "slot": module.slot,
            "name": module.name,
            "qualified_name": module.qualified_name,
            "digest": module.digest,
            "fixture_only": module.fixture_only,
            "host_behavior": module.host_behavior,
            "required_imports": list(module.required_imports),
        }
        for module in evaluation.selected
    )
    global_errors = [
        item
        for item in reasons
        if item.level == "error"
        and item not in evaluation.reasons
    ]
    choices = (
        _choice_matrix(
            config, actual_registry, payload, host
        )
        if all(actual_registry.modules.get(slot) for slot in REQUIRED_SLOTS)
        else {}
    )
    recommendation = (
        _recommendation(
            config,
            actual_registry,
            payload,
            host,
            global_errors,
            evaluation,
        )
        if choices
        else None
    )
    return CompatibilityReport(
        classification=classification,
        buildable=buildable,
        input_digest=input_digest,
        normalized_config=normalized,
        selected_modules=selected_modules,
        payload=payload,
        injectable=host,
        toolchain=toolchain_facts,
        signing=signing,
        required_imports=tuple(
            f"{dll}!{name}" for dll, name in evaluation.required_imports
        ),
        missing_imports=evaluation.missing_imports,
        planned_repairs=evaluation.planned_repairs,
        reasons=tuple(reasons),
        warnings=tuple(warnings),
        recommendation=recommendation,
        choices=choices,
        placement_plan=placement_plan,
        invocation_plan=invocation_plan,
    )
