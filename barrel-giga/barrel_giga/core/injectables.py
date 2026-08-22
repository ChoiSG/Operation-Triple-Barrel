from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

import pefile

from .artifacts import sha256_file


MINIMUM_CORPUS_CODE_CAPACITY = 250 * 1024
ImportRequirement = tuple[str, str]


@dataclass(frozen=True)
class ImportSlot:
    name: str
    name_offset: int


@dataclass(frozen=True)
class InjectableCandidate:
    path: Path
    file_size: int
    sha256: str
    machine: int | None
    pe32_plus: bool
    host_kind: str | None
    section_name: str | None
    code_capacity: int
    import_dlls: tuple[str, ...]
    external_imports: tuple[str, ...]
    missing_imports: tuple[str, ...]
    iat_repairs: tuple[dict[str, object], ...]
    rejection_reasons: tuple[str, ...]

    @property
    def eligible(self) -> bool:
        return not self.rejection_reasons

    @property
    def requires_iat_repair(self) -> bool:
        return bool(self.iat_repairs)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.path.name,
            "path": str(self.path),
            "file_size": self.file_size,
            "sha256": self.sha256,
            "machine": f"0x{self.machine:04X}" if self.machine is not None else None,
            "pe32_plus": self.pe32_plus,
            "host_kind": self.host_kind,
            "section_name": self.section_name,
            "code_capacity": self.code_capacity,
            "import_dlls": list(self.import_dlls),
            "external_imports": list(self.external_imports),
            "missing_imports": list(self.missing_imports),
            "iat_repairs": [dict(item) for item in self.iat_repairs],
            "requires_iat_repair": self.requires_iat_repair,
            "eligible": self.eligible,
            "rejection_reasons": list(self.rejection_reasons),
        }


def _default_system_directory() -> Path | None:
    if os.name != "nt":
        return None
    system_root = os.environ.get("SystemRoot")
    return Path(system_root) / "System32" if system_root else None


def _is_system_import(name: str, system_directory: Path | None) -> bool:
    lowered = name.lower()
    if lowered.startswith(("api-ms-win-", "ext-ms-win-")):
        return True
    return system_directory is None or (system_directory / lowered).is_file()


def plan_iat_repairs(
    imports: dict[str, list[ImportSlot]],
    required_imports: Iterable[ImportRequirement],
) -> tuple[tuple[str, ...], tuple[dict[str, object], ...], str | None]:
    required = sorted(
        {(dll.lower(), name.lower()): (dll, name) for dll, name in required_imports}.values(),
        key=lambda item: (item[0].lower(), item[1].lower()),
    )
    protected: dict[str, set[str]] = {}
    for dll, name in required:
        protected.setdefault(dll.lower(), set()).add(name.lower())
    working = {dll.lower(): list(slots) for dll, slots in imports.items()}
    missing: list[str] = []
    repairs: list[dict[str, object]] = []

    for dll, name in required:
        dll_lower = dll.lower()
        name_lower = name.lower()
        slots = working.get(dll_lower, [])
        if any(slot.name.lower() == name_lower for slot in slots):
            continue
        missing.append(f"{dll}!{name}")
        candidates = [
            (len(slot.name), slot.name.lower(), slot.name_offset, index, slot)
            for index, slot in enumerate(slots)
            if slot.name.lower() not in protected[dll_lower]
            and len(slot.name) >= len(name)
        ]
        if not candidates:
            return (
                tuple(missing),
                tuple(repairs),
                f"no compatible {dll} import-name slot can be repaired for {name}",
            )
        _, _, _, index, old_slot = sorted(candidates)[0]
        slots[index] = ImportSlot(name=name, name_offset=old_slot.name_offset)
        repairs.append(
            {
                "dll": dll,
                "old_name": old_slot.name,
                "new_name": name,
                "name_offset": old_slot.name_offset,
            }
        )

    return tuple(missing), tuple(repairs), None


def collect_import_slots(image: Any) -> dict[str, list[ImportSlot]]:
    imports: dict[str, list[ImportSlot]] = {}
    for descriptor in getattr(image, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace").lower()
        slots: list[ImportSlot] = []
        for index, item in enumerate(descriptor.imports):
            if not item.name:
                continue
            name_offset = getattr(item, "name_offset", None)
            slots.append(
                ImportSlot(
                    name=item.name.decode("ascii", errors="replace"),
                    name_offset=(
                        int(name_offset) if name_offset is not None else index
                    ),
                )
            )
        imports.setdefault(dll, []).extend(slots)
    return imports


def inspect_injectable(
    path: Path,
    required_imports: Iterable[ImportRequirement] = (),
    *,
    minimum_code_capacity: int = MINIMUM_CORPUS_CODE_CAPACITY,
    system_directory: Path | None = None,
) -> InjectableCandidate:
    path = path.resolve()
    reasons: list[str] = []
    machine: int | None = None
    pe32_plus = False
    host_kind: str | None = None
    section_name: str | None = None
    code_capacity = 0
    import_dlls: tuple[str, ...] = ()
    external_imports: tuple[str, ...] = ()
    missing_imports: tuple[str, ...] = ()
    repairs: tuple[dict[str, object], ...] = ()
    image = None

    try:
        image = pefile.PE(str(path), fast_load=True)
        image.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )
        machine = int(image.FILE_HEADER.Machine)
        pe32_plus = int(image.OPTIONAL_HEADER.Magic) == 0x20B
        host_kind = (
            "dll" if image.FILE_HEADER.Characteristics & 0x2000 else "exe"
        )
        entrypoint = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
        for section in image.sections:
            span = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
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
                code_capacity = min(
                    int(section.Misc_VirtualSize), int(section.SizeOfRawData)
                )
                break

        imports = collect_import_slots(image)
        all_import_dlls = set(imports)
        for descriptor in getattr(image, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            all_import_dlls.add(
                descriptor.dll.decode("ascii", errors="replace").lower()
            )
        import_dlls = tuple(sorted(all_import_dlls))
        actual_system_directory = (
            system_directory
            if system_directory is not None
            else _default_system_directory()
        )
        external_imports = tuple(
            dll
            for dll in import_dlls
            if not _is_system_import(dll, actual_system_directory)
        )
        missing_imports, repairs, repair_error = plan_iat_repairs(
            imports, required_imports
        )

        if machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            reasons.append("not AMD64")
        if not pe32_plus:
            reasons.append("not PE32+")
        if host_kind != "exe":
            reasons.append("not an EXE")
        if section_name is None:
            reasons.append("no executable entry-point section")
        elif code_capacity <= minimum_code_capacity:
            reasons.append(
                f"executable section is not over {minimum_code_capacity:,} bytes"
            )
        if external_imports:
            reasons.append(
                "requires non-system DLLs: " + ", ".join(external_imports)
            )
        if repair_error:
            reasons.append(repair_error)
    except (OSError, pefile.PEFormatError, ValueError) as exc:
        reasons.append(f"invalid PE: {exc}")
    finally:
        if image is not None:
            image.close()

    return InjectableCandidate(
        path=path,
        file_size=path.stat().st_size if path.is_file() else 0,
        sha256=sha256_file(path) if path.is_file() else "",
        machine=machine,
        pe32_plus=pe32_plus,
        host_kind=host_kind,
        section_name=section_name,
        code_capacity=code_capacity,
        import_dlls=import_dlls,
        external_imports=external_imports,
        missing_imports=missing_imports,
        iat_repairs=repairs,
        rejection_reasons=tuple(reasons),
    )


Inspector = Callable[..., InjectableCandidate]


def discover_injectables(
    directory: Path,
    required_imports: Iterable[ImportRequirement],
    *,
    inspector: Inspector = inspect_injectable,
    recursive: bool = False,
) -> list[InjectableCandidate]:
    if not directory.is_dir():
        return []
    paths = directory.rglob("*.exe") if recursive else directory.glob("*.exe")
    return [
        inspector(path, required_imports)
        for path in sorted(paths, key=lambda item: (item.name.lower(), str(item)))
        if path.is_file()
    ]

