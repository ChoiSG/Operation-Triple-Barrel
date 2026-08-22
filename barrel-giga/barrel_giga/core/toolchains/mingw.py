from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

import pefile

from ..artifacts import (
    CarrierArtifact,
    DataFixup,
    DataReference,
    ImportFixup,
    write_json,
)
from .base import Toolchain, ToolchainError, ToolchainStatus
from .coff import CoffFile, REL32_TYPES


_REGISTER_NAMES = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


class MingwToolchain(Toolchain):
    """Build carriers from AMD64 PE/COFF symbols and relocations."""

    name = "mingw"

    def __init__(self, prefix: str = "x86_64-w64-mingw32-") -> None:
        self.prefix = prefix

    def _tools(self) -> dict[str, str]:
        tools: dict[str, str] = {}
        missing: list[str] = []
        for role, name in (
            ("gcc", f"{self.prefix}gcc"),
            ("ld", f"{self.prefix}ld"),
            ("objcopy", f"{self.prefix}objcopy"),
            ("objdump", f"{self.prefix}objdump"),
        ):
            path = shutil.which(name)
            if path is None:
                missing.append(name)
            else:
                tools[role] = str(Path(path).resolve())
        if missing:
            raise ToolchainError(f"missing MinGW tools: {', '.join(missing)}")
        return tools

    @staticmethod
    def _environment() -> dict[str, str]:
        environment = dict(os.environ)
        environment.update(
            {
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
                "SOURCE_DATE_EPOCH": "0",
            }
        )
        return environment

    @classmethod
    def _run(cls, command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=cls._environment(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if result.returncode != 0:
            raise ToolchainError(
                f"command failed ({result.returncode}): {subprocess.list2cmdline(command)}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def doctor(self) -> ToolchainStatus:
        try:
            tools = self._tools()
            result = self._run([tools["gcc"], "--version"], Path.cwd())
            identity = result.stdout.splitlines()[0].strip()
            return ToolchainStatus("mingw", True, identity, tools)
        except Exception as exc:
            return ToolchainStatus("mingw", False, "unavailable", {}, (str(exc),))

    @staticmethod
    def _rip_lea(code: bytes, relocation_offset: int) -> tuple[int, str]:
        start = relocation_offset - 3
        if start < 0 or relocation_offset + 4 > len(code):
            raise ToolchainError("COFF RIP-relative LEA relocation is out of range")
        rex, opcode, modrm = code[start : start + 3]
        if opcode != 0x8D or (rex & 0xF8) != 0x48 or (modrm & 0xC7) != 0x05:
            raise ToolchainError(
                "COFF data/payload relocation is not a seven-byte RIP-relative LEA"
            )
        register_number = ((modrm >> 3) & 7) | (8 if rex & 0x04 else 0)
        return start, _REGISTER_NAMES[register_number]

    @staticmethod
    def _relative_addend(code: bytes, offset: int) -> int:
        if offset < 0 or offset + 4 > len(code):
            raise ToolchainError("COFF REL32 relocation field is outside .text")
        return struct.unpack_from("<i", code, offset)[0]

    @staticmethod
    def _apply_internal_rel32(
        code: bytearray,
        relocation_offset: int,
        relocation_type: int,
        target_offset: int,
    ) -> None:
        addend = MingwToolchain._relative_addend(code, relocation_offset)
        trailing = relocation_type - min(REL32_TYPES)
        displacement = target_offset + addend - (
            relocation_offset + 4 + trailing
        )
        if not -(1 << 31) <= displacement < (1 << 31):
            raise ToolchainError("internal COFF REL32 relocation is out of range")
        struct.pack_into("<i", code, relocation_offset, displacement)

    def _extract_carrier(
        self,
        coff: CoffFile,
        declared_imports: dict[str, str],
    ) -> tuple[bytes, int, list[ImportFixup], list[DataFixup]]:
        text_sections = [section for section in coff.sections if section.name == ".text"]
        if len(text_sections) != 1:
            raise ToolchainError(
                f"combined carrier must contain exactly one .text section, found {len(text_sections)}"
            )
        text = text_sections[0]
        code = bytearray(text.data)
        if not code:
            raise ToolchainError("combined carrier .text section is empty")

        entries = coff.named_symbols("AlignRSP")
        if len(entries) != 1:
            raise ToolchainError(
                f"COFF entry symbol AlignRSP occurs {len(entries)} times"
            )
        entry = entries[0]
        if entry.section_number != text.index or not 0 <= entry.value < len(code):
            raise ToolchainError("COFF entry symbol is outside .text")
        payload_symbols = coff.named_symbols("supergiga_payload")
        if len(payload_symbols) != 1 or payload_symbols[0].section_number != 0:
            raise ToolchainError(
                "COFF payload symbol must occur exactly once and remain undefined"
            )
        destination_symbols = coff.named_symbols("supergiga_destination")
        if len(destination_symbols) > 1 or (
            destination_symbols
            and destination_symbols[0].section_number != 0
        ):
            raise ToolchainError(
                "COFF destination symbol must remain uniquely undefined"
            )

        imports: list[ImportFixup] = []
        external_fixups: dict[str, DataFixup] = {}
        data_by_section: dict[int, DataFixup] = {}
        declared = {name.lower(): dll for name, dll in declared_imports.items()}

        for relocation in text.relocations:
            symbol = coff.symbol(relocation.symbol_index)
            if relocation.type not in REL32_TYPES:
                raise ToolchainError(
                    f"unsupported .text COFF relocation 0x{relocation.type:04X} "
                    f"for {symbol.name}"
                )

            if symbol.section_number == text.index:
                if not 0 <= symbol.value < len(code):
                    raise ToolchainError(f"COFF symbol {symbol.name} is outside .text")
                self._apply_internal_rel32(
                    code,
                    relocation.virtual_address,
                    relocation.type,
                    symbol.value,
                )
                continue

            if symbol.section_number == 0:
                if symbol.name.startswith("__imp_"):
                    name = symbol.name[len("__imp_") :]
                    dll = declared.get(name.lower())
                    if dll is None:
                        raise ToolchainError(
                            f"carrier requested undeclared import {name}; add it to a module manifest"
                        )
                    start = relocation.virtual_address - 2
                    if start < 0 or relocation.virtual_address + 4 > len(code):
                        raise ToolchainError(f"COFF import relocation for {name} is out of range")
                    opcode = bytes(code[start : start + 2])
                    register: str | None = None
                    instruction_size = 6
                    if opcode == b"\xFF\x15":
                        kind = "call_iat"
                    elif opcode == b"\xFF\x25":
                        kind = "jump_iat"
                    else:
                        start = relocation.virtual_address - 3
                        if start < 0 or start + 7 > len(code):
                            raise ToolchainError(f"COFF IAT load for {name} is out of range")
                        rex, mov_opcode, modrm = code[start : start + 3]
                        if (
                            mov_opcode != 0x8B
                            or (rex & 0xF8) != 0x48
                            or (modrm & 0xC7) != 0x05
                        ):
                            raise ToolchainError(
                                f"COFF import {name} is not a supported RIP-relative IAT reference"
                            )
                        number = ((modrm >> 3) & 7) | (8 if rex & 0x04 else 0)
                        register = _REGISTER_NAMES[number]
                        kind = "load_iat"
                        instruction_size = 7
                    imports.append(
                        ImportFixup(
                            dll=dll,
                            name=name,
                            placeholder=bytes(code[start : start + instruction_size]),
                            kind=kind,
                            register=register,
                            code_offset=start,
                        )
                    )
                    continue
                if symbol.name in {
                    "supergiga_payload",
                    "supergiga_destination",
                }:
                    start, register = self._rip_lea(
                        code, relocation.virtual_address
                    )
                    target = (
                        "payload"
                        if symbol.name == "supergiga_payload"
                        else "destination"
                    )
                    fixup = external_fixups.setdefault(
                        symbol.name,
                        DataFixup(name=symbol.name, target=target),
                    )
                    fixup.references.append(
                        DataReference(
                            register=register,
                            placeholder=bytes(code[start : start + 7]),
                            code_offset=start,
                        )
                    )
                    continue
                raise ToolchainError(f"unresolved COFF symbol {symbol.name}")

            target_section = coff.section(symbol.section_number)
            if not target_section.name.startswith(".rdata"):
                raise ToolchainError(
                    f"unsupported carrier relocation from .text to {target_section.name}"
                )
            start, register = self._rip_lea(code, relocation.virtual_address)
            addend = self._relative_addend(code, relocation.virtual_address)
            target_offset = symbol.value + addend
            if not 0 <= target_offset < len(target_section.data):
                raise ToolchainError(
                    f"COFF data relocation for {symbol.name} is outside {target_section.name}"
                )
            data_fixup = data_by_section.setdefault(
                target_section.index,
                DataFixup(
                    name=f"coff_section_{target_section.index}_{target_section.name}",
                    data=target_section.data,
                    target="data",
                ),
            )
            data_fixup.references.append(
                DataReference(
                    register=register,
                    placeholder=bytes(code[start : start + 7]),
                    target_offset=target_offset,
                    code_offset=start,
                )
            )

        for section_number, data_fixup in data_by_section.items():
            if section_number and coff.section(section_number).relocations:
                raise ToolchainError(
                    f"carrier data section {coff.section(section_number).name} has unsupported relocations"
                )
            if not data_fixup.references:
                raise ToolchainError(f"carrier fixup {data_fixup.name} has no references")
        if "supergiga_payload" not in external_fixups:
            raise ToolchainError("carrier emitted no supergiga_payload relocation")
        return (
            bytes(code),
            entry.value,
            imports,
            [
                external_fixups[name]
                for name in ("supergiga_payload", "supergiga_destination")
                if name in external_fixups
            ]
            + list(data_by_section.values()),
        )

    def compile_carrier(
        self,
        source: Path,
        build_dir: Path,
        declared_imports: dict[str, str],
    ) -> CarrierArtifact:
        build_dir.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        compiler_object = build_dir / "carrier.compiler.obj"
        entry_object = build_dir / "carrier.entry.obj"
        combined_object = build_dir / "carrier.combined.obj"
        disassembly = build_dir / "carrier.coff.disassembly.txt"
        coff_evidence = build_dir / "carrier.coff.json"
        entry_source = Path(__file__).resolve().parents[3] / "templates" / "carrier_entry.S"
        if not entry_source.is_file():
            raise ToolchainError(f"MinGW carrier entry source is missing: {entry_source}")

        compile_command = [
            tools["gcc"],
            "-c",
            "-std=c11",
            "-O1",
            "-fno-inline",
            "-Wall",
            "-Werror",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
            "-fno-ident",
            "-fno-toplevel-reorder",
            "-o",
            str(compiler_object),
            str(source),
        ]
        entry_command = [
            tools["gcc"],
            "-c",
            "-o",
            str(entry_object),
            str(entry_source),
        ]
        combine_command = [
            tools["ld"],
            "-r",
            "--no-insert-timestamp",
            "-o",
            str(combined_object),
            str(entry_object),
            str(compiler_object),
        ]
        diagnostics: list[str] = []
        for command in (compile_command, entry_command, combine_command):
            result = self._run(command, build_dir)
            diagnostics.extend(
                item
                for item in (result.stdout.strip(), result.stderr.strip())
                if item
            )

        coff = CoffFile.parse(combined_object)
        code, entry_offset, imports, data_fixups = self._extract_carrier(
            coff, declared_imports
        )
        write_json(coff_evidence, coff.evidence())
        disassembly_result = self._run(
            [tools["objdump"], "-drwC", str(combined_object)], build_dir
        )
        disassembly.write_text(disassembly_result.stdout, encoding="utf-8")
        diagnostics.extend(
            item
            for item in (
                disassembly_result.stderr.strip(),
                f"parsed {len(coff.sections)} COFF sections and "
                f"{sum(len(section.relocations) for section in coff.sections)} relocations",
            )
            if item
        )
        status = self.doctor()
        return CarrierArtifact(
            code=code,
            entry_offset=entry_offset,
            import_fixups=imports,
            data_fixups=data_fixups,
            diagnostics=diagnostics,
            compiler_identity=status.identity,
            tool_paths=tools,
            commands=[compile_command, entry_command, combine_command],
            source_path=source,
            retained_artifacts={
                "compiler_object": compiler_object,
                "entry_object": entry_object,
                "combined_object": combined_object,
                "coff_evidence": coff_evidence,
                "disassembly": disassembly,
            },
        )

    def build_raw_fixture(self, source: Path, output: Path, build_dir: Path) -> bytes:
        build_dir.mkdir(parents=True, exist_ok=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        fixture_object = build_dir / f"{source.stem}.mingw.obj"
        self._run(
            [tools["gcc"], "-c", "-o", str(fixture_object), str(source.resolve())],
            build_dir,
        )
        coff = CoffFile.parse(fixture_object)
        text_sections = [section for section in coff.sections if section.name == ".text"]
        starts = coff.named_symbols("payload_start")
        if len(text_sections) != 1 or len(starts) != 1:
            raise ToolchainError(f"fixture {source.name} has an ambiguous .text/payload_start")
        if starts[0].section_number != text_sections[0].index or starts[0].value != 0:
            raise ToolchainError(f"fixture {source.name} payload_start is not at .text offset zero")
        if text_sections[0].relocations:
            raise ToolchainError(f"fixture {source.name} retains unresolved relocations")
        payload = text_sections[0].data
        output.write_bytes(payload)
        return payload

    def build_dll_fixture(
        self,
        source: Path,
        output: Path,
        build_dir: Path,
        libraries: tuple[str, ...] = (),
        exports: tuple[str, ...] = (),
    ) -> Path:
        build_dir.mkdir(parents=True, exist_ok=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        fixture_object = build_dir / f"{source.stem}.mingw.obj"
        compile_command = [
            tools["gcc"],
            "-c",
            "-o",
            str(fixture_object),
            str(source.resolve()),
        ]
        link_libraries = [
            f"-l{Path(library).stem}" for library in libraries
        ] or ["-lkernel32"]
        link_command = [
            tools["gcc"],
            "-shared",
            "-nostdlib",
            "-Wl,--entry,DllMain",
            "-Wl,--no-insert-timestamp",
            "-Wl,--dynamicbase",
            "-Wl,--nxcompat",
            "-Wl,--enable-reloc-section",
            *(("-Wl,--export-all-symbols",) if exports else ()),
            "-o",
            str(output.resolve()),
            str(fixture_object),
            *link_libraries,
        ]
        self._run(compile_command, build_dir)
        self._run(link_command, build_dir)
        image = pefile.PE(str(output), fast_load=False)
        try:
            if image.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
                raise ToolchainError(f"fixture {source.name} is not AMD64")
            if not image.FILE_HEADER.Characteristics & 0x2000:
                raise ToolchainError(f"fixture {source.name} is not a DLL")
            if image.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
                raise ToolchainError(f"fixture {source.name} has no entry point")
        finally:
            image.close()
        return output

    def build_runtime_helper(self, source: Path, output: Path, build_dir: Path) -> Path:
        build_dir.mkdir(parents=True, exist_ok=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        command = [
            tools["gcc"],
            "-std=c11",
            "-O2",
            "-Wall",
            "-Werror",
            "-Wl,--no-insert-timestamp",
            "-municode",
            "-o",
            str(output.resolve()),
            str(source.resolve()),
        ]
        self._run(command, build_dir)
        return output

    def build_exe_fixture(self, source: Path, output: Path, build_dir: Path) -> Path:
        build_dir.mkdir(parents=True, exist_ok=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        fixture_object = build_dir / f"{source.stem}.mingw.obj"
        self._run(
            [tools["gcc"], "-c", "-o", str(fixture_object), str(source.resolve())],
            build_dir,
        )
        self._run(
            [
                tools["gcc"],
                "-nostdlib",
                "-Wl,--entry,mainCRTStartup",
                "-Wl,--subsystem,console",
                "-Wl,--no-insert-timestamp",
                "-Wl,--dynamicbase",
                "-Wl,--nxcompat",
                "-o",
                str(output.resolve()),
                str(fixture_object),
                "-lkernel32",
                "-luser32",
            ],
            build_dir,
        )
        image = pefile.PE(str(output), fast_load=False)
        try:
            if image.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
                raise ToolchainError(f"fixture {source.name} is not AMD64")
            if image.FILE_HEADER.Characteristics & 0x2000:
                raise ToolchainError(f"fixture {source.name} unexpectedly became a DLL")
            if image.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
                raise ToolchainError(f"fixture {source.name} has no entry point")
        finally:
            image.close()
        return output
