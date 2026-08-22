from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pefile

from ..artifacts import CarrierArtifact, DataFixup, DataReference, ImportFixup
from .base import Toolchain, ToolchainError, ToolchainStatus


_IMPORT_RE = re.compile(
    r"(?P<op>call|jmp)\s+QWORD\s+PTR\s+__imp_(?P<name>[A-Za-z0-9_@?$]+)",
    re.IGNORECASE,
)
_EXTERNAL_DATA_RE = re.compile(
    r"(?:lea|mov)\s+(?P<register>r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5])),"
    r"\s*(?:QWORD\s+PTR\s+)?(?:OFFSET\s+FLAT:)?"
    r"(?P<symbol>supergiga_(?:payload|destination))\b",
    re.IGNORECASE,
)
_DATA_REF_RE = re.compile(
    r"lea\s+(?P<register>r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5])),"
    r"\s*OFFSET\s+FLAT:(?P<name>\$SG[0-9]+)",
    re.IGNORECASE,
)
_DATA_START_RE = re.compile(r"^\s*(?P<name>\$SG[0-9]+)\s+DB\s+(?P<data>.+)$")
_DATA_CONT_RE = re.compile(r"^\s+DB\s+(?P<data>.+)$")
_INTERNAL_FLAT_RE = re.compile(
    r"(?P<prefix>lea\s+r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5]),\s*)"
    r"OFFSET\s+FLAT:(?P<symbol>[A-Za-z_?$@][A-Za-z0-9_?$@]*)",
    re.IGNORECASE,
)

_STALE_VS_ENVIRONMENT = {
    "include",
    "lib",
    "libpath",
    "ucrtversion",
    "universalsdkdir",
    "vcinstalldir",
    "vctoolsinstalldir",
    "visualstudioversion",
    "vsinstalldir",
    "windowssdkdir",
    "windowssdkversion",
}


def _placeholder(kind: str, name: str, index: int, size: int) -> bytes:
    seed = hashlib.sha256(f"supergiga:{kind}:{name}:{index}".encode()).digest()
    value = bytearray(seed[:size])
    value[0] = 0xF1
    value[1] = 0xF2
    return bytes(value)


def _asm_db(value: bytes, comment: str) -> str:
    encoded = ", ".join(f"0{byte:02X}H" for byte in value)
    return f"\tDB\t{encoded}\t; {comment}"


def _parse_db(value: str) -> bytes:
    value = value.split(";", 1)[0]
    output = bytearray()
    token_re = re.compile(r"'([^']*)'|(?:0)?([0-9A-Fa-f]+)H|\b([0-9]+)\b")
    for match in token_re.finditer(value):
        if match.group(1) is not None:
            output.extend(match.group(1).encode("latin-1"))
        elif match.group(2) is not None:
            output.append(int(match.group(2), 16) & 0xFF)
        else:
            output.append(int(match.group(3), 10) & 0xFF)
    return bytes(output)


class _AssemblyRewrite:
    def __init__(self, declared_imports: dict[str, str]):
        self.declared_imports = {name.lower(): dll for name, dll in declared_imports.items()}
        self.import_fixups: list[ImportFixup] = []
        self.data_fixups: dict[str, DataFixup] = {
            "supergiga_payload": DataFixup(
                name="supergiga_payload", target="payload"
            )
        }

    def rewrite(self, text: str) -> str:
        lines = text.splitlines()
        output: list[str] = []
        current_data: DataFixup | None = None
        stub_inserted = False
        skipped_segment: str | None = None

        for line in lines:
            stripped = line.strip()

            if skipped_segment is not None:
                if re.match(
                    rf"^\s*{re.escape(skipped_segment)}\s+ENDS",
                    line,
                    re.IGNORECASE,
                ):
                    skipped_segment = None
                continue
            segment_match = re.match(r"^\s*([A-Za-z0-9_?$@]+)\s+SEGMENT", line)
            if segment_match and segment_match.group(1).lower() in {"pdata", "xdata", "voltbl"}:
                skipped_segment = segment_match.group(1)
                continue

            data_start = _DATA_START_RE.match(line)
            if data_start:
                current_data = DataFixup(
                    name=data_start.group("name"),
                    data=_parse_db(data_start.group("data")),
                )
                self.data_fixups[current_data.name] = current_data
                output.append(f"; {line}")
                continue
            data_cont = _DATA_CONT_RE.match(line)
            if current_data is not None and data_cont:
                current_data.data += _parse_db(data_cont.group("data"))
                output.append(f"; {line}")
                continue
            if stripped and not stripped.startswith(";"):
                current_data = None

            if stripped.upper().startswith("INCLUDELIB"):
                output.append(f"; {line} ; removed by SuperGiga")
                continue
            if stripped.upper().startswith("EXTRN"):
                output.append(f"; {line} ; resolved by SuperGiga")
                continue
            if stripped.upper().startswith("COMM"):
                if (
                    "supergiga_payload" in stripped
                    or "supergiga_destination" in stripped
                ):
                    output.append(f"; {line} ; external image placeholder")
                    continue
                raise ToolchainError(f"unsupported mutable global in carrier assembly: {line}")
            if re.match(r"^\s*_BSS\s+SEGMENT", line, re.IGNORECASE):
                raise ToolchainError("carrier generated a _BSS segment")

            import_match = _IMPORT_RE.search(line)
            if import_match:
                name = import_match.group("name")
                dll = self.declared_imports.get(name.lower())
                if dll is None:
                    raise ToolchainError(
                        f"carrier requested undeclared import {name}; add it to a module manifest"
                    )
                kind = "call_iat" if import_match.group("op").lower() == "call" else "jump_iat"
                marker = _placeholder(kind, name, len(self.import_fixups), 6)
                self.import_fixups.append(
                    ImportFixup(dll=dll, name=name, placeholder=marker, kind=kind)
                )
                output.append(_asm_db(marker, f"SuperGiga {kind} {dll}!{name}"))
                continue

            external_match = _EXTERNAL_DATA_RE.search(line)
            if external_match:
                symbol = external_match.group("symbol").lower()
                target = (
                    "payload"
                    if symbol == "supergiga_payload"
                    else "destination"
                )
                fixup = self.data_fixups.setdefault(
                    symbol,
                    DataFixup(name=symbol, target=target),
                )
                marker = _placeholder(
                    target, fixup.name, len(fixup.references), 7
                )
                fixup.references.append(
                    DataReference(
                        register=external_match.group("register").lower(),
                        placeholder=marker,
                    )
                )
                output.append(_asm_db(marker, f"SuperGiga {target} LEA"))
                continue

            data_match = _DATA_REF_RE.search(line)
            if data_match:
                name = data_match.group("name")
                if name not in self.data_fixups:
                    raise ToolchainError(f"reference to unknown compiler data symbol {name}")
                fixup = self.data_fixups[name]
                marker = _placeholder("data", name, len(fixup.references), 7)
                fixup.references.append(
                    DataReference(
                        register=data_match.group("register").lower(),
                        placeholder=marker,
                    )
                )
                output.append(_asm_db(marker, f"SuperGiga data LEA {name}"))
                continue

            line = _INTERNAL_FLAT_RE.sub(
                lambda match: f"{match.group('prefix')}{match.group('symbol')}",
                line,
            )

            output.append(line)
            if not stub_inserted and re.match(r"^\s*_TEXT\s+SEGMENT", line, re.IGNORECASE):
                output.extend(
                    [
                        "PUBLIC\tAlignRSP",
                        "AlignRSP PROC",
                        "\tpush\trbp",
                        "\tmov\trbp, rsp",
                        "\tand\trsp, 0FFFFFFFFFFFFFFF0H",
                        "\tsub\trsp, 020H",
                        "\tcall\tsg_entry",
                        "\tmov\trsp, rbp",
                        "\tpop\trbp",
                        "\tret\t0",
                        "AlignRSP ENDP",
                    ]
                )
                stub_inserted = True

        if not stub_inserted:
            raise ToolchainError("MSVC assembly did not contain an _TEXT segment")

        active = "\n".join(
            line for line in output if not line.lstrip().startswith(";")
        )
        if (
            "__imp_" in active
            or "supergiga_payload" in active
            or "supergiga_destination" in active
        ):
            raise ToolchainError("unresolved external reference remains in rewritten assembly")
        return "\n".join(output) + "\n"


class MsvcToolchain(Toolchain):
    name = "msvc"

    def __init__(self, vcvars_path: Path | None = None):
        self.vcvars_path = vcvars_path or self._discover_vcvars()
        self._environment: dict[str, str] | None = None

    @staticmethod
    def _discover_vcvars() -> Path | None:
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Microsoft Visual Studio/2022/Professional/VC/Auxiliary/Build/vcvars64.bat",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Microsoft Visual Studio/2022/Enterprise/VC/Auxiliary/Build/vcvars64.bat",
        ]
        for candidate in candidates:
            try:
                if candidate.is_file():
                    return candidate
            except OSError:
                continue
        return None

    def _load_environment(self) -> dict[str, str]:
        if self._environment is not None:
            return self._environment
        if self.vcvars_path is None:
            raise ToolchainError("Visual Studio 2022 vcvars64.bat was not found")
        script_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".cmd",
                encoding="utf-8",
                delete=False,
            ) as script:
                script.write(f'@call "{self.vcvars_path}" >nul\n@set\n')
                script_path = Path(script.name)
            base_environment = {
                key: value
                for key, value in os.environ.items()
                if key.lower() not in _STALE_VS_ENVIRONMENT
                and not key.lower().startswith("vscmd_")
            }
            command_processor = base_environment.get(
                "ComSpec", r"C:\Windows\System32\cmd.exe"
            )
            result = subprocess.run(
                [command_processor, "/d", "/c", str(script_path)],
                env=base_environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        finally:
            if script_path is not None:
                script_path.unlink(missing_ok=True)
        if result.returncode != 0:
            raise ToolchainError(f"vcvars64.bat failed: {result.stderr.strip()}")
        environment: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key:
                    environment[key] = value
        path_keys = [key for key in environment if key.lower() == "path"]
        if path_keys:
            path_value = environment[path_keys[-1]]
            for key in path_keys:
                environment.pop(key, None)
            environment["PATH"] = path_value
        if not environment.get("PATH"):
            raise ToolchainError(
                f"vcvars64.bat did not return PATH: {self.vcvars_path}"
            )
        self._environment = environment
        return environment

    def _tools(self) -> dict[str, str]:
        missing: list[str] = []
        environment: dict[str, str] = {}
        for attempt in range(2):
            environment = self._load_environment()
            tools: dict[str, str] = {}
            missing = []
            vc_tools_root = next(
                (
                    value
                    for key, value in environment.items()
                    if key.lower() == "vctoolsinstalldir"
                ),
                "",
            )
            for name in ("cl.exe", "ml64.exe", "link.exe", "dumpbin.exe"):
                path = shutil.which(name, path=environment["PATH"])
                if path is None and vc_tools_root:
                    candidate = (
                        Path(vc_tools_root) / "bin" / "HostX64" / "x64" / name
                    )
                    if candidate.is_file():
                        path = str(candidate)
                if path is None:
                    missing.append(name)
                else:
                    tools[name] = path
            if not missing:
                return tools
            if attempt == 0:
                self._environment = None

        vc_tools = next(
            (
                value
                for key, value in environment.items()
                if key.lower() == "vctoolsinstalldir"
            ),
            "<missing>",
        )
        raise ToolchainError(
            f"{', '.join(missing)} not found after vcvars64 initialization; "
            f"vcvars={self.vcvars_path}; VCToolsInstallDir={vc_tools}"
        )

    def _prepare_command(
        self, command: list[str], cwd: Path
    ) -> list[str]:
        return list(command)

    def _run(
        self,
        command: list[str],
        environment: dict[str, str],
        cwd: Path,
    ) -> subprocess.CompletedProcess[str]:
        command[:] = self._prepare_command(command, cwd)
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if result.returncode != 0:
            rendered = subprocess.list2cmdline(command)
            raise ToolchainError(
                f"command failed ({result.returncode}): {rendered}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def doctor(self) -> ToolchainStatus:
        try:
            tools = self._tools()
            environment = self._load_environment()
            result = subprocess.run(
                [tools["cl.exe"]],
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            identity = (result.stderr or result.stdout).splitlines()[0].strip()
            return ToolchainStatus("msvc", True, identity, tools)
        except Exception as exc:
            return ToolchainStatus("msvc", False, "unavailable", {}, (str(exc),))

    def compile_carrier(
        self,
        source: Path,
        build_dir: Path,
        declared_imports: dict[str, str],
    ) -> CarrierArtifact:
        build_dir.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        environment = self._load_environment()
        original_asm = build_dir / "carrier.original.asm"
        rewritten_asm = build_dir / "carrier.rewritten.asm"
        compiler_obj = build_dir / "carrier.compiler.obj"
        carrier_obj = build_dir / "carrier.obj"
        carrier_exe = build_dir / "carrier.exe"
        diagnostics: list[str] = []

        compile_command = [
                tools["cl.exe"],
                "/nologo",
                "/c",
                "/FAs",
                "/GS-",
                "/GR-",
                "/EHsc-",
                "/Od",
                "/Zl",
                f"/Fa{original_asm}",
                f"/Fo{compiler_obj}",
                str(source),
            ]
        compile_result = self._run(
            compile_command,
            environment,
            build_dir,
        )
        diagnostics.extend(filter(None, (compile_result.stdout.strip(), compile_result.stderr.strip())))
        if not original_asm.is_file():
            raise ToolchainError(f"cl.exe did not create {original_asm}")

        rewrite = _AssemblyRewrite(declared_imports)
        rewritten_asm.write_text(
            rewrite.rewrite(original_asm.read_text(encoding="utf-8", errors="replace")),
            encoding="utf-8",
        )

        assemble_command = [
                tools["ml64.exe"],
                "/nologo",
                "/c",
                f"/Fo{carrier_obj}",
                str(rewritten_asm),
            ]
        assemble_result = self._run(
            assemble_command,
            environment,
            build_dir,
        )
        diagnostics.extend(filter(None, (assemble_result.stdout.strip(), assemble_result.stderr.strip())))

        link_command = [
                tools["link.exe"],
                "/nologo",
                "/entry:AlignRSP",
                "/subsystem:console",
                "/machine:x64",
                "/nodefaultlib",
                "/fixed",
                "/dynamicbase:no",
                f"/out:{carrier_exe}",
                str(carrier_obj),
            ]
        link_result = self._run(
            link_command,
            environment,
            build_dir,
        )
        diagnostics.extend(filter(None, (link_result.stdout.strip(), link_result.stderr.strip())))

        carrier_pe = pefile.PE(str(carrier_exe), fast_load=False)
        text_section = next(
            (
                section
                for section in carrier_pe.sections
                if section.Name.rstrip(b"\0") == b".text"
            ),
            None,
        )
        if text_section is None:
            raise ToolchainError("linked carrier has no .text section")
        code = bytes(text_section.get_data())[: text_section.Misc_VirtualSize]
        entry_offset = carrier_pe.OPTIONAL_HEADER.AddressOfEntryPoint - text_section.VirtualAddress
        carrier_pe.close()
        if not (0 <= entry_offset < len(code)):
            raise ToolchainError("carrier entry point is outside its .text section")

        for fixup in rewrite.import_fixups:
            count = code.count(fixup.placeholder)
            if count != 1:
                raise ToolchainError(
                    f"import placeholder for {fixup.name} occurs {count} times in carrier"
                )
            fixup.code_offset = code.index(fixup.placeholder)
        data_fixups = list(rewrite.data_fixups.values())
        for fixup in data_fixups:
            for reference in fixup.references:
                count = code.count(reference.placeholder)
                if count != 1:
                    raise ToolchainError(
                        f"data placeholder for {fixup.name} occurs {count} times in carrier"
                    )
                reference.code_offset = code.index(reference.placeholder)

        status = self.doctor()
        return CarrierArtifact(
            code=code,
            entry_offset=entry_offset,
            import_fixups=rewrite.import_fixups,
            data_fixups=data_fixups,
            diagnostics=diagnostics,
            compiler_identity=status.identity,
            tool_paths=tools,
            commands=[compile_command, assemble_command, link_command],
            source_path=source,
            retained_artifacts={
                "assembly_original": original_asm,
                "assembly_rewritten": rewritten_asm,
                "compiler_object": compiler_obj,
                "carrier_object": carrier_obj,
                "linked_image": carrier_exe,
            },
        )

    def build_asm_payload(self, source: Path, output: Path, build_dir: Path) -> bytes:
        """Assemble a fixture whose public entry label is ``payload_start``."""
        build_dir.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        environment = self._load_environment()
        payload_obj = build_dir / f"{source.stem}.obj"
        payload_exe = build_dir / f"{source.stem}.exe"
        self._run(
            [
                tools["ml64.exe"],
                "/nologo",
                "/c",
                f"/Fo{payload_obj}",
                str(source.resolve()),
            ],
            environment,
            build_dir,
        )
        self._run(
            [
                tools["link.exe"],
                "/nologo",
                "/entry:payload_start",
                "/subsystem:console",
                "/machine:x64",
                "/nodefaultlib",
                "/fixed",
                "/dynamicbase:no",
                f"/out:{payload_exe}",
                str(payload_obj),
            ],
            environment,
            build_dir,
        )
        image = pefile.PE(str(payload_exe), fast_load=False)
        section = next(
            (item for item in image.sections if item.Name.rstrip(b"\0") == b".text"),
            None,
        )
        if section is None:
            raise ToolchainError(f"fixture {source.name} has no .text section")
        code = bytes(section.get_data())[: section.Misc_VirtualSize]
        entry_offset = image.OPTIONAL_HEADER.AddressOfEntryPoint - section.VirtualAddress
        if not 0 <= entry_offset < len(code):
            raise ToolchainError(f"fixture {source.name} entry point is outside .text")
        payload = code[entry_offset:]
        image.close()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
        return payload

    def build_raw_fixture(self, source: Path, output: Path, build_dir: Path) -> bytes:
        return self.build_asm_payload(source, output, build_dir)

    def build_asm_dll(
        self,
        source: Path,
        output: Path,
        build_dir: Path,
        libraries: tuple[str, ...] = ("kernel32.lib",),
        exports: tuple[str, ...] = (),
    ) -> Path:
        """Assemble a controlled x64 DLL fixture whose entry point is DllMain."""
        build_dir.mkdir(parents=True, exist_ok=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        environment = self._load_environment()
        dll_obj = build_dir / f"{source.stem}.obj"
        self._run(
            [
                tools["ml64.exe"],
                "/nologo",
                "/c",
                f"/Fo{dll_obj}",
                str(source.resolve()),
            ],
            environment,
            build_dir,
        )
        self._run(
            [
                tools["link.exe"],
                "/nologo",
                "/dll",
                "/entry:DllMain",
                "/machine:x64",
                "/nodefaultlib",
                "/dynamicbase",
                "/nxcompat",
                "/incremental:no",
                f"/out:{output.resolve()}",
                str(dll_obj),
                *libraries,
                *(f"/export:{name}" for name in exports),
            ],
            environment,
            build_dir,
        )
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

    def build_dll_fixture(
        self,
        source: Path,
        output: Path,
        build_dir: Path,
        libraries: tuple[str, ...] = (),
        exports: tuple[str, ...] = (),
    ) -> Path:
        return self.build_asm_dll(
            source,
            output,
            build_dir,
            libraries or ("kernel32.lib",),
            exports,
        )

    def build_runtime_helper(
        self, source: Path, output: Path, build_dir: Path
    ) -> Path:
        build_dir.mkdir(parents=True, exist_ok=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        environment = self._load_environment()
        self._run(
            [
                tools["cl.exe"],
                "/nologo",
                "/std:c11",
                "/O2",
                "/W4",
                "/WX",
                "/MT",
                "/DUNICODE",
                "/D_UNICODE",
                f"/Fe{output.resolve()}",
                str(source.resolve()),
                "/link",
                "/incremental:no",
                "/subsystem:console",
            ],
            environment,
            build_dir,
        )
        return output

    def build_exe_fixture(
        self, source: Path, output: Path, build_dir: Path
    ) -> Path:
        build_dir.mkdir(parents=True, exist_ok=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        tools = self._tools()
        environment = self._load_environment()
        fixture_object = build_dir / f"{source.stem}.obj"
        self._run(
            [
                tools["ml64.exe"],
                "/nologo",
                "/c",
                f"/Fo{fixture_object}",
                str(source.resolve()),
            ],
            environment,
            build_dir,
        )
        self._run(
            [
                tools["link.exe"],
                "/nologo",
                "/entry:mainCRTStartup",
                "/subsystem:console",
                "/machine:x64",
                "/nodefaultlib",
                "/dynamicbase",
                "/nxcompat",
                "/incremental:no",
                f"/out:{output.resolve()}",
                str(fixture_object),
                "kernel32.lib",
                "user32.lib",
            ],
            environment,
            build_dir,
        )
        image = pefile.PE(str(output), fast_load=False)
        try:
            if (
                image.FILE_HEADER.Machine
                != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
            ):
                raise ToolchainError(f"fixture {source.name} is not AMD64")
            if image.FILE_HEADER.Characteristics & 0x2000:
                raise ToolchainError(
                    f"fixture {source.name} unexpectedly became a DLL"
                )
            if image.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
                raise ToolchainError(f"fixture {source.name} has no entry point")
        finally:
            image.close()
        return output

