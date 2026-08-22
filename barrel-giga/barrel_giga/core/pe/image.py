from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pefile


class PEValidationError(ValueError):
    pass


IMAGE_DLLCHARACTERISTICS_GUARD_CF = pefile.DLL_CHARACTERISTICS[
    "IMAGE_DLLCHARACTERISTICS_GUARD_CF"
]


@dataclass(frozen=True)
class SectionInfo:
    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def mapped_file_size(self) -> int:
        return min(self.virtual_size, self.raw_size)


class PEImage:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.original_bytes = self.path.read_bytes()
        self.pe = pefile.PE(data=self.original_bytes, fast_load=False)
        self.pe.parse_data_directories()

    @property
    def host_kind(self) -> str:
        return "dll" if self.pe.FILE_HEADER.Characteristics & 0x2000 else "exe"

    def validate_host(self, expected_kind: str) -> None:
        if expected_kind not in {"exe", "dll"}:
            raise PEValidationError(f"unsupported host kind {expected_kind!r}")
        if self.pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            raise PEValidationError("host must be AMD64")
        if self.pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise PEValidationError("host must be PE32+")
        if self.host_kind != expected_kind:
            raise PEValidationError(
                f"host is {self.host_kind.upper()}, but recipe requires {expected_kind.upper()}"
            )
        if self.path.suffix.lower() != f".{expected_kind}":
            raise PEValidationError(
                f"{expected_kind.upper()} host must use a .{expected_kind} extension"
            )
        section = self.code_section()
        if not section.characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
            raise PEValidationError("entry-point section is not executable")
        if section.mapped_file_size <= 0:
            raise PEValidationError("executable section has no mapped raw capacity")

    def validate_phase1_host(self) -> None:
        self.validate_host("exe")

    @property
    def image_base(self) -> int:
        return int(self.pe.OPTIONAL_HEADER.ImageBase)

    @property
    def entrypoint_rva(self) -> int:
        return int(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def code_section(self) -> SectionInfo:
        entrypoint = self.entrypoint_rva
        for section in self.pe.sections:
            span = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if (
                section.Characteristics
                & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
                and section.VirtualAddress <= entrypoint < section.VirtualAddress + span
            ):
                return SectionInfo(
                    name=section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                    rva=int(section.VirtualAddress),
                    virtual_size=int(section.Misc_VirtualSize),
                    raw_offset=int(section.PointerToRawData),
                    raw_size=int(section.SizeOfRawData),
                    characteristics=int(section.Characteristics),
                )
        raise PEValidationError("could not locate executable entry-point section")

    def rva_to_offset(self, rva: int) -> int:
        offset = self.pe.get_offset_from_rva(rva)
        if offset is None:
            raise PEValidationError(f"RVA 0x{rva:X} has no file offset")
        return int(offset)

    def iat_va(self, dll: str, name: str) -> int | None:
        wanted_dll = dll.lower()
        wanted_name = name.lower()
        matches: list[int] = []
        for descriptor in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            descriptor_name = descriptor.dll.decode("ascii", errors="replace").lower()
            if descriptor_name != wanted_dll:
                continue
            for item in descriptor.imports:
                if item.name and item.name.decode("ascii", errors="replace").lower() == wanted_name:
                    matches.append(int(item.address))
        if len(matches) > 1:
            raise PEValidationError(f"ambiguous IAT entry {dll}!{name}")
        return matches[0] if matches else None

    def repair_import_name(
        self,
        dll: str,
        name: str,
        protected_names: set[str] | None = None,
    ) -> dict[str, int | str]:
        if self.iat_va(dll, name) is not None:
            raise PEValidationError(f"IAT entry already exists: {dll}!{name}")

        wanted_dll = dll.lower()
        wanted_name = name.lower()
        protected = {item.lower() for item in (protected_names or set())}
        candidates: list[tuple[int, str, int, int]] = []
        for descriptor in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            descriptor_name = descriptor.dll.decode(
                "ascii", errors="replace"
            ).lower()
            if descriptor_name != wanted_dll:
                continue
            for item in descriptor.imports:
                if not item.name:
                    continue
                old_name = item.name.decode("ascii", errors="strict")
                if old_name.lower() in protected or old_name.lower() == wanted_name:
                    continue
                if len(old_name) >= len(name):
                    candidates.append(
                        (len(old_name), old_name.lower(), int(item.name_offset), int(item.address))
                    )

        if not candidates:
            raise PEValidationError(
                f"no compatible {dll} import-name slot can be repaired for {name}"
            )

        _, _, name_offset, iat_va = sorted(candidates)[0]
        old_item = next(
            item
            for descriptor in self.pe.DIRECTORY_ENTRY_IMPORT
            if descriptor.dll.decode("ascii", errors="replace").lower() == wanted_dll
            for item in descriptor.imports
            if item.name and int(item.name_offset) == name_offset
        )
        old_name = old_item.name.decode("ascii", errors="strict")
        replacement = name.encode("ascii") + b"\0" * (len(old_name) - len(name))
        self.pe.set_bytes_at_offset(name_offset, replacement)

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            delattr(self.pe, "DIRECTORY_ENTRY_IMPORT")
        self.pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        if self.iat_va(dll, name) != iat_va:
            raise PEValidationError(f"repaired IAT entry failed verification: {dll}!{name}")

        return {
            "dll": dll,
            "old_name": old_name,
            "new_name": name,
            "name_offset": name_offset,
            "iat_va": iat_va,
        }

    def write_rva(self, rva: int, data: bytes) -> None:
        offset = self.rva_to_offset(rva)
        self.pe.set_bytes_at_offset(offset, data)

    def clear_invalid_signature(self) -> dict[str, int]:
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        previous = {
            "file_offset": int(directory.VirtualAddress),
            "size": int(directory.Size),
        }
        directory.VirtualAddress = 0
        directory.Size = 0
        return previous

    def disable_control_flow_guard(self) -> dict[str, int | bool | None]:
        before = int(self.pe.OPTIONAL_HEADER.DllCharacteristics)
        load_config = getattr(self.pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
        guard_flags = (
            int(load_config.struct.GuardFlags)
            if load_config is not None
            and hasattr(load_config.struct, "GuardFlags")
            else None
        )
        after = before & ~IMAGE_DLLCHARACTERISTICS_GUARD_CF
        self.pe.OPTIONAL_HEADER.DllCharacteristics = after
        return {
            "guard_cf_was_enabled": bool(
                before & IMAGE_DLLCHARACTERISTICS_GUARD_CF
            ),
            "guard_cf_disabled": before != after,
            "dll_characteristics_before": before,
            "dll_characteristics_after": after,
            "load_config_guard_flags": guard_flags,
        }

    def set_entrypoint(self, rva: int) -> None:
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = rva

    def write(self, output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        self.pe.OPTIONAL_HEADER.CheckSum = 0
        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()
        self.pe.write(str(output))


def ensure_payload_fits_code_section(
    host: Path,
    payload_size: int,
    host_kind: str = "exe",
) -> SectionInfo:
    if payload_size < 0:
        raise PEValidationError("payload size cannot be negative")
    image = PEImage(host)
    image.validate_host(host_kind)
    section = image.code_section()
    if payload_size > section.mapped_file_size:
        raise PEValidationError(
            f"payload is {payload_size:,} bytes, but {host.name} has only "
            f"{section.mapped_file_size:,} mapped bytes in its executable "
            f"{section.name} section"
        )
    return section

