from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

import capstone
import pefile

from .fixups import rel32


class InvocationError(ValueError):
    pass


@dataclass(frozen=True)
class InvocationTarget:
    kind: str
    name: str | None
    rva: int
    function_start_rva: int
    function_end_rva: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "rva": self.rva,
            "function_start_rva": self.function_start_rva,
            "function_end_rva": self.function_end_rva,
        }


@dataclass(frozen=True)
class BackdoorSite:
    rva: int
    size: int
    original_bytes: bytes
    decoded_instruction: str
    original_target_rva: int

    def replacement(self, image_base: int, carrier_entry_rva: int) -> tuple[bytes, int]:
        displacement = rel32(
            image_base + self.rva,
            self.size,
            image_base + carrier_entry_rva,
        )
        return b"\xE9" + struct.pack("<i", displacement), displacement

    def to_dict(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "size": self.size,
            "original_bytes": self.original_bytes.hex(),
            "decoded_instruction": self.decoded_instruction,
            "original_target_rva": self.original_target_rva,
        }


def _function_bounds(image: pefile.PE, rva: int) -> tuple[int, int]:
    matches = [
        entry
        for entry in getattr(image, "DIRECTORY_ENTRY_EXCEPTION", [])
        if int(entry.struct.BeginAddress) <= rva < int(entry.struct.EndAddress)
    ]
    if len(matches) != 1:
        raise InvocationError(
            f"target RVA 0x{rva:X} does not resolve to one unambiguous "
            "AMD64 runtime function"
        )
    start = int(matches[0].struct.BeginAddress)
    end = int(matches[0].struct.EndAddress)
    if start >= end:
        raise InvocationError(
            f"target RVA 0x{rva:X} has malformed runtime-function bounds"
        )
    return start, end


def resolve_invocation_target(
    image: pefile.PE,
    target_kind: str,
    export_name: str | None = None,
    *,
    require_function_bounds: bool = True,
) -> InvocationTarget:
    if target_kind in {"entrypoint", "dllmain"}:
        rva = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
        if rva == 0:
            raise InvocationError(f"{target_kind} target is missing")
        name = None
    elif target_kind == "export":
        if export_name is None or not export_name.strip():
            raise InvocationError("named-export invocation requires dll_export")
        directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
        if directory is None:
            raise InvocationError("DLL has no export directory")
        wanted = export_name.casefold()
        matches = [
            symbol
            for symbol in directory.symbols
            if symbol.name
            and symbol.name.decode("ascii", errors="strict").casefold() == wanted
        ]
        if len(matches) != 1:
            raise InvocationError(
                f"named export {export_name!r} resolved {len(matches)} times"
            )
        rva = int(matches[0].address)
        export_directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]
        ]
        if int(export_directory.VirtualAddress) <= rva < (
            int(export_directory.VirtualAddress) + int(export_directory.Size)
        ):
            raise InvocationError(f"named export {export_name!r} is forwarded")
        name = export_name
    else:
        raise InvocationError(f"unsupported invocation target {target_kind!r}")

    matching_sections = [
        section
        for section in image.sections
        if int(section.VirtualAddress)
        <= rva
        < int(section.VirtualAddress)
        + min(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        and int(section.Characteristics)
        & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
    ]
    if len(matching_sections) != 1:
        raise InvocationError(
            f"{target_kind} target RVA 0x{rva:X} is not in one mapped "
            "executable section"
        )
    if require_function_bounds:
        start, end = _function_bounds(image, rva)
    else:
        start, end = rva, rva + 1
    return InvocationTarget(target_kind, name, rva, start, end)


def find_backdoor_site(
    image: pefile.PE,
    target: InvocationTarget,
) -> BackdoorSite:
    size = target.function_end_rva - target.function_start_rva
    try:
        offset = int(image.get_offset_from_rva(target.function_start_rva))
    except (TypeError, ValueError, pefile.PEFormatError) as exc:
        raise InvocationError("target function has no mapped file range") from exc
    code = bytes(image.__data__[offset : offset + size])
    if len(code) != size:
        raise InvocationError("target function bytes are truncated")

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(
        decoder.disasm(
            code,
            int(image.OPTIONAL_HEADER.ImageBase) + target.function_start_rva,
        )
    )
    if not instructions:
        raise InvocationError("target function did not decode")
    if sum(item.size for item in instructions) != len(code):
        raise InvocationError("target function has undecoded or ambiguous bytes")

    image_base = int(image.OPTIONAL_HEADER.ImageBase)
    candidates: list[BackdoorSite] = []
    for instruction in instructions:
        if (
            instruction.size != 5
            or bytes(instruction.bytes[:1]) not in {b"\xE8", b"\xE9"}
            or not instruction.operands
            or instruction.operands[0].type != capstone.x86.X86_OP_IMM
        ):
            continue
        rva = int(instruction.address) - image_base
        original_target = int(instruction.operands[0].imm) - image_base
        candidates.append(
            BackdoorSite(
                rva=rva,
                size=instruction.size,
                original_bytes=bytes(instruction.bytes),
                decoded_instruction=f"{instruction.mnemonic} {instruction.op_str}",
                original_target_rva=original_target,
            )
        )
    if not candidates:
        raise InvocationError(
            "target function has no supported five-byte direct branch"
        )
    return min(candidates, key=lambda item: item.rva)

