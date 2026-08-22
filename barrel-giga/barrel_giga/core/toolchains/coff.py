from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import ToolchainError


IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000

IMAGE_REL_AMD64_ADDR64 = 0x0001
IMAGE_REL_AMD64_ADDR32 = 0x0002
IMAGE_REL_AMD64_ADDR32NB = 0x0003
IMAGE_REL_AMD64_REL32 = 0x0004
IMAGE_REL_AMD64_REL32_1 = 0x0005
IMAGE_REL_AMD64_REL32_2 = 0x0006
IMAGE_REL_AMD64_REL32_3 = 0x0007
IMAGE_REL_AMD64_REL32_4 = 0x0008
IMAGE_REL_AMD64_REL32_5 = 0x0009
IMAGE_REL_AMD64_SECTION = 0x000A
IMAGE_REL_AMD64_SECREL = 0x000B

REL32_TYPES = {
    IMAGE_REL_AMD64_REL32,
    IMAGE_REL_AMD64_REL32_1,
    IMAGE_REL_AMD64_REL32_2,
    IMAGE_REL_AMD64_REL32_3,
    IMAGE_REL_AMD64_REL32_4,
    IMAGE_REL_AMD64_REL32_5,
}


@dataclass(frozen=True)
class CoffRelocation:
    virtual_address: int
    symbol_index: int
    type: int


@dataclass(frozen=True)
class CoffSection:
    index: int
    name: str
    data: bytes
    characteristics: int
    relocations: tuple[CoffRelocation, ...]


@dataclass(frozen=True)
class CoffSymbol:
    index: int
    name: str
    value: int
    section_number: int
    type: int
    storage_class: int
    auxiliary_count: int


class CoffFile:
    def __init__(
        self,
        path: Path,
        sections: tuple[CoffSection, ...],
        symbols: tuple[CoffSymbol | None, ...],
    ) -> None:
        self.path = path
        self.sections = sections
        self.symbols = symbols

    @staticmethod
    def _bounded(data: bytes, offset: int, size: int, label: str) -> bytes:
        if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
            raise ToolchainError(f"COFF {label} is outside the file")
        return data[offset : offset + size]

    @staticmethod
    def _string(data: bytes, string_offset: int, offset: int, label: str) -> str:
        if offset < 4:
            raise ToolchainError(f"COFF {label} has invalid string-table offset {offset}")
        string_size = struct.unpack_from("<I", data, string_offset)[0]
        if offset >= string_size:
            raise ToolchainError(f"COFF {label} is outside the string table")
        start = string_offset + offset
        end = data.find(b"\0", start, string_offset + string_size)
        if end < 0:
            raise ToolchainError(f"COFF {label} string is not terminated")
        try:
            return data[start:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ToolchainError(f"COFF {label} is not UTF-8") from exc

    @classmethod
    def parse(cls, path: Path) -> "CoffFile":
        data = path.read_bytes()
        if len(data) < 20:
            raise ToolchainError("COFF file is shorter than its header")
        (
            machine,
            section_count,
            _timestamp,
            symbol_offset,
            symbol_count,
            optional_size,
            _characteristics,
        ) = struct.unpack_from("<HHIIIHH", data, 0)
        if machine != IMAGE_FILE_MACHINE_AMD64:
            raise ToolchainError(f"COFF machine 0x{machine:04X} is not AMD64")
        if section_count == 0:
            raise ToolchainError("COFF object has no sections")
        if optional_size != 0:
            raise ToolchainError("COFF carrier object unexpectedly has an optional header")
        section_table_offset = 20
        cls._bounded(data, section_table_offset, section_count * 40, "section table")
        symbol_size = symbol_count * 18
        cls._bounded(data, symbol_offset, symbol_size, "symbol table")
        string_offset = symbol_offset + symbol_size
        string_header = cls._bounded(data, string_offset, 4, "string table header")
        string_size = struct.unpack_from("<I", string_header)[0]
        if string_size < 4:
            raise ToolchainError("COFF string table is malformed")
        cls._bounded(data, string_offset, string_size, "string table")

        raw_sections: list[tuple[int, bytes, int, int, int, int]] = []
        for number in range(section_count):
            offset = section_table_offset + number * 40
            name_raw = data[offset : offset + 8]
            (
                _physical_address,
                _virtual_address,
                raw_size,
                raw_offset,
                relocation_offset,
                _line_offset,
                relocation_count,
                _line_count,
                characteristics,
            ) = struct.unpack_from("<IIIIIIHHI", data, offset + 8)
            if name_raw.startswith(b"/"):
                try:
                    name_index = int(name_raw[1:].split(b"\0", 1)[0])
                except ValueError as exc:
                    raise ToolchainError("COFF section has an invalid long name") from exc
                name = cls._string(data, string_offset, name_index, "section name")
            else:
                name = name_raw.rstrip(b"\0").decode("ascii", errors="strict")
            if characteristics & IMAGE_SCN_LNK_NRELOC_OVFL:
                raise ToolchainError(f"COFF section {name} uses relocation overflow")
            section_data = cls._bounded(data, raw_offset, raw_size, f"section {name} data")
            cls._bounded(
                data,
                relocation_offset,
                relocation_count * 10,
                f"section {name} relocations",
            )
            raw_sections.append(
                (
                    number + 1,
                    section_data,
                    characteristics,
                    relocation_offset,
                    relocation_count,
                    raw_size,
                )
            )

        symbols: list[CoffSymbol | None] = [None] * symbol_count
        index = 0
        while index < symbol_count:
            offset = symbol_offset + index * 18
            name_raw = data[offset : offset + 8]
            if name_raw[:4] == b"\0\0\0\0":
                name_index = struct.unpack_from("<I", name_raw, 4)[0]
                name = cls._string(data, string_offset, name_index, "symbol name")
            else:
                name = name_raw.rstrip(b"\0").decode("ascii", errors="strict")
            value, section_number, symbol_type, storage_class, auxiliary_count = (
                struct.unpack_from("<IhHBB", data, offset + 8)
            )
            if index + auxiliary_count >= symbol_count:
                raise ToolchainError(f"COFF symbol {name} has out-of-range auxiliary records")
            symbols[index] = CoffSymbol(
                index=index,
                name=name,
                value=value,
                section_number=section_number,
                type=symbol_type,
                storage_class=storage_class,
                auxiliary_count=auxiliary_count,
            )
            index += 1 + auxiliary_count

        sections: list[CoffSection] = []
        for section_number, section_data, characteristics, relocation_offset, relocation_count, _ in raw_sections:
            relocations: list[CoffRelocation] = []
            for relocation_index in range(relocation_count):
                offset = relocation_offset + relocation_index * 10
                virtual_address, symbol_index, relocation_type = struct.unpack_from(
                    "<IIH", data, offset
                )
                if symbol_index >= symbol_count or symbols[symbol_index] is None:
                    raise ToolchainError(
                        f"COFF relocation references invalid symbol index {symbol_index}"
                    )
                if virtual_address > len(section_data):
                    raise ToolchainError("COFF relocation address is outside its section")
                relocations.append(
                    CoffRelocation(virtual_address, symbol_index, relocation_type)
                )
            section_name_offset = section_table_offset + (section_number - 1) * 40
            name_raw = data[section_name_offset : section_name_offset + 8]
            if name_raw.startswith(b"/"):
                name = cls._string(
                    data,
                    string_offset,
                    int(name_raw[1:].split(b"\0", 1)[0]),
                    "section name",
                )
            else:
                name = name_raw.rstrip(b"\0").decode("ascii", errors="strict")
            sections.append(
                CoffSection(
                    index=section_number,
                    name=name,
                    data=section_data,
                    characteristics=characteristics,
                    relocations=tuple(relocations),
                )
            )
        return cls(path, tuple(sections), tuple(symbols))

    def symbol(self, index: int) -> CoffSymbol:
        value = self.symbols[index]
        if value is None:
            raise ToolchainError(f"COFF symbol index {index} is auxiliary")
        return value

    def section(self, number: int) -> CoffSection:
        if number <= 0 or number > len(self.sections):
            raise ToolchainError(f"COFF section number {number} is invalid")
        return self.sections[number - 1]

    def named_symbols(self, name: str) -> list[CoffSymbol]:
        return [
            symbol
            for symbol in self.symbols
            if symbol is not None and symbol.name == name
        ]

    def evidence(self) -> dict[str, Any]:
        return {
            "format": "pe-coff-amd64-object",
            "path": str(self.path),
            "sections": [
                {
                    "index": section.index,
                    "name": section.name,
                    "size": len(section.data),
                    "characteristics": f"0x{section.characteristics:08X}",
                    "relocations": [
                        {
                            "offset": relocation.virtual_address,
                            "type": f"0x{relocation.type:04X}",
                            "symbol_index": relocation.symbol_index,
                            "symbol": self.symbol(relocation.symbol_index).name,
                        }
                        for relocation in section.relocations
                    ],
                }
                for section in self.sections
            ],
            "symbols": [
                {
                    "index": symbol.index,
                    "name": symbol.name,
                    "value": symbol.value,
                    "section_number": symbol.section_number,
                    "type": f"0x{symbol.type:04X}",
                    "storage_class": symbol.storage_class,
                    "auxiliary_count": symbol.auxiliary_count,
                }
                for symbol in self.symbols
                if symbol is not None
            ],
        }

