from __future__ import annotations

import struct


class FixupError(ValueError):
    pass


_REGISTERS = {
    "rax": 0,
    "rcx": 1,
    "rdx": 2,
    "rbx": 3,
    "rsp": 4,
    "rbp": 5,
    "rsi": 6,
    "rdi": 7,
    "r8": 8,
    "r9": 9,
    "r10": 10,
    "r11": 11,
    "r12": 12,
    "r13": 13,
    "r14": 14,
    "r15": 15,
}


def rel32(instruction_va: int, instruction_size: int, target_va: int) -> int:
    displacement = target_va - (instruction_va + instruction_size)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise FixupError(
            f"target 0x{target_va:X} is outside rel32 range from 0x{instruction_va:X}"
        )
    return displacement


def encode_iat_reference(
    kind: str,
    instruction_va: int,
    target_va: int,
    register: str | None = None,
) -> tuple[bytes, int]:
    instruction_size = 7 if kind == "load_iat" else 6
    displacement = rel32(instruction_va, instruction_size, target_va)
    if kind == "call_iat":
        opcode = b"\xFF\x15"
    elif kind == "jump_iat":
        opcode = b"\xFF\x25"
    elif kind == "load_iat":
        if register is None:
            raise FixupError("load_iat requires a destination register")
        try:
            number = _REGISTERS[register.lower()]
        except KeyError as exc:
            raise FixupError(f"unsupported IAT load destination register {register}") from exc
        rex = 0x48 | (0x04 if number >= 8 else 0)
        modrm = ((number & 7) << 3) | 0x05
        return bytes((rex, 0x8B, modrm)) + struct.pack("<i", displacement), displacement
    else:
        raise FixupError(f"unsupported IAT fixup kind {kind}")
    return opcode + struct.pack("<i", displacement), displacement


def encode_rip_lea(
    register: str, instruction_va: int, target_va: int
) -> tuple[bytes, int]:
    try:
        number = _REGISTERS[register.lower()]
    except KeyError as exc:
        raise FixupError(f"unsupported LEA destination register {register}") from exc
    displacement = rel32(instruction_va, 7, target_va)
    rex = 0x48 | (0x04 if number >= 8 else 0)
    modrm = ((number & 7) << 3) | 0x05
    return bytes((rex, 0x8D, modrm)) + struct.pack("<i", displacement), displacement

