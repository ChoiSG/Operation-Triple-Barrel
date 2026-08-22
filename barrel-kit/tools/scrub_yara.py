#!/usr/bin/env python3

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys


PATCHES = {
    "Windows_Trojan_Adaptix_b2cda978:$a1": (
        bytes.fromhex("48 85 C0"),
        bytes.fromhex("48 09 C0"),
    ),
    "Windows_Trojan_Adaptix_b2cda978:$a5": (
        bytes.fromhex("48 83 C0 01"),
        bytes.fromhex("48 8D 40 01"),
    ),
}


def parse_patterns(rule_path: Path) -> dict[str, list[int | None]]:
    text = rule_path.read_text(encoding="utf-8")
    patterns: dict[str, list[int | None]] = {}

    for rule_match in re.finditer(r"(?ms)^rule\s+(\w+)\s*\{(.*?)^\}", text):
        rule_name, body = rule_match.groups()
        for string_match in re.finditer(r"\$(\w+)\s*=\s*\{([^}]*)\}", body, re.S):
            string_name, expression = string_match.groups()
            tokens = expression.split()
            pattern = [None if token == "??" else int(token, 16) for token in tokens]
            patterns[f"{rule_name}:${string_name}"] = pattern

    if not patterns:
        raise ValueError(f"no hex patterns found in {rule_path}")
    return patterns


def find_matches(data: bytes | bytearray, pattern: list[int | None]) -> list[int]:
    width = len(pattern)
    return [
        offset
        for offset in range(len(data) - width + 1)
        if all(expected is None or data[offset + index] == expected
               for index, expected in enumerate(pattern))
    ]


def apply_patch(data: bytearray, offset: int, width: int,
                before: bytes, after: bytes) -> int:
    if len(before) != len(after):
        raise ValueError("replacement length must not change")

    span = bytes(data[offset:offset + width])
    relative = span.find(before)
    if relative < 0 or span.find(before, relative + 1) >= 0:
        raise ValueError(f"replacement anchor is not unique at 0x{offset:x}")

    patch_offset = offset + relative
    data[patch_offset:patch_offset + len(before)] = after
    return patch_offset


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} <rules.yar> <agent.dll>", file=sys.stderr)
        return 2

    rule_path = Path(sys.argv[1])
    dll_path = Path(sys.argv[2])
    patterns = parse_patterns(rule_path)
    data = bytearray(dll_path.read_bytes())

    if data[:2] != b"MZ":
        raise ValueError(f"not a PE file: {dll_path}")

    before_hash = hashlib.sha256(data).hexdigest()
    patched = 0

    for name, (before, after) in PATCHES.items():
        if name not in patterns:
            raise ValueError(f"expected pattern missing from rule file: {name}")

        matches = find_matches(data, patterns[name])
        for match_offset in matches:
            patch_offset = apply_patch(
                data,
                match_offset,
                len(patterns[name]),
                before,
                after,
            )
            print(f"[+] {name}: 0x{patch_offset:x} {before.hex()} -> {after.hex()}")
            patched += 1

    remaining = {
        name: matches
        for name, pattern in patterns.items()
        if (matches := find_matches(data, pattern))
    }
    if remaining:
        detail = ", ".join(
            f"{name}@{','.join(f'0x{offset:x}' for offset in offsets)}"
            for name, offsets in remaining.items()
        )
        raise ValueError(f"unhandled YARA matches remain: {detail}")

    dll_path.write_bytes(data)
    after_hash = hashlib.sha256(data).hexdigest()
    print(f"[+] scrubbed {patched} match(es)")
    print(f"[+] sha256 {before_hash} -> {after_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
