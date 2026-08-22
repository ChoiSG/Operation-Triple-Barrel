#!/usr/bin/env python3
"""Extract PE version info from a DLL, generate .rc, compile to .syso."""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pefile


def extract_version_info(pe_path: str) -> dict:
    pe = pefile.PE(pe_path, fast_load=False)
    info = {
        "file_version": (0, 0, 0, 0),
        "product_version": (0, 0, 0, 0),
        "file_flags_mask": 0x3F,
        "file_flags": 0,
        "file_os": 0x40004,
        "file_type": 0x2,
        "file_subtype": 0,
        "strings": {},
        "translation": (0x0409, 0x04B0),
    }

    if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
        ffi = pe.VS_FIXEDFILEINFO[0]
        info["file_version"] = (
            (ffi.FileVersionMS >> 16) & 0xFFFF,
            ffi.FileVersionMS & 0xFFFF,
            (ffi.FileVersionLS >> 16) & 0xFFFF,
            ffi.FileVersionLS & 0xFFFF,
        )
        info["product_version"] = (
            (ffi.ProductVersionMS >> 16) & 0xFFFF,
            ffi.ProductVersionMS & 0xFFFF,
            (ffi.ProductVersionLS >> 16) & 0xFFFF,
            ffi.ProductVersionLS & 0xFFFF,
        )
        info["file_flags_mask"] = ffi.FileFlagsMask
        info["file_flags"] = ffi.FileFlags
        info["file_os"] = ffi.FileOS
        info["file_type"] = ffi.FileType
        info["file_subtype"] = ffi.FileSubtype

    for group in getattr(pe, "FileInfo", None) or ():
        for item in group:
            for table in getattr(item, "StringTable", ()):
                for key, value in table.entries.items():
                    k = key.decode("utf-8", errors="replace").replace("\x00", "").strip()
                    v = value.decode("utf-8", errors="replace").replace("\x00", "").strip()
                    if k and v:
                        info["strings"][k] = v
                if hasattr(table, "name"):
                    try:
                        name = table.name
                        if isinstance(name, bytes):
                            name = name.decode("ascii", errors="ignore")
                        lang_id = int(name, 16)
                        info["translation"] = (lang_id >> 16, lang_id & 0xFFFF)
                    except (ValueError, TypeError):
                        pass
            for var in getattr(item, "Var", ()):
                if hasattr(var, "entry") and "Translation" in var.entry:
                    raw = var.entry["Translation"]
                    if isinstance(raw, bytes) and len(raw) >= 4:
                        info["translation"] = struct.unpack("<HH", raw[:4])
                    elif isinstance(raw, int):
                        info["translation"] = (raw & 0xFFFF, (raw >> 16) & 0xFFFF)

    pe.close()
    return info


def escape_rc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def generate_rc(info: dict) -> str:
    fv = info["file_version"]
    pv = info["product_version"]
    lang, cp = info["translation"]
    block_id = f"{lang:04X}{cp:04X}"

    lines = []
    lines.append('#include <winver.h>')
    lines.append("")
    lines.append("VS_VERSION_INFO VERSIONINFO")
    lines.append(f" FILEVERSION {fv[0]},{fv[1]},{fv[2]},{fv[3]}")
    lines.append(f" PRODUCTVERSION {pv[0]},{pv[1]},{pv[2]},{pv[3]}")
    lines.append(f" FILEFLAGSMASK {info['file_flags_mask']:#x}")
    lines.append(f" FILEFLAGS {info['file_flags']:#x}")
    lines.append(f" FILEOS {info['file_os']:#x}")
    lines.append(f" FILETYPE {info['file_type']:#x}")
    lines.append(f" FILESUBTYPE {info['file_subtype']:#x}")
    lines.append("BEGIN")
    lines.append('    BLOCK "StringFileInfo"')
    lines.append("    BEGIN")
    lines.append(f'        BLOCK "{block_id}"')
    lines.append("        BEGIN")
    for key, value in info["strings"].items():
        lines.append(f'            VALUE "{escape_rc(key)}", "{escape_rc(value)}"')
    lines.append("        END")
    lines.append("    END")
    lines.append('    BLOCK "VarFileInfo"')
    lines.append("    BEGIN")
    lines.append(f"        VALUE \"Translation\", {lang:#06x}, {cp:#06x}")
    lines.append("    END")
    lines.append("END")
    lines.append("")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <original-dll> <output-dir>", file=sys.stderr)
        sys.exit(1)

    original = sys.argv[1]
    out_dir = Path(sys.argv[2])
    syso_path = out_dir / "versioninfo.syso"

    info = extract_version_info(original)
    if not info["strings"]:
        print(f"[versioninfo] No version info in {original}, skipping", file=sys.stderr)
        syso_path.unlink(missing_ok=True)
        return

    rc_content = generate_rc(info)

    with tempfile.NamedTemporaryFile(suffix=".rc", mode="w", delete=False) as f:
        f.write(rc_content)
        rc_path = f.name

    try:
        subprocess.run(
            ["x86_64-w64-mingw32-windres", rc_path, "-O", "coff", "-o", str(syso_path)],
            check=True,
        )
        names = ", ".join(f"{k}={v}" for k, v in list(info["strings"].items())[:3])
        print(f"[versioninfo] {syso_path.name}: {names}...", file=sys.stderr)
    finally:
        Path(rc_path).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
