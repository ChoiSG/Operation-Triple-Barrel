from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def utc_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass
class ImportFixup:
    dll: str
    name: str
    placeholder: bytes
    kind: str = "call_iat"
    register: str | None = None
    code_offset: int | None = None
    instruction_va: int | None = None
    target_va: int | None = None
    displacement: int | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["placeholder"] = self.placeholder.hex()
        return value


@dataclass
class DataReference:
    register: str
    placeholder: bytes
    target_offset: int = 0
    code_offset: int | None = None
    instruction_va: int | None = None
    target_va: int | None = None
    displacement: int | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["placeholder"] = self.placeholder.hex()
        return value


@dataclass
class DataFixup:
    name: str
    data: bytes = b""
    target: str = "data"
    references: list[DataReference] = field(default_factory=list)
    rva: int | None = None
    file_offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "data_hex": self.data.hex(),
            "size": len(self.data),
            "target": self.target,
            "references": [reference.to_dict() for reference in self.references],
            "rva": self.rva,
            "file_offset": self.file_offset,
        }


@dataclass
class CarrierArtifact:
    code: bytes
    entry_offset: int
    import_fixups: list[ImportFixup]
    data_fixups: list[DataFixup]
    diagnostics: list[str]
    compiler_identity: str
    tool_paths: dict[str, str]
    commands: list[list[str]]
    source_path: Path
    retained_artifacts: dict[str, Path]
    toolchain_metadata: dict[str, Any] = field(default_factory=dict)
    evidence_schema: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.evidence_schema,
            "code_size": len(self.code),
            "code_sha256": sha256_bytes(self.code),
            "entry_offset": self.entry_offset,
            "import_fixups": [fixup.to_dict() for fixup in self.import_fixups],
            "data_fixups": [fixup.to_dict() for fixup in self.data_fixups],
            "diagnostics": self.diagnostics,
            "compiler_identity": self.compiler_identity,
            "tool_paths": self.tool_paths,
            "toolchain_metadata": self.toolchain_metadata,
            "commands": self.commands,
            "source_path": str(self.source_path),
            "retained_artifacts": {
                role: str(path)
                for role, path in sorted(self.retained_artifacts.items())
            },
        }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")

