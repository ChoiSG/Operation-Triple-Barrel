from __future__ import annotations

import os
import sys
from dataclasses import dataclass


PROFILE_NAMES = ("auto", "windows", "linux")
TOOLCHAIN_NAMES = ("auto", "msvc", "mingw")


@dataclass(frozen=True)
class ExecutionProfile:
    name: str
    default_toolchain: str
    signing_required: bool = False


def _default_toolchain(profile_name: str, fallback: str) -> str:
    selected = os.environ.get("BARREL_GIGA_DEFAULT_TOOLCHAIN", fallback)
    if selected not in {"msvc", "mingw"}:
        raise ValueError(
            "BARREL_GIGA_DEFAULT_TOOLCHAIN must be msvc or mingw"
        )
    if profile_name == "windows" and selected != "msvc":
        raise ValueError("the Windows profile requires MSVC")
    if profile_name == "linux" and selected != "mingw":
        raise ValueError("the Linux profile requires MinGW")
    return selected


def resolve_profile(name: str = "auto") -> ExecutionProfile:
    if name not in PROFILE_NAMES:
        raise ValueError(f"unknown execution profile {name!r}")
    selected = os.environ.get("BARREL_GIGA_PROFILE", name) if name == "auto" else name
    if selected == "auto":
        selected = "windows" if sys.platform == "win32" else "linux"
    if selected == "windows":
        return ExecutionProfile(
            name="windows",
            default_toolchain=_default_toolchain("windows", "msvc"),
        )
    if selected == "linux":
        return ExecutionProfile(
            name="linux",
            default_toolchain=_default_toolchain("linux", "mingw"),
        )
    raise ValueError(f"unknown execution profile {selected!r}")


def resolve_toolchain_name(name: str, profile: ExecutionProfile) -> str:
    if name == "auto":
        return profile.default_toolchain
    if name not in TOOLCHAIN_NAMES:
        raise ValueError(f"unknown toolchain {name!r}")
    if profile.name == "windows" and name != "msvc":
        raise ValueError("the Windows profile requires MSVC")
    if profile.name == "linux" and name != "mingw":
        raise ValueError("the Linux profile requires MinGW")
    return name
