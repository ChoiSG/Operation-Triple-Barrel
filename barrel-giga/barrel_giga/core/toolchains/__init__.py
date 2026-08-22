from __future__ import annotations

from .base import Toolchain


def create_toolchain(name: str) -> Toolchain:
    if name == "msvc":
        from .msvc import MsvcToolchain

        return MsvcToolchain()
    if name == "mingw":
        from .mingw import MingwToolchain

        return MingwToolchain()
    raise ValueError(f"unknown toolchain {name!r}")


__all__ = ["Toolchain", "create_toolchain"]
