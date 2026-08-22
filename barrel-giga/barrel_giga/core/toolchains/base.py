from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..artifacts import CarrierArtifact


class ToolchainError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolchainStatus:
    name: str
    ready: bool
    identity: str
    tools: dict[str, str]
    diagnostics: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None


class Toolchain(ABC):
    name: str

    @abstractmethod
    def doctor(self) -> ToolchainStatus:
        raise NotImplementedError

    @abstractmethod
    def compile_carrier(
        self,
        source: Path,
        build_dir: Path,
        declared_imports: dict[str, str],
    ) -> CarrierArtifact:
        raise NotImplementedError

    @abstractmethod
    def build_raw_fixture(self, source: Path, output: Path, build_dir: Path) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def build_dll_fixture(
        self,
        source: Path,
        output: Path,
        build_dir: Path,
        libraries: tuple[str, ...] = (),
        exports: tuple[str, ...] = (),
    ) -> Path:
        raise NotImplementedError

    def build_runtime_helper(self, source: Path, output: Path, build_dir: Path) -> Path | None:
        return None

    def build_exe_fixture(self, source: Path, output: Path, build_dir: Path) -> Path | None:
        return None

