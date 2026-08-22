from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile

import pefile


MANIFEST_SCHEMA = 1
AMD64 = 0x8664
PE32_PLUS = 0x20B
IMAGE_FILE_DLL = 0x2000
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")


class InjectableError(RuntimeError):
    pass


@dataclass(frozen=True)
class InjectableSpec:
    name: str
    release: str
    url: str
    homepage: str
    archive_size: int
    archive_sha256: str
    member: str
    executable_size: int
    executable_sha256: str


@dataclass(frozen=True)
class PeFacts:
    machine: int
    entrypoint_rva: int
    image_size: int


@dataclass(frozen=True)
class InjectableStatus:
    name: str
    path: Path
    status: str
    reason: str | None = None
    size: int | None = None
    sha256: str | None = None
    pe: PeFacts | None = None


@dataclass(frozen=True)
class InstallResult:
    action: str
    injectable: InjectableStatus


Downloader = Callable[[str, Path], None]
PeInspector = Callable[[Path], PeFacts]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def _object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InjectableError(f"{field} must be an object")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InjectableError(f"{field} must be a non-empty string")
    return value.strip()


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InjectableError(f"{field} must be a positive integer")
    return value


def _hash(value: object, field: str) -> str:
    text = _string(value, field)
    if not _SHA256.fullmatch(text):
        raise InjectableError(f"{field} must contain 64 hexadecimal digits")
    return text.upper()


def _https_url(value: object, field: str) -> str:
    text = _string(value, field)
    parsed = urlsplit(text)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise InjectableError(f"{field} must be an HTTPS URL")
    return text


def _member(value: object, field: str) -> str:
    text = _string(value, field)
    member = PurePosixPath(text.replace("\\", "/"))
    if member.is_absolute() or not member.parts or any(
        part in {"", ".", ".."} for part in member.parts
    ):
        raise InjectableError(f"{field} must be a safe relative archive member")
    return member.as_posix()


def _known_fields(value: dict[str, object], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise InjectableError(f"unknown {field} fields: {', '.join(unknown)}")


def load_spec(path: Path) -> InjectableSpec:
    path = path.resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InjectableError(f"cannot read injectable manifest {path}: {exc}") from exc

    root = _object(value, "manifest")
    _known_fields(
        root,
        {"schema", "name", "release", "url", "homepage", "archive", "executable"},
        "manifest",
    )
    if root.get("schema") != MANIFEST_SCHEMA:
        raise InjectableError(f"manifest schema must be {MANIFEST_SCHEMA}")

    name = _string(root.get("name"), "name")
    if Path(name).name != name or not name.lower().endswith(".exe"):
        raise InjectableError("name must be a flat .exe filename")

    archive = _object(root.get("archive"), "archive")
    executable = _object(root.get("executable"), "executable")
    _known_fields(archive, {"size", "sha256", "member"}, "archive")
    _known_fields(executable, {"size", "sha256"}, "executable")

    return InjectableSpec(
        name=name,
        release=_string(root.get("release"), "release"),
        url=_https_url(root.get("url"), "url"),
        homepage=_https_url(root.get("homepage"), "homepage"),
        archive_size=_positive_int(archive.get("size"), "archive.size"),
        archive_sha256=_hash(archive.get("sha256"), "archive.sha256"),
        member=_member(archive.get("member"), "archive.member"),
        executable_size=_positive_int(executable.get("size"), "executable.size"),
        executable_sha256=_hash(executable.get("sha256"), "executable.sha256"),
    )


def inspect_pe(path: Path) -> PeFacts:
    try:
        image = pefile.PE(str(path), fast_load=True)
    except (OSError, pefile.PEFormatError) as exc:
        raise InjectableError(f"invalid PE: {exc}") from exc
    try:
        if image.FILE_HEADER.Machine != AMD64:
            raise InjectableError(
                f"PE machine is 0x{image.FILE_HEADER.Machine:04X}, expected AMD64"
            )
        if image.OPTIONAL_HEADER.Magic != PE32_PLUS:
            raise InjectableError("PE is not PE32+")
        if image.FILE_HEADER.Characteristics & IMAGE_FILE_DLL:
            raise InjectableError("PE is a DLL, expected an EXE")
        if image.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
            raise InjectableError("PE has no entry point")
        return PeFacts(
            machine=image.FILE_HEADER.Machine,
            entrypoint_rva=image.OPTIONAL_HEADER.AddressOfEntryPoint,
            image_size=image.OPTIONAL_HEADER.SizeOfImage,
        )
    finally:
        image.close()


def _identity_error(path: Path, size: int, expected_hash: str) -> str | None:
    if not path.is_file():
        return "file is missing"
    actual_size = path.stat().st_size
    if actual_size != size:
        return f"size is {actual_size:,}, expected {size:,}"
    actual_hash = sha256_file(path)
    if actual_hash != expected_hash:
        return f"SHA-256 is {actual_hash}, expected {expected_hash}"
    return None


def inspect_path(
    spec: InjectableSpec,
    path: Path,
    *,
    pe_inspector: PeInspector = inspect_pe,
) -> InjectableStatus:
    target = path.resolve()
    identity_error = _identity_error(
        target, spec.executable_size, spec.executable_sha256
    )
    if identity_error is not None:
        status = "missing" if not target.exists() else "invalid"
        return InjectableStatus(
            name=spec.name,
            path=target,
            status=status,
            reason=identity_error,
        )
    try:
        pe = pe_inspector(target)
    except InjectableError as exc:
        return InjectableStatus(
            name=spec.name,
            path=target,
            status="invalid",
            reason=str(exc),
            size=spec.executable_size,
            sha256=spec.executable_sha256,
        )
    return InjectableStatus(
        name=spec.name,
        path=target,
        status="ready",
        size=spec.executable_size,
        sha256=spec.executable_sha256,
        pe=pe,
    )


def inspect_injectable(
    spec: InjectableSpec,
    directory: Path,
    *,
    pe_inspector: PeInspector = inspect_pe,
) -> InjectableStatus:
    return inspect_path(
        spec,
        directory.resolve() / spec.name,
        pe_inspector=pe_inspector,
    )


def _download(url: str, destination: Path) -> None:
    request = Request(url, headers={"User-Agent": "Barrel-Giga prep/1"})
    with urlopen(request, timeout=60) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output, length=1024 * 1024)


def _extract(spec: InjectableSpec, archive_path: Path, destination: Path) -> None:
    try:
        with ZipFile(archive_path) as archive:
            matches = [
                item
                for item in archive.infolist()
                if item.filename.replace("\\", "/") == spec.member
            ]
            if len(matches) != 1 or matches[0].is_dir():
                raise InjectableError(
                    f"archive must contain exactly one {spec.member!r} file"
                )
            if matches[0].file_size != spec.executable_size:
                raise InjectableError(
                    f"archive member size is {matches[0].file_size:,}, "
                    f"expected {spec.executable_size:,}"
                )
            with archive.open(matches[0]) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    except InjectableError:
        raise
    except (BadZipFile, OSError) as exc:
        raise InjectableError(f"cannot extract {spec.member!r}: {exc}") from exc


def install_injectable(
    spec: InjectableSpec,
    directory: Path,
    *,
    downloader: Downloader = _download,
    pe_inspector: PeInspector = inspect_pe,
) -> InstallResult:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / spec.name

    existing = inspect_injectable(spec, directory, pe_inspector=pe_inspector)
    if existing.status == "ready":
        return InstallResult(action="cached", injectable=existing)
    if target.exists():
        raise InjectableError(
            f"refusing to replace {target}: {existing.reason}; move or remove it first"
        )

    staged_handle = tempfile.NamedTemporaryFile(
        prefix=f".{Path(spec.name).stem}.",
        suffix=".staged",
        dir=directory,
        delete=False,
    )
    executable_path = Path(staged_handle.name)
    staged_handle.close()
    try:
        with tempfile.TemporaryDirectory(
            prefix=f".{Path(spec.name).stem}.", dir=directory
        ) as temporary:
            staging = Path(temporary)
            archive_path = staging / "source.zip"
            downloader(spec.url, archive_path)
            archive_error = _identity_error(
                archive_path, spec.archive_size, spec.archive_sha256
            )
            if archive_error is not None:
                raise InjectableError(f"downloaded archive failed verification: {archive_error}")
            _extract(spec, archive_path, executable_path)
            executable_error = _identity_error(
                executable_path,
                spec.executable_size,
                spec.executable_sha256,
            )
            if executable_error is not None:
                raise InjectableError(
                    f"extracted executable failed verification: {executable_error}"
                )
            pe_inspector(executable_path)
            os.replace(executable_path, target)
    except InjectableError:
        raise
    except Exception as exc:
        raise InjectableError(f"cannot prepare {spec.name}: {exc}") from exc
    finally:
        executable_path.unlink(missing_ok=True)

    installed = inspect_injectable(spec, directory, pe_inspector=pe_inspector)
    if installed.status != "ready":
        raise InjectableError(
            f"installed {spec.name} failed final verification: {installed.reason}"
        )
    return InstallResult(action="installed", injectable=installed)
