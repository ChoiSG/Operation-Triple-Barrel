from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile


OSSLSIGNCODE_VERSION = "2.14"
DEFAULT_DIRECTORY = (
    Path(__file__).resolve().parents[1]
    / "bin"
    / "tools"
    / f"osslsigncode-{OSSLSIGNCODE_VERSION}"
)


class OsslSignCodeError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManagedFile:
    member: str
    size: int
    sha256: str


@dataclass(frozen=True)
class WindowsArchive:
    url: str
    size: int
    sha256: str
    files: tuple[ManagedFile, ...]


@dataclass(frozen=True)
class OsslSignCodeInstall:
    action: str
    path: Path
    version: str | None


WINDOWS_ARCHIVE = WindowsArchive(
    url=(
        "https://github.com/mtrojnar/osslsigncode/releases/download/2.14/"
        "osslsigncode-2.14-windows-x64-mingw.zip"
    ),
    size=2_259_975,
    sha256="9A1722AAF62A27852C4EB9C35749A0248065052D0AE0A93D4ED6BB49DEF027F2",
    files=(
        ManagedFile(
            "bin/osslsigncode.exe",
            324_954,
            "BC4BDEAC3EDC01983FA5DE241584C8D5630521DE1848D854028E025D78E8D00A",
        ),
        ManagedFile(
            "bin/libcrypto-3-x64.dll",
            4_520_960,
            "B860CB15E2CF8FD102CDF5247F2CC513AD07DB157AEDF0ADDD38F7B4893D1C75",
        ),
        ManagedFile(
            "bin/libssl-3-x64.dll",
            551_424,
            "10FE3F317FD4D9107152D2805D4F7ABF67296F685F392D0C23EC43F398A0FAF2",
        ),
        ManagedFile(
            "bin/zlib1.dll",
            90_112,
            "09F2CD41E3F5BB18FE5F3F9D5F580560D45D498CC2EEAFBF453C52CBDB9D2D29",
        ),
    ),
)


Downloader = Callable[[str, Path], None]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def _download(url: str, destination: Path) -> None:
    request = Request(url, headers={"User-Agent": "Barrel-Giga prep/1"})
    with urlopen(request, timeout=60) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output, length=1024 * 1024)


def _file_error(path: Path, expected: ManagedFile) -> str | None:
    if not path.is_file():
        return f"{expected.member} is missing"
    if path.stat().st_size != expected.size:
        return f"{expected.member} has the wrong size"
    if _sha256_file(path) != expected.sha256:
        return f"{expected.member} has the wrong SHA-256"
    return None


def managed_osslsigncode_path(
    directory: Path = DEFAULT_DIRECTORY,
    *,
    spec: WindowsArchive = WINDOWS_ARCHIVE,
    platform_name: str | None = None,
) -> Path | None:
    if (platform_name or os.name) != "nt":
        return None
    directory = directory.resolve()
    for expected in spec.files:
        if _file_error(directory / Path(expected.member), expected) is not None:
            return None
    return directory / "bin" / "osslsigncode.exe"


def _extract_archive(
    archive_path: Path,
    destination: Path,
    spec: WindowsArchive,
) -> None:
    try:
        with ZipFile(archive_path) as archive:
            members = {
                item.filename.replace("\\", "/"): item
                for item in archive.infolist()
            }
            for expected in spec.files:
                member = members.get(expected.member)
                if member is None or member.is_dir():
                    raise OsslSignCodeError(
                        f"archive is missing {expected.member}"
                    )
                target = destination / Path(expected.member)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except OsslSignCodeError:
        raise
    except (BadZipFile, OSError) as exc:
        raise OsslSignCodeError(f"cannot extract osslsigncode: {exc}") from exc


def prepare_osslsigncode(
    directory: Path = DEFAULT_DIRECTORY,
    *,
    downloader: Downloader = _download,
    spec: WindowsArchive = WINDOWS_ARCHIVE,
    platform_name: str | None = None,
) -> OsslSignCodeInstall:
    platform_name = platform_name or os.name
    if platform_name != "nt":
        system_tool = shutil.which("osslsigncode")
        if system_tool:
            return OsslSignCodeInstall(
                action="system",
                path=Path(system_tool).resolve(),
                version=None,
            )
        raise OsslSignCodeError(
            "osslsigncode is not installed (Debian/Kali: sudo apt install osslsigncode)"
        )

    directory = directory.resolve()
    installed = managed_osslsigncode_path(
        directory, spec=spec, platform_name=platform_name
    )
    if installed is not None:
        return OsslSignCodeInstall("cached", installed, OSSLSIGNCODE_VERSION)
    if directory.exists() and any(directory.iterdir()):
        raise OsslSignCodeError(
            f"refusing to replace invalid osslsigncode cache: {directory}"
        )

    directory.parent.mkdir(parents=True, exist_ok=True)
    if directory.exists():
        directory.rmdir()
    try:
        with tempfile.TemporaryDirectory(
            prefix=".osslsigncode-", dir=directory.parent
        ) as temporary:
            staging = Path(temporary)
            archive_path = staging / "source.zip"
            payload = staging / "payload"
            payload.mkdir()
            downloader(spec.url, archive_path)
            if archive_path.stat().st_size != spec.size:
                raise OsslSignCodeError(
                    "downloaded osslsigncode archive has the wrong size"
                )
            if _sha256_file(archive_path) != spec.sha256:
                raise OsslSignCodeError(
                    "downloaded osslsigncode archive has the wrong SHA-256"
                )
            _extract_archive(archive_path, payload, spec)
            for expected in spec.files:
                error = _file_error(payload / Path(expected.member), expected)
                if error is not None:
                    raise OsslSignCodeError(error)
            os.replace(payload, directory)
    except OsslSignCodeError:
        raise
    except Exception as exc:
        raise OsslSignCodeError(f"cannot prepare osslsigncode: {exc}") from exc

    installed = managed_osslsigncode_path(
        directory, spec=spec, platform_name=platform_name
    )
    if installed is None:
        raise OsslSignCodeError("installed osslsigncode failed final verification")
    return OsslSignCodeInstall("installed", installed, OSSLSIGNCODE_VERSION)
