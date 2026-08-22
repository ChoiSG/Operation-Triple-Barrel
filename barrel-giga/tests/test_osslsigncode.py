from __future__ import annotations

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from barrel_giga.osslsigncode import (
    ManagedFile,
    OsslSignCodeError,
    WindowsArchive,
    prepare_osslsigncode,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class OsslSignCodeTests(unittest.TestCase):
    @staticmethod
    def _fixture(root: Path) -> tuple[WindowsArchive, Path]:
        files = {
            "bin/osslsigncode.exe": b"tool",
            "bin/libcrypto-3-x64.dll": b"crypto",
            "bin/libssl-3-x64.dll": b"ssl",
            "bin/zlib1.dll": b"zlib",
        }
        archive_path = root / "source.zip"
        with ZipFile(archive_path, "w") as archive:
            for name, value in files.items():
                archive.writestr(name, value)
        archive_bytes = archive_path.read_bytes()
        return (
            WindowsArchive(
                url="https://example.invalid/osslsigncode.zip",
                size=len(archive_bytes),
                sha256=_sha256(archive_bytes),
                files=tuple(
                    ManagedFile(name, len(value), _sha256(value))
                    for name, value in files.items()
                ),
            ),
            archive_path,
        )

    def test_windows_install_is_verified_and_cached(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-tool-test-") as temporary:
            root = Path(temporary)
            spec, source = self._fixture(root)
            calls = 0

            def downloader(_: str, destination: Path) -> None:
                nonlocal calls
                calls += 1
                shutil.copyfile(source, destination)

            destination = root / "tools" / "osslsigncode"
            first = prepare_osslsigncode(
                destination,
                downloader=downloader,
                spec=spec,
                platform_name="nt",
            )
            second = prepare_osslsigncode(
                destination,
                downloader=downloader,
                spec=spec,
                platform_name="nt",
            )

            self.assertEqual(calls, 1)
            self.assertEqual(first.action, "installed")
            self.assertEqual(second.action, "cached")
            self.assertEqual(first.path.read_bytes(), b"tool")

    def test_bad_archive_hash_does_not_publish(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-tool-test-") as temporary:
            root = Path(temporary)
            spec, source = self._fixture(root)
            spec = WindowsArchive(
                url=spec.url,
                size=spec.size,
                sha256="0" * 64,
                files=spec.files,
            )

            def downloader(_: str, destination: Path) -> None:
                shutil.copyfile(source, destination)

            destination = root / "tools" / "osslsigncode"
            with self.assertRaisesRegex(OsslSignCodeError, "wrong SHA-256"):
                prepare_osslsigncode(
                    destination,
                    downloader=downloader,
                    spec=spec,
                    platform_name="nt",
                )
            self.assertFalse(destination.exists())

    def test_non_windows_uses_the_system_tool(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-tool-test-") as temporary:
            tool = Path(temporary) / "osslsigncode"
            tool.touch()
            with patch(
                "barrel_giga.osslsigncode.shutil.which", return_value=str(tool)
            ):
                result = prepare_osslsigncode(platform_name="posix")
            self.assertEqual(result.action, "system")
            self.assertEqual(result.path, tool.resolve())
            self.assertIsNone(result.version)


if __name__ == "__main__":
    unittest.main()
