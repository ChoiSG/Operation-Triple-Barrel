from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from barrel_giga.injectable import (
    AMD64,
    InjectableError,
    InjectableSpec,
    PeFacts,
    inspect_pe,
    install_injectable,
    load_spec,
)


ROOT = Path(__file__).resolve().parents[1]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class InjectableTests(unittest.TestCase):
    @staticmethod
    def _fixture(root: Path) -> tuple[InjectableSpec, Path, bytes]:
        executable = b"MZ\x00synthetic executable"
        archive_path = root / "source.zip"
        with ZipFile(archive_path, "w") as archive:
            archive.writestr("AppleWin-x64.exe", executable)
        archive_bytes = archive_path.read_bytes()
        return (
            InjectableSpec(
                name="AppleWin-x64.exe",
                release="test",
                url="https://example.invalid/AppleWin.zip",
                homepage="https://example.invalid/release",
                archive_size=len(archive_bytes),
                archive_sha256=_sha256(archive_bytes),
                member="AppleWin-x64.exe",
                executable_size=len(executable),
                executable_sha256=_sha256(executable),
            ),
            archive_path,
            executable,
        )

    @staticmethod
    def _pe(_: Path) -> PeFacts:
        return PeFacts(machine=AMD64, entrypoint_rva=0x1000, image_size=0x2000)

    def test_repository_manifest_pins_one_applewin_executable(self):
        spec = load_spec(ROOT / "injectable.json")
        self.assertEqual(spec.name, "AppleWin-x64.exe")
        self.assertEqual(spec.release, "v1.32.0.0")
        self.assertEqual(spec.member, "AppleWin-x64.exe")
        self.assertEqual(spec.executable_size, 3_154_944)
        self.assertEqual(
            spec.executable_sha256,
            "A0AD41367CA10651EC7C455915CDE676B1D8EE8480C2311583163A110D46A699",
        )

    def test_install_is_verified_atomic_and_cached(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-test-") as temporary:
            root = Path(temporary)
            spec, source, executable = self._fixture(root)
            calls = 0

            def downloader(_: str, destination: Path) -> None:
                nonlocal calls
                calls += 1
                shutil.copyfile(source, destination)

            destination = root / "injectables"
            first = install_injectable(
                spec, destination, downloader=downloader, pe_inspector=self._pe
            )
            second = install_injectable(
                spec, destination, downloader=downloader, pe_inspector=self._pe
            )
            self.assertEqual(calls, 1)
            self.assertEqual(first.action, "installed")
            self.assertEqual(second.action, "cached")
            self.assertEqual((destination / spec.name).read_bytes(), executable)

    def test_existing_mismatch_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-test-") as temporary:
            root = Path(temporary)
            spec, source, _ = self._fixture(root)
            destination = root / "injectables"
            destination.mkdir()
            target = destination / spec.name
            target.write_bytes(b"unrelated existing file")

            def downloader(_: str, path: Path) -> None:
                shutil.copyfile(source, path)

            with self.assertRaisesRegex(InjectableError, "refusing to replace"):
                install_injectable(
                    spec,
                    destination,
                    downloader=downloader,
                    pe_inspector=self._pe,
                )
            self.assertEqual(target.read_bytes(), b"unrelated existing file")

    def test_staged_executable_inherits_the_destination_directory(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-test-") as temporary:
            root = Path(temporary)
            spec, source, _ = self._fixture(root)
            destination = (root / "injectables").resolve()

            def downloader(_: str, path: Path) -> None:
                shutil.copyfile(source, path)

            def inspector(path: Path) -> PeFacts:
                self.assertEqual(path.resolve().parent, destination)
                return self._pe(path)

            install_injectable(
                spec,
                destination,
                downloader=downloader,
                pe_inspector=inspector,
            )

    def test_bad_archive_hash_does_not_publish(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-test-") as temporary:
            root = Path(temporary)
            spec, source, _ = self._fixture(root)
            spec = InjectableSpec(
                **{**spec.__dict__, "archive_sha256": "0" * 64}
            )
            destination = root / "injectables"

            def downloader(_: str, path: Path) -> None:
                shutil.copyfile(source, path)

            with self.assertRaisesRegex(InjectableError, "archive failed verification"):
                install_injectable(
                    spec,
                    destination,
                    downloader=downloader,
                    pe_inspector=self._pe,
                )
            self.assertFalse((destination / spec.name).exists())

    def test_manifest_rejects_unknown_fields_and_http(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-test-") as temporary:
            path = Path(temporary) / "injectable.json"
            value = json.loads((ROOT / "injectable.json").read_text(encoding="utf-8"))
            value["unknown"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(InjectableError, "unknown manifest fields"):
                load_spec(path)

            value.pop("unknown")
            value["url"] = "http://example.invalid/AppleWin.zip"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(InjectableError, "must be an HTTPS URL"):
                load_spec(path)

    def test_pe_inspection_rejects_non_pe_data(self):
        with tempfile.TemporaryDirectory(prefix="barrel-giga-test-") as temporary:
            path = Path(temporary) / "bad.exe"
            path.write_bytes(b"not a PE")
            with self.assertRaisesRegex(InjectableError, "invalid PE"):
                inspect_pe(path)


if __name__ == "__main__":
    unittest.main()
