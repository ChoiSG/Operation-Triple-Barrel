from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pefile

from barrel_giga.cli import main
from barrel_giga.injectable import sha256_file


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("BARREL_GIGA_RUN_BUILD_INTEGRATION") == "1",
    "set BARREL_GIGA_RUN_BUILD_INTEGRATION=1",
)
class NativeBuildIntegrationTests(unittest.TestCase):
    def test_real_barrel_kit_payload_builds_in_pinned_applewin(self):
        payload = ROOT.parent / "barrel-kit" / "output" / "agent.x64.bin"
        injectable = ROOT / "bin" / "injectables" / "AppleWin-x64.exe"
        if not payload.is_file() or not injectable.is_file():
            self.skipTest("build Barrel Kit and run `py barrel-giga.py prep` first")

        host_hash = sha256_file(injectable)
        with tempfile.TemporaryDirectory(
            prefix="barrel-giga-build-test-"
        ) as temporary:
            output = Path(temporary) / "applewin-barrel.exe"
            result = main(
                [
                    "build",
                    "--input",
                    str(payload),
                    "--injectable",
                    str(injectable),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(result, 0)
            self.assertTrue(output.is_file())
            self.assertEqual(sha256_file(injectable), host_hash)

            manifest_path = (
                Path(temporary) / "applewin-barrel.artifacts" / "manifest.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIn("barrel_giga_version", manifest)
            self.assertNotIn("supergiga_version", manifest)
            self.assertTrue(manifest["compatibility"]["buildable"])
            self.assertEqual(
                [f"{item['slot']}/{item['name']}" for item in manifest["recipe"]],
                [
                    "guardrail/none",
                    "anti_emulation/none",
                    "memory/image_split_restore",
                    "decoder/xor_stream",
                    "execute/thread_keepalive",
                    "pe_invoke/function_backdoor",
                ],
            )
            self.assertEqual(
                manifest["compatibility"]["planned_repairs"],
                [
                    {
                        "dll": "KERNEL32.dll",
                        "name_offset": 2045286,
                        "new_name": "FlushInstructionCache",
                        "old_name": "DeleteCriticalSection",
                    }
                ],
            )
            self.assertEqual(
                sha256_file(output), manifest["injection"]["output_sha256"]
            )

            image = pefile.PE(str(output), fast_load=False)
            try:
                self.assertEqual(image.FILE_HEADER.Machine, 0x8664)
                self.assertEqual(
                    image.OPTIONAL_HEADER.CheckSum, image.generate_checksum()
                )
                self.assertEqual(
                    image.OPTIONAL_HEADER.AddressOfEntryPoint,
                    manifest["injection"]["original_entrypoint_rva"],
                )
            finally:
                image.close()


if __name__ == "__main__":
    unittest.main()
