from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import pefile
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from barrel_giga.core.signing import (
    create_signing_identity,
    discover_signing_backend,
    extract_signer_certificate,
    load_signing_profile,
    sign_pe,
)


ROOT = Path(__file__).resolve().parents[1]
APPLEWIN = ROOT / "bin" / "injectables" / "AppleWin-x64.exe"


class SigningTests(unittest.TestCase):
    def setUp(self):
        if not APPLEWIN.is_file():
            self.skipTest("run `py barrel-giga.py prep` first")

    def test_unsigned_identity_comes_from_pe_metadata(self):
        profile = load_signing_profile(APPLEWIN)
        self.assertEqual(profile.identity_source, "pe_metadata")
        self.assertEqual(profile.description, "Apple //e Emulator for Windows")
        self.assertIn("CN=AppleWin", profile.subject.rfc4514_string())

    def test_generated_identity_is_a_self_signed_code_signing_certificate(self):
        profile = load_signing_profile(APPLEWIN)
        with tempfile.TemporaryDirectory(
            prefix="barrel-giga-identity-test-"
        ) as temporary:
            identity = create_signing_identity(profile, temporary)
            self.assertTrue(identity.pfx_path.is_file())
            self.assertEqual(identity.certificate.subject, profile.subject)
            self.assertEqual(identity.certificate.issuer, profile.subject)
            eku = identity.certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            self.assertIn(ExtendedKeyUsageOID.CODE_SIGNING, eku)

    @unittest.skipUnless(
        os.environ.get("BARREL_GIGA_RUN_SIGNING_INTEGRATION") == "1",
        "set BARREL_GIGA_RUN_SIGNING_INTEGRATION=1",
    )
    def test_osslsigncode_timestamps_metadata_and_cloned_identity_paths(self):
        backend = discover_signing_backend()
        self.assertEqual(backend.name, "osslsigncode")

        with tempfile.TemporaryDirectory(
            prefix="barrel-giga-signing-test-"
        ) as temporary:
            temporary_path = Path(temporary)
            metadata_target = temporary_path / "metadata.exe"
            cloned_target = temporary_path / "cloned.exe"
            shutil.copyfile(APPLEWIN, metadata_target)
            shutil.copyfile(APPLEWIN, cloned_target)

            metadata_result = sign_pe(
                metadata_target,
                injectable_path=APPLEWIN,
                backend=backend,
            )
            cloned_result = sign_pe(
                cloned_target,
                injectable_path=metadata_target,
                backend=backend,
            )

            self.assertEqual(metadata_result.identity_source, "pe_metadata")
            self.assertEqual(cloned_result.identity_source, "original_signature")
            self.assertEqual(
                cloned_result.certificate_subject,
                metadata_result.certificate_subject,
            )
            self.assertEqual(
                cloned_result.source_certificate_subject,
                metadata_result.certificate_subject,
            )
            self.assertTrue(metadata_result.timestamp_url)
            self.assertTrue(cloned_result.timestamp_url)

            for target, result in (
                (metadata_target, metadata_result),
                (cloned_target, cloned_result),
            ):
                certificate = extract_signer_certificate(target)
                self.assertIsNotNone(certificate)
                assert certificate is not None
                self.assertEqual(
                    certificate.fingerprint(hashes.SHA256()).hex().upper(),
                    result.certificate_thumbprint,
                )
                image = pefile.PE(str(target), fast_load=False)
                try:
                    security = image.OPTIONAL_HEADER.DATA_DIRECTORY[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                    ]
                    self.assertGreater(security.VirtualAddress, 0)
                    self.assertGreater(security.Size, 0)
                finally:
                    image.close()



if __name__ == "__main__":
    unittest.main()
