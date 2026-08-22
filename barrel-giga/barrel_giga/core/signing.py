"""Authenticode self-signing for Barrel-Giga outputs.

Python creates the ephemeral signing identity. osslsigncode creates the
Authenticode CMS and obtains the RFC 3161 timestamp.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import struct
import subprocess
import tempfile
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pefile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..osslsigncode import managed_osslsigncode_path


DEFAULT_TIMESTAMP_URLS = (
    "http://timestamp.sectigo.com/rfc3161",
    "http://timestamp.digicert.com",
)

WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


class SigningError(RuntimeError):
    pass


@dataclass(frozen=True)
class SigningProfile:
    subject: x509.Name
    description: str
    identity_source: str
    source_certificate_subject: str | None = None
    source_certificate_issuer: str | None = None


@dataclass(frozen=True)
class SigningIdentity:
    pfx_path: Path
    password_path: Path
    password: str
    certificate: x509.Certificate


@dataclass(frozen=True)
class SigningBackend:
    name: str
    tool_path: Path


@dataclass(frozen=True)
class SigningResult:
    signed_output_sha256: str
    backend: str
    tool: str
    identity_source: str
    certificate_subject: str
    certificate_thumbprint: str
    certificate_expires: datetime
    source_certificate_subject: str | None
    source_certificate_issuer: str | None
    timestamp_url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "backend": self.backend,
            "tool": self.tool,
            "identity_source": self.identity_source,
            "certificate_subject": self.certificate_subject,
            "certificate_thumbprint_sha256": self.certificate_thumbprint,
            "certificate_expires": self.certificate_expires.isoformat(),
            "source_certificate_subject": self.source_certificate_subject,
            "source_certificate_issuer": self.source_certificate_issuer,
            "timestamp_obtained": True,
            "timestamp_url": self.timestamp_url,
            "signed_output_sha256": self.signed_output_sha256,
        }


def _decode_version_value(value: bytes | str) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value.replace("\x00", "").strip()


def _pe_version_info(pe: pefile.PE) -> dict[str, str]:
    result: dict[str, str] = {}
    for group in getattr(pe, "FileInfo", None) or ():
        for item in group:
            for table in getattr(item, "StringTable", ()):
                for key, value in table.entries.items():
                    result[_decode_version_value(key)] = _decode_version_value(value)
    return result


def _first_der_object(value: bytes) -> bytes:
    if len(value) < 2 or value[0] != 0x30:
        raise SigningError("certificate table does not contain DER SignedData")
    first_length = value[1]
    if first_length < 0x80:
        header_length = 2
        content_length = first_length
    else:
        length_octets = first_length & 0x7F
        if length_octets == 0 or length_octets > 4 or len(value) < 2 + length_octets:
            raise SigningError("certificate table has an invalid DER length")
        header_length = 2 + length_octets
        content_length = int.from_bytes(value[2:header_length], "big")
    total_length = header_length + content_length
    if total_length > len(value):
        raise SigningError("certificate table contains truncated SignedData")
    return value[:total_length]


def _pkcs7_blobs(pe_data: bytes) -> tuple[bytes, ...]:
    try:
        image = pefile.PE(data=pe_data, fast_load=True)
        directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        offset = int(directory.VirtualAddress)
        size = int(directory.Size)
    except Exception as exc:
        raise SigningError(f"unable to inspect the PE certificate table: {exc}") from exc

    if offset == 0 and size == 0:
        return ()
    if offset <= 0 or size < 8 or offset + size > len(pe_data):
        raise SigningError("PE certificate table is outside the file")

    blobs: list[bytes] = []
    cursor = offset
    limit = offset + size
    while cursor + 8 <= limit:
        length, _revision, certificate_type = struct.unpack_from("<IHH", pe_data, cursor)
        if length < 8 or cursor + length > limit:
            raise SigningError("PE certificate table contains an invalid WIN_CERTIFICATE")
        if certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            blobs.append(_first_der_object(pe_data[cursor + 8 : cursor + length]))
        cursor += (length + 7) & ~7
    return tuple(blobs)


def _has_code_signing_eku(certificate: x509.Certificate) -> bool:
    try:
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.CODE_SIGNING in eku


def _is_end_entity(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return True
    return not constraints.ca


def extract_signer_certificate(pe_path: str | Path) -> x509.Certificate | None:
    pe_path = Path(pe_path)
    blobs = _pkcs7_blobs(pe_path.read_bytes())
    if not blobs:
        return None

    for blob in blobs:
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message="PKCS#7 certificates could not be parsed as DER.*",
                    category=UserWarning,
                )
                certificates = pkcs7.load_der_pkcs7_certificates(blob)
        except ValueError:
            continue
        code_signers = [item for item in certificates if _has_code_signing_eku(item)]
        if code_signers:
            return code_signers[0]
        end_entities = [item for item in certificates if _is_end_entity(item)]
        if end_entities:
            return end_entities[0]
        if certificates:
            return certificates[0]
    raise SigningError("the PE has a signature table but no readable signer certificate")


def _metadata_subject(company: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, company),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        ]
    )


def load_signing_profile(pe_path: str | Path) -> SigningProfile:
    pe_path = Path(pe_path)
    try:
        image = pefile.PE(str(pe_path), fast_load=False)
        version_info = _pe_version_info(image)
        image.close()
    except Exception as exc:
        raise SigningError(f"unable to read PE metadata from {pe_path}: {exc}") from exc

    description = (
        version_info.get("FileDescription")
        or version_info.get("ProductName")
        or pe_path.stem
    )
    signer = extract_signer_certificate(pe_path)
    if signer is not None:
        if not signer.subject:
            raise SigningError("the original signer certificate has an empty subject")
        return SigningProfile(
            subject=signer.subject,
            description=description,
            identity_source="original_signature",
            source_certificate_subject=signer.subject.rfc4514_string(),
            source_certificate_issuer=signer.issuer.rfc4514_string(),
        )

    company = (
        version_info.get("CompanyName")
        or version_info.get("ProductName")
        or pe_path.stem
    ).strip()
    if not company:
        company = pe_path.stem
    return SigningProfile(
        subject=_metadata_subject(company[:64]),
        description=description,
        identity_source="pe_metadata",
    )


def _friendly_name(subject: x509.Name) -> str:
    names = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return names[0].value if names else "Barrel-Giga"


def create_signing_identity(
    profile: SigningProfile,
    directory: str | Path,
) -> SigningIdentity:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(profile.subject)
        .issuer_name(profile.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    password = secrets.token_urlsafe(24)
    pfx = pkcs12.serialize_key_and_certificates(
        name=_friendly_name(profile.subject).encode("utf-8"),
        key=key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )
    pfx_path = directory / "codesign.pfx"
    password_path = directory / "codesign.password"
    pfx_path.write_bytes(pfx)
    password_path.write_text(password, encoding="utf-8")
    try:
        os.chmod(pfx_path, 0o600)
        os.chmod(password_path, 0o600)
    except OSError:
        pass
    return SigningIdentity(pfx_path, password_path, password, certificate)


def _configured_tool(environment_name: str) -> Path | None:
    configured = os.environ.get(environment_name, "").strip()
    if not configured:
        return None
    path = Path(configured).expanduser().resolve()
    if not path.is_file():
        raise SigningError(f"{environment_name} does not point to a file: {path}")
    return path


def _discover_osslsigncode() -> Path | None:
    configured = _configured_tool("BARREL_GIGA_OSSLSIGNCODE")
    if configured is not None:
        return configured
    managed = managed_osslsigncode_path()
    if managed is not None:
        return managed
    on_path = shutil.which("osslsigncode") or shutil.which("osslsigncode.exe")
    return Path(on_path).resolve() if on_path else None


def discover_signing_backend(profile_name: str | None = None) -> SigningBackend:
    del profile_name
    osslsigncode = _discover_osslsigncode()
    if osslsigncode is not None:
        return SigningBackend("osslsigncode", osslsigncode)
    raise SigningError(
        "osslsigncode was not found; install it or set BARREL_GIGA_OSSLSIGNCODE"
    )


def timestamp_urls() -> tuple[str, ...]:
    configured = os.environ.get("BARREL_GIGA_TIMESTAMP_URLS", "").strip()
    if not configured:
        return DEFAULT_TIMESTAMP_URLS
    urls = tuple(
        item.strip()
        for item in configured.replace(";", ",").split(",")
        if item.strip()
    )
    if not urls:
        raise SigningError("BARREL_GIGA_TIMESTAMP_URLS contains no usable URLs")
    return urls


def _run(command: list[str], timeout: int = 90) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SigningError(f"signing command failed to run: {exc}") from exc


def _failure(label: str, result: subprocess.CompletedProcess[str]) -> str:
    output = "\n".join(
        item.strip()
        for item in (result.stdout, result.stderr)
        if item and item.strip()
    )
    return f"{label} failed (exit {result.returncode})" + (
        f":\n{output}" if output else ""
    )


def _sign_with_osslsigncode(
    backend: SigningBackend,
    pe_path: Path,
    identity: SigningIdentity,
    description: str,
    urls: tuple[str, ...],
) -> str:
    failures: list[str] = []
    for index, url in enumerate(urls):
        candidate = pe_path.with_name(f".{pe_path.name}.signed-{index}")
        candidate.unlink(missing_ok=True)
        try:
            result = _run(
                [
                    str(backend.tool_path),
                    "sign",
                    "-pkcs12",
                    str(identity.pfx_path),
                    "-readpass",
                    str(identity.password_path),
                    "-h",
                    "sha256",
                    "-n",
                    description,
                    "-ts",
                    url,
                    "-in",
                    str(pe_path),
                    "-out",
                    str(candidate),
                ]
            )
            if result.returncode == 0 and candidate.is_file():
                os.replace(candidate, pe_path)
                return url
            failures.append(_failure(f"Authenticode + RFC 3161 ({url})", result))
        finally:
            candidate.unlink(missing_ok=True)
    raise SigningError("all RFC 3161 timestamp services failed:\n" + "\n".join(failures))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def sign_pe(
    pe_path: str | Path,
    injectable_path: str | Path | None = None,
    progress: Any = None,
    backend: SigningBackend | None = None,
) -> SigningResult:
    del progress
    pe_path = Path(pe_path).resolve()
    if not pe_path.is_file():
        raise SigningError(f"PE output does not exist: {pe_path}")

    source_path = Path(injectable_path).resolve() if injectable_path else pe_path
    profile = load_signing_profile(source_path)
    selected_backend = backend or discover_signing_backend()
    urls = timestamp_urls()

    with tempfile.TemporaryDirectory(prefix="barrel-giga-sign-") as temporary:
        identity = create_signing_identity(profile, temporary)
        if selected_backend.name != "osslsigncode":
            raise SigningError(f"unknown Authenticode backend: {selected_backend.name}")
        timestamp_url = _sign_with_osslsigncode(
            selected_backend, pe_path, identity, profile.description, urls
        )

        embedded = extract_signer_certificate(pe_path)
        if embedded is None:
            raise SigningError("signing backend returned success without embedding a certificate")
        expected = identity.certificate.fingerprint(hashes.SHA256())
        if embedded.fingerprint(hashes.SHA256()) != expected:
            raise SigningError("embedded signer certificate does not match the generated identity")

        certificate = identity.certificate
        thumbprint = expected.hex().upper()

    return SigningResult(
        signed_output_sha256=_sha256_file(pe_path),
        backend=selected_backend.name,
        tool=str(selected_backend.tool_path),
        identity_source=profile.identity_source,
        certificate_subject=certificate.subject.rfc4514_string(),
        certificate_thumbprint=thumbprint,
        certificate_expires=certificate.not_valid_after_utc,
        source_certificate_subject=profile.source_certificate_subject,
        source_certificate_issuer=profile.source_certificate_issuer,
        timestamp_url=timestamp_url,
    )
