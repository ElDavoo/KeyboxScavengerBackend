from __future__ import annotations

import datetime
import textwrap

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _self_signed_pem(private_key) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.TITLE, "TEE")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def generate_key_pems() -> tuple[str, str]:
    """Return (ecdsa_cert_pem, rsa_cert_pem), both wrapped at 64 columns."""
    ec_key = ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _self_signed_pem(ec_key), _self_signed_pem(rsa_key)


def unwrap_pem(pem: str) -> str:
    """Collapse the base64 body of a PEM block onto a single line."""
    lines = pem.strip().splitlines()
    return "\n".join([lines[0], "".join(lines[1:-1]), lines[-1]])


def rewrap_pem(pem: str, width: int) -> str:
    lines = pem.strip().splitlines()
    return "\n".join([lines[0], *textwrap.wrap("".join(lines[1:-1]), width), lines[-1]])


def keybox_xml(ecdsa_pem: str, rsa_pem: str, rsa_algorithm: str = "rsa") -> bytes:
    return f"""<?xml version="1.0"?>
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="sw">
    <Key algorithm="ecdsa">
      <CertificateChain>
        <NumberOfCertificates>1</NumberOfCertificates>
        <Certificate format="pem">
{ecdsa_pem}
        </Certificate>
      </CertificateChain>
    </Key>
    <Key algorithm="{rsa_algorithm}">
      <CertificateChain>
        <NumberOfCertificates>1</NumberOfCertificates>
        <Certificate format="pem">
{rsa_pem}
        </Certificate>
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>
""".encode()
