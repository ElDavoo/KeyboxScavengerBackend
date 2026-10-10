from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from scavenger.validator import KeyboxValidator


def _name(common_name: str | None = None, organization: str | None = None, title: str | None = None) -> x509.Name:
    attributes = []
    if common_name:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if title:
        attributes.append(x509.NameAttribute(NameOID.TITLE, title))
    return x509.Name(attributes)


def _chain(subjects: list[x509.Name]) -> list[x509.Certificate]:
    """Build a leaf-first chain where each subject is issued by the next one."""
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in subjects]
    now = datetime.now(timezone.utc)
    certificates = []
    for index, subject in enumerate(subjects):
        issuer_index = min(index + 1, len(subjects) - 1)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subjects[issuer_index])
            .public_key(keys[index].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(keys[issuer_index], hashes.SHA256())
        )
        certificates.append(certificate)
    return certificates


class RkpChainDetectionTests(unittest.TestCase):
    def test_droid_ca_intermediates_are_rkp(self):
        chain = _chain(
            [
                _name("774a0c73f386df0837e4730415e1e950", "TEE"),
                _name("Droid CA3", "Google LLC"),
                _name("Droid CA2", "Google LLC"),
                _name("Key Attestation CA1", "Google LLC"),
            ]
        )
        self.assertTrue(KeyboxValidator._is_rkp_chain(chain))
        self.assertTrue(KeyboxValidator._verify_certificate_chain(chain))

    def test_factory_tee_intermediates_are_not_rkp(self):
        chain = _chain(
            [
                _name(title="TEE"),
                _name(title="TEE"),
                _name("Root"),
            ]
        )
        self.assertFalse(KeyboxValidator._is_rkp_chain(chain))

    def test_droid_ca_name_from_other_organization_is_not_rkp(self):
        chain = _chain(
            [
                _name("leaf", "TEE"),
                _name("Droid CA3", "Not Google"),
                _name("Root"),
            ]
        )
        self.assertFalse(KeyboxValidator._is_rkp_chain(chain))


if __name__ == "__main__":
    unittest.main()
