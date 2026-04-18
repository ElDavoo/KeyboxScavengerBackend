from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET

try:
    from scavenger.validator import KeyboxValidator
except ModuleNotFoundError as exc:
    KeyboxValidator = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


@unittest.skipIf(KeyboxValidator is None, f"validator deps unavailable: {_IMPORT_ERROR}")
class ValidatorPemSanitizerTests(unittest.TestCase):
    def test_sanitize_pem_certificate_strips_junk_and_rebuilds_markers(self):
        raw = """
noise before
-----BEGIN CERTIFICATE-----
QUJD
REVG
R0g=
-----END CERTIFICATE-----
noise after
"""

        sanitized = KeyboxValidator._sanitize_pem_certificate(raw)

        self.assertEqual(
            sanitized,
            "-----BEGIN CERTIFICATE-----\nQUJDREVGR0g=\n-----END CERTIFICATE-----\n",
        )

    def test_sanitize_pem_certificate_uses_longest_recoverable_run(self):
        raw = """
-----BEGIN CERTIFICATE-----
QUJD
REVG
this-is-not-base64
QQ==
-----END CERTIFICATE-----
"""

        sanitized = KeyboxValidator._sanitize_pem_certificate(raw)

        self.assertEqual(
            sanitized,
            "-----BEGIN CERTIFICATE-----\nQUJDREVG\n-----END CERTIFICATE-----\n",
        )

    def test_sanitize_pem_certificate_tolerates_missing_padding(self):
        raw = "QQ"

        sanitized = KeyboxValidator._sanitize_pem_certificate(raw)

        self.assertEqual(
            sanitized,
            "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n",
        )

    def test_sanitize_pem_certificate_raises_on_unrecoverable_data(self):
        with self.assertRaises(ValueError):
            KeyboxValidator._sanitize_pem_certificate("totally-invalid###")

    def test_parse_certificates_applies_sanitization(self):
        root = ET.fromstring(
            """
<AndroidAttestation>
  <Keybox>
    <Key>
      <CertificateChain>
        <Certificate format=\"pem\">prefix
-----BEGIN CERTIFICATE-----
QQ
-----END CERTIFICATE-----
suffix</Certificate>
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>
"""
        )

        certificates = KeyboxValidator._parse_certificates(root, 1)

        self.assertEqual(
            certificates[0],
            "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n",
        )

    def test_parse_certificates_handles_comment_noise_in_keybox_payload(self):
        root = ET.fromstring(
            """
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox DeviceID="t.me/keyboxstrong @evokerr">
        <Key algorithm="ecdsa">
            <PrivateKey format="pem">
-----BEGIN EC PRIVATE KEY-----
MDEyMzQ1Njc4OWFiY2RlZg==
-----END EC PRIVATE KEY-----
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>3</NumberOfCertificates>
                <Certificate format="pem">
-----BEGIN CERTIFICATE-----
QUFB
<!--comment noise-->
QkJC
-----END CERTIFICATE-----
                </Certificate>
                <Certificate format="pem">
-----BEGIN CERTIFICATE-----
Q0ND
<!--another comment-->
RERE
-----END CERTIFICATE-----
                </Certificate>
                <Certificate format="pem">
-----BEGIN CERTIFICATE-----
RUVG
<!--comment noise-->
R0dH
-----END CERTIFICATE-----
                </Certificate>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>
"""
        )

        counts = KeyboxValidator._parse_number_of_certificates(root)
        self.assertEqual(max(counts), 3)

        certificates = KeyboxValidator._parse_certificates(root, 3)

        self.assertEqual(len(certificates), 3)
        self.assertEqual(
            certificates[0],
            "-----BEGIN CERTIFICATE-----\nQUFBQkJC\n-----END CERTIFICATE-----\n",
        )
        self.assertEqual(
            certificates[1],
            "-----BEGIN CERTIFICATE-----\nQ0NDRERE\n-----END CERTIFICATE-----\n",
        )
        self.assertEqual(
            certificates[2],
            "-----BEGIN CERTIFICATE-----\nRUVGR0dH\n-----END CERTIFICATE-----\n",
        )


if __name__ == "__main__":
    unittest.main()
