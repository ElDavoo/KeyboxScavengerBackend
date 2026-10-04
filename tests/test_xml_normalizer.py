import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from scavenger.xml_normalizer import XmlNormalizationError, normalize_xml_payload
from tests.keybox_factory import generate_key_pems, keybox_xml, rewrap_pem, unwrap_pem


class XmlNormalizerTests(unittest.TestCase):
    def test_normalize_all_well_formed_fixture_keyboxes(self):
        fixtures_dir = Path(__file__).resolve().parent.parent / "test_keyboxes"
        fixtures = sorted(fixtures_dir.glob("*.xml"))
        self.assertGreater(len(fixtures), 0)
        malformed = []

        for fixture in fixtures:
            raw_payload = fixture.read_bytes()
            try:
                ET.fromstring(raw_payload)
            except ET.ParseError:
                malformed.append(fixture.name)
                continue

            with self.subTest(fixture=fixture.name):
                normalized = normalize_xml_payload(raw_payload)
                self.assertTrue(normalized.startswith(b"<?xml"))
                self.assertNotIn(b"<!--", normalized)

                root = ET.fromstring(normalized)
                for node in root.iter():
                    self.assertFalse(
                        any(key.lower() == "deviceid" for key in node.attrib),
                        msg=f"DeviceID attribute still present in {fixture.name}",
                    )

                for tag in ("Certificate", "PrivateKey"):
                    for block in root.findall(f".//{tag}"):
                        content = block.text or ""
                        lines = [line for line in content.splitlines() if line.strip()]
                        self.assertTrue(
                            lines,
                            msg=f"{tag} block unexpectedly empty in {fixture.name}",
                        )
                        self.assertEqual(
                            lines,
                            [line.strip() for line in lines],
                            msg=f"{tag} lines contain extra spaces in {fixture.name}",
                        )

        self.assertIn("keybox (8).xml", malformed)

    def test_removes_deviceid_attribute_before_processing(self):
        payload = (
            b"<AndroidAttestation><Keybox DeviceID='abc123' Product='foo'>"
            b"<Key/></Keybox></AndroidAttestation>"
        )

        normalized = normalize_xml_payload(payload)
        root = ET.fromstring(normalized)

        keybox = root.find(".//Keybox")
        self.assertIsNotNone(keybox)
        self.assertNotIn("DeviceID", keybox.attrib)
        self.assertEqual(keybox.attrib.get("Product"), "foo")

    def test_raises_on_malformed_orphan_deviceid_keybox_wrapper(self):
        payload = b"""<?xml version='1.0' encoding='utf-8'?>
<AndroidAttestation>
  <Keybox DeviceID='orphan'>
  <Keybox>
    <Key algorithm='ecdsa'>
      <CertificateChain>
        <NumberOfCertificates>3</NumberOfCertificates>
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>
"""

        with self.assertRaises(XmlNormalizationError):
            normalize_xml_payload(payload)

    def test_known_malformed_fixture_raises(self):
        fixture = Path(__file__).resolve().parent.parent / "test_keyboxes" / "keybox (8).xml"

        with self.assertRaises(XmlNormalizationError):
            normalize_xml_payload(fixture.read_bytes())

    def test_pem_line_wrapping_does_not_change_normalized_output(self):
        ecdsa_pem, rsa_pem = generate_key_pems()

        wrapped = normalize_xml_payload(keybox_xml(ecdsa_pem, rsa_pem))
        single_line = normalize_xml_payload(keybox_xml(unwrap_pem(ecdsa_pem), unwrap_pem(rsa_pem)))
        odd_width = normalize_xml_payload(keybox_xml(rewrap_pem(ecdsa_pem, 76), rewrap_pem(rsa_pem, 40)))

        self.assertEqual(wrapped, single_line)
        self.assertEqual(wrapped, odd_width)
        certificate = ET.fromstring(wrapped).find(".//Certificate")
        body_lines = certificate.text.splitlines()[1:-1]
        self.assertTrue(all(len(line) <= 64 for line in body_lines))

    def test_tampered_key_algorithm_is_restored_from_certificate(self):
        ecdsa_pem, rsa_pem = generate_key_pems()

        clean = normalize_xml_payload(keybox_xml(ecdsa_pem, rsa_pem))
        tampered = normalize_xml_payload(keybox_xml(ecdsa_pem, rsa_pem, rsa_algorithm="@evokerr"))

        self.assertEqual(clean, tampered)
        algorithms = [key.get("algorithm") for key in ET.fromstring(tampered).iter("Key")]
        self.assertEqual(algorithms, ["ecdsa", "rsa"])

    def test_non_base64_pem_body_is_left_untouched(self):
        payload = (
            b"<AndroidAttestation><Keybox><Key algorithm='rsa'><CertificateChain>"
            b"<Certificate format='pem'>-----BEGIN CERTIFICATE-----\nnot base64 at all!\n"
            b"-----END CERTIFICATE-----</Certificate></CertificateChain></Key></Keybox>"
            b"</AndroidAttestation>"
        )

        certificate = ET.fromstring(normalize_xml_payload(payload)).find(".//Certificate")

        self.assertIn("not base64 at all!", certificate.text)

    def test_raises_on_unrecoverable_xml(self):
        payload = b"<AndroidAttestation><Keybox><Key></AndroidAttestation>"

        with self.assertRaises(XmlNormalizationError):
            normalize_xml_payload(payload)


if __name__ == "__main__":
    unittest.main()
