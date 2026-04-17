import tempfile
import unittest
from pathlib import Path

from scavenger.storage import KeyboxStorage
from scavenger.xml_normalizer import normalize_xml_payload


class KeyboxStorageTests(unittest.TestCase):
    def test_persist_writes_sha_and_latest_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            storage = KeyboxStorage(output_dir)

            payload_one = b"<keybox>one</keybox>"
            payload_two = b"<keybox>two</keybox>"

            first = storage.persist(payload_one)
            second = storage.persist(payload_one)
            third = storage.persist(payload_two)

            self.assertTrue(first.digest_path.exists())
            self.assertTrue(second.digest_path.exists())
            self.assertEqual(first.digest_path, second.digest_path)
            self.assertTrue(first.wrote_digest_file)
            self.assertFalse(second.wrote_digest_file)

            self.assertTrue(third.digest_path.exists())
            self.assertNotEqual(first.digest_path, third.digest_path)
            self.assertEqual((output_dir / "keybox.xml").read_bytes(), payload_two)

            self.assertEqual(first.digest_path.name, "8cfa2d5f761d67833f85d8d56571c319.xml")
            self.assertEqual(third.digest_path.name, "b5b96db27bb53f9ba9e6f944c1144b94.xml")

    def test_normalized_xml_avoids_duplicates_from_formatting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            storage = KeyboxStorage(output_dir)

            payload_one = b"""<AndroidAttestation>
    <!-- comment should not affect hash -->
    <Keybox DeviceID=\"A\" Product=\"B\">
      <Key>
        <CertificateChain>
          <Certificate format=\"pem\">\nABC\n</Certificate>
        </CertificateChain>
      </Key>
    </Keybox>
</AndroidAttestation>"""

            payload_two = b"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<AndroidAttestation><Keybox Product=\"B\" DeviceID=\"A\"><Key><CertificateChain><Certificate format=\"pem\">ABC</Certificate></CertificateChain></Key></Keybox></AndroidAttestation>"""

            first_normalized = normalize_xml_payload(payload_one)
            second_normalized = normalize_xml_payload(payload_two)

            self.assertEqual(first_normalized, second_normalized)

            first = storage.persist(first_normalized)
            second = storage.persist(second_normalized)

            self.assertEqual(first.digest_path, second.digest_path)
            self.assertTrue(first.wrote_digest_file)
            self.assertFalse(second.wrote_digest_file)


if __name__ == "__main__":
    unittest.main()
