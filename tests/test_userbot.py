from __future__ import annotations

import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock

from scavenger.models import ValidationResult
from scavenger.storage import KeyboxStorage
from scavenger.userbot import KeyboxScavengerUserbot
from scavenger.xml_normalizer import normalize_xml_payload


class FakeClient:
    def __init__(self):
        self.registered_handlers = []

    def on(self, event_builder):
        def decorator(handler):
            self.registered_handlers.append((handler, event_builder))
            return handler

        return decorator


class FakeFile:
    def __init__(self, payload: bytes, name: str = "keybox.xml", mime_type: str = "application/xml"):
        self.mime_type = mime_type
        self.name = name
        self.size = len(payload)


class FakeMessage:
    def __init__(self, payload: bytes, message_id: int = 1):
        self.file = FakeFile(payload)
        self.id = message_id


class FakeEventClient:
    def __init__(self, payload: bytes):
        self._payload = payload

    async def download_media(self, message, as_type):
        return self._payload


class FakeEvent:
    def __init__(self, payload: bytes, chat_id: int = 123, message_id: int = 1):
        self.chat_id = chat_id
        self.message = FakeMessage(payload, message_id=message_id)
        self.client = FakeEventClient(payload)


class KeyboxScavengerUserbotTests(unittest.TestCase):
    @staticmethod
    def _payload_rsa_only() -> bytes:
        return normalize_xml_payload(
            b"""<AndroidAttestation>
    <Keybox>
        <Key algorithm=\"rsa\">
            <CertificateChain>
                <NumberOfCertificates>3</NumberOfCertificates>
                <Certificate format=\"pem\">RSA_CERT_A</Certificate>
                <Certificate format=\"pem\">RSA_CERT_B</Certificate>
                <Certificate format=\"pem\">RSA_CERT_C</Certificate>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>"""
        )

    @staticmethod
    def _payload_rsa_and_ecdsa() -> bytes:
        return normalize_xml_payload(
            b"""<AndroidAttestation>
    <Keybox>
        <Key algorithm=\"rsa\">
            <CertificateChain>
                <NumberOfCertificates>3</NumberOfCertificates>
                <Certificate format=\"pem\">RSA_CERT_A</Certificate>
                <Certificate format=\"pem\">RSA_CERT_B</Certificate>
                <Certificate format=\"pem\">RSA_CERT_C</Certificate>
            </CertificateChain>
        </Key>
        <Key algorithm=\"ecdsa\">
            <CertificateChain>
                <NumberOfCertificates>3</NumberOfCertificates>
                <Certificate format=\"pem\">ECDSA_CERT_A</Certificate>
                <Certificate format=\"pem\">ECDSA_CERT_B</Certificate>
                <Certificate format=\"pem\">ECDSA_CERT_C</Certificate>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>"""
        )

    @staticmethod
    def _payload_ecdsa_only() -> bytes:
        return normalize_xml_payload(
            b"""<AndroidAttestation>
    <Keybox>
        <Key algorithm=\"ecdsa\">
            <CertificateChain>
                <NumberOfCertificates>3</NumberOfCertificates>
                <Certificate format=\"pem\">ECDSA_ONLY_A</Certificate>
                <Certificate format=\"pem\">ECDSA_ONLY_B</Certificate>
                <Certificate format=\"pem\">ECDSA_ONLY_C</Certificate>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>"""
        )

    def test_registers_handlers_for_new_and_edited_messages(self):
        settings = Mock()
        validator = Mock()
        storage = Mock()
        userbot = KeyboxScavengerUserbot(settings=settings, validator=validator, storage=storage)
        client = FakeClient()
        userbot._handle_message = AsyncMock()

        userbot._register_handlers(client, [12345, "test-channel"])

        self.assertEqual(len(client.registered_handlers), 2)
        first_handler, first_builder = client.registered_handlers[0]
        second_handler, second_builder = client.registered_handlers[1]

        self.assertEqual(first_builder.__class__.__name__, "NewMessage")
        self.assertEqual(second_builder.__class__.__name__, "MessageEdited")

        fake_event = object()
        asyncio.run(first_handler(fake_event))
        asyncio.run(second_handler(fake_event))

        self.assertEqual(userbot._handle_message.await_count, 2)
        userbot._handle_message.assert_any_await(fake_event)

    def test_quarantine_moves_revoked_and_replaces_latest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            storage = KeyboxStorage(output_dir)

            revoked_payload = b"<keybox>revoked</keybox>"
            valid_payload = b"<keybox>valid</keybox>"
            latest_revoked_payload = b"<keybox>latest-revoked</keybox>"

            revoked_path = output_dir / "revoked-source.xml"
            valid_path = output_dir / "valid-source.xml"
            latest_path = output_dir / "keybox.xml"
            revoked_path.write_bytes(revoked_payload)
            valid_path.write_bytes(valid_payload)
            latest_path.write_bytes(latest_revoked_payload)

            validator = Mock()

            async def validate_payload(payload: bytes) -> ValidationResult:
                if payload == revoked_payload:
                    return ValidationResult(is_valid=False, revoked_serials=["revoked"])
                if payload == valid_payload:
                    return ValidationResult(is_valid=True)
                if payload == latest_revoked_payload:
                    return ValidationResult(is_valid=False, revoked_serials=["latest-revoked"])
                return ValidationResult(is_valid=False)

            validator.validate = AsyncMock(side_effect=validate_payload)
            validator.consume_revocation_update_flag = Mock(return_value=True)

            userbot = KeyboxScavengerUserbot(
                settings=Mock(),
                validator=validator,
                storage=storage,
            )

            moved_count, replaced_latest = asyncio.run(userbot._quarantine_revoked_keyboxes())

            self.assertEqual(moved_count, 1)
            self.assertTrue(replaced_latest)
            self.assertFalse(revoked_path.exists())
            self.assertTrue((output_dir / "revoked" / revoked_path.name).exists())
            self.assertEqual(latest_path.read_bytes(), valid_payload)

    def test_quarantine_keeps_latest_when_no_valid_replacement_exists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            storage = KeyboxStorage(output_dir)

            revoked_payload = b"<keybox>revoked</keybox>"
            latest_revoked_payload = b"<keybox>latest-revoked</keybox>"

            revoked_path = output_dir / "revoked-source.xml"
            latest_path = output_dir / "keybox.xml"
            revoked_path.write_bytes(revoked_payload)
            latest_path.write_bytes(latest_revoked_payload)

            validator = Mock()

            async def validate_payload(payload: bytes) -> ValidationResult:
                if payload == revoked_payload:
                    return ValidationResult(is_valid=False, revoked_serials=["revoked"])
                if payload == latest_revoked_payload:
                    return ValidationResult(is_valid=False, revoked_serials=["latest-revoked"])
                return ValidationResult(is_valid=False)

            validator.validate = AsyncMock(side_effect=validate_payload)
            validator.consume_revocation_update_flag = Mock(return_value=True)

            userbot = KeyboxScavengerUserbot(
                settings=Mock(),
                validator=validator,
                storage=storage,
            )

            moved_count, replaced_latest = asyncio.run(userbot._quarantine_revoked_keyboxes())

            self.assertEqual(moved_count, 1)
            self.assertFalse(replaced_latest)
            self.assertEqual(latest_path.read_bytes(), latest_revoked_payload)

    def test_maybe_handle_revocation_update_skips_without_flag(self):
        validator = Mock()
        validator.consume_revocation_update_flag = Mock(return_value=False)

        userbot = KeyboxScavengerUserbot(settings=Mock(), validator=validator, storage=Mock())
        userbot._quarantine_revoked_keyboxes = AsyncMock(return_value=(0, False))

        asyncio.run(userbot._maybe_handle_revocation_update())

        userbot._quarantine_revoked_keyboxes.assert_not_called()

    def test_superset_removes_existing_subset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            storage = KeyboxStorage(output_dir)

            subset_payload = self._payload_rsa_only()
            superset_payload = self._payload_rsa_and_ecdsa()

            existing_subset = storage.persist(subset_payload)

            validator = Mock()
            validator.validate = AsyncMock(return_value=ValidationResult(is_valid=True))
            validator.consume_revocation_update_flag = Mock(return_value=False)

            userbot = KeyboxScavengerUserbot(settings=Mock(max_xml_size=20 * 1024), validator=validator, storage=storage)

            asyncio.run(userbot._handle_message(FakeEvent(superset_payload)))

            expected_superset_digest = hashlib.md5(superset_payload).hexdigest()
            expected_superset_path = output_dir / f"{expected_superset_digest}.xml"

            self.assertFalse(existing_subset.digest_path.exists())
            self.assertTrue(expected_superset_path.exists())
            self.assertEqual((output_dir / "keybox.xml").read_bytes(), superset_payload)

    def test_subset_is_ignored_when_superset_exists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            storage = KeyboxStorage(output_dir)

            subset_payload = self._payload_rsa_only()
            superset_payload = self._payload_rsa_and_ecdsa()

            existing_superset = storage.persist(superset_payload)

            validator = Mock()
            validator.validate = AsyncMock(return_value=ValidationResult(is_valid=True))
            validator.consume_revocation_update_flag = Mock(return_value=False)

            userbot = KeyboxScavengerUserbot(settings=Mock(max_xml_size=20 * 1024), validator=validator, storage=storage)

            asyncio.run(userbot._handle_message(FakeEvent(subset_payload)))

            subset_digest = hashlib.md5(subset_payload).hexdigest()
            subset_path = output_dir / f"{subset_digest}.xml"

            self.assertFalse(subset_path.exists())
            self.assertTrue(existing_superset.digest_path.exists())
            self.assertEqual((output_dir / "keybox.xml").read_bytes(), superset_payload)
            self.assertEqual(userbot.stats.valid, 0)

    def test_unrelated_keybox_is_stored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            storage = KeyboxStorage(output_dir)

            rsa_payload = self._payload_rsa_only()
            ecdsa_payload = self._payload_ecdsa_only()

            existing_rsa = storage.persist(rsa_payload)

            validator = Mock()
            validator.validate = AsyncMock(return_value=ValidationResult(is_valid=True))
            validator.consume_revocation_update_flag = Mock(return_value=False)

            userbot = KeyboxScavengerUserbot(settings=Mock(max_xml_size=20 * 1024), validator=validator, storage=storage)

            asyncio.run(userbot._handle_message(FakeEvent(ecdsa_payload)))

            ecdsa_digest = hashlib.md5(ecdsa_payload).hexdigest()
            ecdsa_path = output_dir / f"{ecdsa_digest}.xml"

            self.assertTrue(existing_rsa.digest_path.exists())
            self.assertTrue(ecdsa_path.exists())
            self.assertEqual((output_dir / "keybox.xml").read_bytes(), ecdsa_payload)
            self.assertEqual(userbot.stats.valid, 1)


if __name__ == "__main__":
    unittest.main()
