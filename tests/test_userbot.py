from __future__ import annotations

import asyncio
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock

from scavenger.models import ValidationResult
from scavenger.storage import KeyboxStorage
from scavenger.userbot import KeyboxCandidate, KeyboxScavengerUserbot
from scavenger.xml_normalizer import normalize_xml_payload
from tests.keybox_factory import generate_key_pems, keybox_xml, unwrap_pem


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

            moved_count, replaced_latest = asyncio.run(userbot._run_keybox_maintenance())

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

            moved_count, replaced_latest = asyncio.run(userbot._run_keybox_maintenance())

            self.assertEqual(moved_count, 1)
            self.assertFalse(replaced_latest)
            self.assertEqual(latest_path.read_bytes(), latest_revoked_payload)

    def test_maybe_handle_revocation_update_skips_without_flag(self):
        validator = Mock()
        validator.consume_revocation_update_flag = Mock(return_value=False)

        userbot = KeyboxScavengerUserbot(settings=Mock(), validator=validator, storage=Mock())
        userbot._run_keybox_maintenance = AsyncMock(return_value=(0, False))

        asyncio.run(userbot._maybe_handle_revocation_update())

        userbot._run_keybox_maintenance.assert_not_called()

    def test_startup_revocation_maintenance_runs_quarantine(self):
        validator = Mock()
        validator.consume_revocation_update_flag = Mock(return_value=False)

        userbot = KeyboxScavengerUserbot(settings=Mock(), validator=validator, storage=Mock())
        userbot._run_keybox_maintenance = AsyncMock(return_value=(0, False))

        asyncio.run(userbot._run_startup_revocation_maintenance())

        userbot._run_keybox_maintenance.assert_awaited_once()

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

    def test_reformatted_copy_of_stored_keybox_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            ecdsa_pem, rsa_pem = generate_key_pems()

            # Simulate a keybox stored before PEM bodies and algorithms were canonicalized.
            legacy_path = output_dir / "legacy.xml"
            legacy_path.write_bytes(keybox_xml(unwrap_pem(ecdsa_pem), unwrap_pem(rsa_pem)))
            storage = KeyboxStorage(output_dir)

            validator = Mock()
            validator.validate = AsyncMock(return_value=ValidationResult(is_valid=True))
            validator.consume_revocation_update_flag = Mock(return_value=False)

            userbot = KeyboxScavengerUserbot(settings=Mock(max_xml_size=20 * 1024), validator=validator, storage=storage)

            asyncio.run(userbot._handle_message(FakeEvent(keybox_xml(ecdsa_pem, rsa_pem, rsa_algorithm="@evokerr"))))

            self.assertEqual(sorted(path.name for path in output_dir.glob("*.xml")), ["legacy.xml"])
            self.assertEqual(userbot.stats.valid, 0)

    def test_repository_deduplication_collapses_reformatted_copies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            ecdsa_pem, rsa_pem = generate_key_pems()
            other_ecdsa_pem, other_rsa_pem = generate_key_pems()

            (output_dir / "single_line.xml").write_bytes(keybox_xml(unwrap_pem(ecdsa_pem), unwrap_pem(rsa_pem)))
            (output_dir / "wrapped.xml").write_bytes(keybox_xml(ecdsa_pem, rsa_pem))
            (output_dir / "tampered.xml").write_bytes(keybox_xml(ecdsa_pem, rsa_pem, rsa_algorithm="@evokerr"))
            (output_dir / "unrelated.xml").write_bytes(keybox_xml(other_ecdsa_pem, other_rsa_pem))
            (output_dir / "keybox.xml").write_bytes(keybox_xml(ecdsa_pem, rsa_pem, rsa_algorithm="@evokerr"))

            storage = KeyboxStorage(output_dir)
            userbot = KeyboxScavengerUserbot(settings=Mock(), validator=Mock(), storage=storage)

            removed = userbot._deduplicate_repository()

            canonical = normalize_xml_payload(keybox_xml(ecdsa_pem, rsa_pem))
            other_canonical = normalize_xml_payload(keybox_xml(other_ecdsa_pem, other_rsa_pem))
            self.assertEqual(removed, 2)
            self.assertEqual(
                sorted(path.name for path in output_dir.glob("*.xml")),
                sorted(
                    [
                        "keybox.xml",
                        f"{hashlib.md5(canonical).hexdigest()}.xml",
                        f"{hashlib.md5(other_canonical).hexdigest()}.xml",
                    ]
                ),
            )
            self.assertEqual((output_dir / "keybox.xml").read_bytes(), canonical)

    def test_startup_maintenance_deduplicates_before_quarantine(self):
        userbot = KeyboxScavengerUserbot(settings=Mock(), validator=Mock(), storage=Mock())
        calls = []
        userbot._deduplicate_repository = Mock(side_effect=lambda: calls.append("dedup") or 0)

        async def quarantine():
            calls.append("quarantine")
            return 0, False

        userbot._run_keybox_maintenance = quarantine

        asyncio.run(userbot._run_startup_revocation_maintenance())

        self.assertEqual(calls, ["dedup", "quarantine"])

    def test_select_latest_candidate_priority(self):
        soon = datetime(2026, 10, 21, tzinfo=timezone.utc)
        later = datetime(2032, 1, 1, tzinfo=timezone.utc)

        def candidate(name: str, is_rkp: bool, is_complete: bool, expiration, mtime_ns: int = 0):
            return KeyboxCandidate(
                payload=name.encode(),
                is_rkp=is_rkp,
                is_complete=is_complete,
                expiration=expiration,
                mtime_ns=mtime_ns,
            )

        select = KeyboxScavengerUserbot._select_latest_candidate

        rkp_incomplete = candidate("rkp-incomplete", True, False, later)
        factory_complete = candidate("factory-complete", False, True, soon)
        self.assertIs(select([factory_complete, rkp_incomplete]), rkp_incomplete)

        complete_late = candidate("complete-late", False, True, later)
        incomplete_soon = candidate("incomplete-soon", False, False, soon)
        self.assertIs(select([incomplete_soon, complete_late]), complete_late)

        complete_soon = candidate("complete-soon", False, True, soon)
        self.assertIs(select([complete_late, complete_soon]), complete_soon)

        older = candidate("older", False, True, later, mtime_ns=1)
        newer = candidate("newer", False, True, later, mtime_ns=2)
        self.assertIs(select([older, newer]), newer)

        self.assertIsNone(select([]))

    def test_is_complete_keybox_requires_ecdsa_and_rsa(self):
        self.assertTrue(KeyboxScavengerUserbot._is_complete_keybox(self._payload_rsa_and_ecdsa()))
        self.assertFalse(KeyboxScavengerUserbot._is_complete_keybox(self._payload_rsa_only()))
        self.assertFalse(KeyboxScavengerUserbot._is_complete_keybox(self._payload_ecdsa_only()))

    def test_maintenance_moves_expired_keybox_and_replaces_latest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            storage = KeyboxStorage(output_dir)

            expired_payload = b"<keybox>expired</keybox>"
            valid_payload = b"<keybox>valid</keybox>"
            valid_expiration = datetime(2032, 1, 1, tzinfo=timezone.utc)

            expired_path = output_dir / "expired-source.xml"
            valid_path = output_dir / "valid-source.xml"
            latest_path = output_dir / "keybox.xml"
            expired_path.write_bytes(expired_payload)
            valid_path.write_bytes(valid_payload)
            latest_path.write_bytes(expired_payload)

            validator = Mock()

            async def validate_payload(payload: bytes) -> ValidationResult:
                if payload == expired_payload:
                    return ValidationResult(is_valid=False, has_expired_certificate=True)
                if payload == valid_payload:
                    return ValidationResult(is_valid=True, nearest_expiration_date=valid_expiration)
                return ValidationResult(is_valid=False)

            validator.validate = AsyncMock(side_effect=validate_payload)

            userbot = KeyboxScavengerUserbot(settings=Mock(), validator=validator, storage=storage)

            moved_count, replaced_latest = asyncio.run(userbot._run_keybox_maintenance())

            self.assertEqual(moved_count, 1)
            self.assertTrue(replaced_latest)
            self.assertFalse(expired_path.exists())
            self.assertTrue((output_dir / "revoked" / expired_path.name).exists())
            self.assertEqual(latest_path.read_bytes(), valid_payload)
            self.assertEqual(userbot._next_expiration, valid_expiration)

    def test_new_non_rkp_keybox_does_not_replace_rkp_latest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            storage = KeyboxStorage(output_dir)

            rkp_payload = self._payload_ecdsa_only()
            factory_payload = self._payload_rsa_and_ecdsa()
            storage.persist(rkp_payload)

            validator = Mock()

            async def validate_payload(payload: bytes) -> ValidationResult:
                return ValidationResult(is_valid=True, is_rkp=payload == rkp_payload)

            validator.validate = AsyncMock(side_effect=validate_payload)
            validator.consume_revocation_update_flag = Mock(return_value=False)

            userbot = KeyboxScavengerUserbot(settings=Mock(max_xml_size=20 * 1024), validator=validator, storage=storage)

            asyncio.run(userbot._handle_message(FakeEvent(factory_payload)))

            factory_path = output_dir / f"{hashlib.md5(factory_payload).hexdigest()}.xml"
            self.assertTrue(factory_path.exists())
            self.assertEqual((output_dir / "keybox.xml").read_bytes(), rkp_payload)
            self.assertEqual(userbot.stats.valid, 1)

    def test_seconds_until_next_expiration(self):
        userbot = KeyboxScavengerUserbot(settings=Mock(), validator=Mock(), storage=Mock())
        self.assertIsNone(userbot._seconds_until_next_expiration())

        userbot._next_expiration = datetime.now(timezone.utc) - timedelta(hours=1)
        self.assertEqual(userbot._seconds_until_next_expiration(), 1)

        userbot._next_expiration = datetime.now(timezone.utc) + timedelta(hours=1)
        self.assertAlmostEqual(userbot._seconds_until_next_expiration(), 3601, delta=5)


if __name__ == "__main__":
    unittest.main()
