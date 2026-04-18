from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock

from scavenger.models import ValidationResult
from scavenger.storage import KeyboxStorage
from scavenger.userbot import KeyboxScavengerUserbot


class FakeClient:
    def __init__(self):
        self.registered_handlers = []

    def on(self, event_builder):
        def decorator(handler):
            self.registered_handlers.append((handler, event_builder))
            return handler

        return decorator


class KeyboxScavengerUserbotTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
