from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET

from loguru import logger
from telethon import TelegramClient, events
from telethon.sessions import StringSession

from scavenger.config import ScavengerSettings
from scavenger.storage import KeyboxStorage
from scavenger.validator import KeyboxValidator
from scavenger.xml_normalizer import XmlNormalizationError, normalize_xml_payload

XML_MIME_TYPES = {"application/xml", "text/xml"}


@dataclass
class ScanStats:
    scanned: int = 0
    valid: int = 0
    invalid: int = 0
    skipped_non_xml: int = 0
    skipped_oversized: int = 0
    errors: int = 0


class KeyboxScavengerUserbot:
    def __init__(
        self,
        settings: ScavengerSettings,
        validator: KeyboxValidator,
        storage: KeyboxStorage,
    ):
        self.settings = settings
        self.validator = validator
        self.storage = storage
        self.stats = ScanStats()
        self._revocation_maintenance_lock = asyncio.Lock()
        self._revocation_refresh_stop = asyncio.Event()

    async def run(self) -> None:
        session = (
            StringSession(self.settings.session_string)
            if self.settings.session_string
            else self.settings.session_name
        )

        client = TelegramClient(
            session=session,
            api_id=self.settings.api_id,
            api_hash=self.settings.api_hash,
            request_retries=max(self.settings.network_retries, 1),
            connection_retries=max(self.settings.network_retries, 1),
            retry_delay=2,
        )

        await client.connect()
        if not await client.is_user_authorized():
            raise RuntimeError(
                "The Telegram session is not authorized. Set SCAVENGER_SESSION_STRING or use an authorized session file."
            )

        targets = await self._resolve_targets(client)
        if not targets:
            raise RuntimeError("No target chats resolved from SCAVENGER_TARGETS")

        await self._run_startup_revocation_maintenance()
        logger.info("Watching {} targets", len(targets))

        self._register_handlers(client, targets)

        self._revocation_refresh_stop.clear()
        refresh_task = asyncio.create_task(self._periodic_revocation_refresh())
        try:
            await client.run_until_disconnected()
        finally:
            self._revocation_refresh_stop.set()
            refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await refresh_task

    def _register_handlers(self, client: TelegramClient, targets: list) -> None:
        @client.on(events.NewMessage(chats=targets))
        async def on_new_message(event):
            await self._handle_message(event)

        @client.on(events.MessageEdited(chats=targets))
        async def on_edited_message(event):
            await self._handle_message(event)

        # Keep references so the callbacks are retained on the instance.
        self._on_new_message = on_new_message
        self._on_edited_message = on_edited_message

    async def _resolve_targets(self, client: TelegramClient) -> list:
        resolved = []
        for target in self.settings.monitored_targets:
            try:
                resolved_target = await client.get_input_entity(target)
                resolved.append(resolved_target)
                logger.info("Resolved target {}", target)
            except Exception as exc:
                self.stats.errors += 1
                logger.error("Failed to resolve target {}: {}", target, exc)
        return resolved

    async def _handle_message(self, event) -> None:
        message = event.message
        file_info = message.file
        if file_info is None:
            return

        mime_type = (file_info.mime_type or "").lower()
        file_name = (file_info.name or "").lower()

        is_xml = mime_type in XML_MIME_TYPES or file_name.endswith(".xml")
        if not is_xml:
            self.stats.skipped_non_xml += 1
            return

        file_size = file_info.size or 0
        if file_size > self.settings.max_xml_size:
            self.stats.skipped_oversized += 1
            logger.warning(
                "Skipping oversized XML chat={} message={} size={}",
                event.chat_id,
                message.id,
                file_size,
            )
            return

        try:
            payload = await event.client.download_media(message, bytes)
        except Exception as exc:
            self.stats.errors += 1
            logger.error(
                "Failed to download document chat={} message={}: {}",
                event.chat_id,
                message.id,
                exc,
            )
            return

        if payload is None:
            self.stats.errors += 1
            logger.error(
                "Download returned no payload chat={} message={}",
                event.chat_id,
                message.id,
            )
            return

        xml_payload = bytes(payload)
        try:
            normalized_xml_payload = normalize_xml_payload(xml_payload)
        except XmlNormalizationError as exc:
            logger.warning(
                "Skipping XML normalization chat={} message={} reason={}",
                event.chat_id,
                message.id,
                exc,
            )
            normalized_xml_payload = xml_payload

        self.stats.scanned += 1

        try:
            result = await self.validator.validate(normalized_xml_payload)
        except Exception as exc:
            self.stats.errors += 1
            logger.error(
                "Validation failed chat={} message={}: {}",
                event.chat_id,
                message.id,
                exc,
            )
            return

        await self._maybe_handle_revocation_update()

        if not result.is_valid:
            self.stats.invalid += 1
            logger.info(
                "Rejected keybox chat={} message={} reasons={}",
                event.chat_id,
                message.id,
                "; ".join(result.reasons) if result.reasons else "unknown",
            )
            return

        should_skip, subset_paths = self._classify_repository_overlap(normalized_xml_payload)
        if should_skip:
            logger.info(
                "Skipped keybox already included chat={} message={}",
                event.chat_id,
                message.id,
            )
            return

        for subset_path in subset_paths:
            try:
                subset_path.unlink()
                logger.info("Removed subset keybox {}", subset_path)
            except OSError as exc:
                logger.warning("Failed removing subset keybox {}: {}", subset_path, exc)

        storage_result = self.storage.persist(normalized_xml_payload)
        self.stats.valid += 1
        logger.info(
            "Stored valid keybox chat={} message={} digest={} new={} latest={}",
            event.chat_id,
            message.id,
            storage_result.digest,
            storage_result.wrote_digest_file,
            storage_result.latest_path,
        )

    async def _maybe_handle_revocation_update(self) -> None:
        if not self.validator.consume_revocation_update_flag():
            return

        async with self._revocation_maintenance_lock:
            moved_count, replaced_latest = await self._quarantine_revoked_keyboxes()
            logger.info(
                "Revocation update maintenance complete moved_revoked={} replaced_latest={}",
                moved_count,
                replaced_latest,
            )

    async def _periodic_revocation_refresh(self) -> None:
        interval = self.settings.revocation_refresh_seconds
        while not self._revocation_refresh_stop.is_set():
            try:
                await self.validator.refresh_revocation_status()
                await self._maybe_handle_revocation_update()
            except Exception as exc:
                logger.warning("Periodic revocation refresh failed: {}", exc)

            try:
                await asyncio.wait_for(self._revocation_refresh_stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    async def _run_startup_revocation_maintenance(self) -> None:
        async with self._revocation_maintenance_lock:
            try:
                moved_count, replaced_latest = await self._quarantine_revoked_keyboxes()
            except Exception as exc:
                logger.warning("Startup revocation maintenance failed: {}", exc)
                return

            if moved_count or replaced_latest:
                logger.info(
                    "Startup revocation maintenance complete moved_revoked={} replaced_latest={}",
                    moved_count,
                    replaced_latest,
                )
            else:
                logger.info("Startup revocation maintenance complete with no changes")

    async def _quarantine_revoked_keyboxes(self) -> tuple[int, bool]:
        output_dir = self.storage.output_dir
        revoked_dir = output_dir / "revoked"
        revoked_dir.mkdir(parents=True, exist_ok=True)

        candidate_payloads: list[tuple[float, bytes]] = []
        moved_count = 0

        for keybox_path in self._repository_keyboxes(output_dir):
            try:
                payload = keybox_path.read_bytes()
            except OSError as exc:
                logger.warning("Failed to read keybox {}: {}", keybox_path, exc)
                continue

            try:
                result = await self.validator.validate(payload)
            except Exception as exc:
                logger.warning("Failed to validate keybox {}: {}", keybox_path, exc)
                continue

            if result.revoked_serials:
                destination = self._next_revoked_destination(revoked_dir, keybox_path)
                keybox_path.replace(destination)
                moved_count += 1
                logger.warning("Moved revoked keybox {} to {}", keybox_path, destination)
                continue

            if result.is_valid:
                candidate_payloads.append((keybox_path.stat().st_mtime, payload))

        latest_path = output_dir / "keybox.xml"
        replaced_latest = False
        if latest_path.exists():
            try:
                latest_payload = latest_path.read_bytes()
                latest_result = await self.validator.validate(latest_payload)
            except Exception as exc:
                logger.warning("Failed to validate latest keybox {}: {}", latest_path, exc)
            else:
                if latest_result.revoked_serials:
                    replacement_payload = self._select_replacement_payload(candidate_payloads)
                    if replacement_payload is not None:
                        self.storage.persist(replacement_payload)
                        replaced_latest = True

        return moved_count, replaced_latest

    @staticmethod
    def _repository_keyboxes(output_dir: Path) -> list[Path]:
        return sorted(
            [
                path
                for path in output_dir.glob("*.xml")
                if path.is_file() and path.name != "keybox.xml"
            ]
        )

    def _classify_repository_overlap(self, incoming_payload: bytes) -> tuple[bool, list[Path]]:
        incoming_signatures = self._extract_key_signatures(incoming_payload)
        if not incoming_signatures:
            return False, []

        existing: list[tuple[Path, set[tuple[str, tuple[str, ...]]]]] = []
        for path in self._repository_keyboxes(self.storage.output_dir):
            try:
                signatures = self._extract_key_signatures(path.read_bytes())
            except OSError as exc:
                logger.warning("Failed reading keybox {}: {}", path, exc)
                continue

            if signatures:
                existing.append((path, signatures))

        for _, signatures in existing:
            if incoming_signatures <= signatures:
                return True, []

        subset_paths = [
            path for path, signatures in existing if signatures < incoming_signatures
        ]
        return False, subset_paths

    @staticmethod
    def _extract_key_signatures(payload: bytes) -> set[tuple[str, tuple[str, ...]]]:
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            logger.warning("Failed to parse keybox XML for overlap detection: {}", exc)
            return set()

        signatures: set[tuple[str, tuple[str, ...]]] = set()
        for keybox in root.findall(".//Keybox"):
            for key in keybox.findall("Key"):
                algorithm = (key.get("algorithm") or "").strip().lower()
                certificate_chain = tuple(
                    KeyboxScavengerUserbot._normalize_key_material(certificate.text)
                    for certificate in key.findall('.//Certificate[@format="pem"]')
                    if certificate.text
                )
                if certificate_chain:
                    signatures.add((algorithm, certificate_chain))

        return signatures

    @staticmethod
    def _normalize_key_material(raw_text: str) -> str:
        return "\n".join(line.strip() for line in raw_text.splitlines() if line.strip())

    @staticmethod
    def _next_revoked_destination(revoked_dir: Path, source_path: Path) -> Path:
        destination = revoked_dir / source_path.name
        if not destination.exists():
            return destination

        stem = source_path.stem
        suffix = source_path.suffix
        index = 1
        while True:
            candidate = revoked_dir / f"{stem}.{index}{suffix}"
            if not candidate.exists():
                return candidate
            index += 1

    @staticmethod
    def _select_replacement_payload(candidate_payloads: list[tuple[float, bytes]]) -> bytes | None:
        if not candidate_payloads:
            return None
        candidate_payloads.sort(key=lambda item: item[0], reverse=True)
        return candidate_payloads[0][1]
