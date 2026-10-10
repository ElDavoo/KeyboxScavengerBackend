from __future__ import annotations

import asyncio
import contextlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

from loguru import logger
from telethon import TelegramClient, events, utils
from telethon.sessions import StringSession
from telethon.tl.types import Channel

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


@dataclass
class KeyboxCandidate:
    payload: bytes
    is_rkp: bool
    is_complete: bool
    expiration: datetime | None
    mtime_ns: int


@dataclass
class PollTarget:
    entity: object
    label: str
    peer_id: int


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
        self._polling_stop = asyncio.Event()
        self._expiration_watch_stop = asyncio.Event()
        self._expiration_schedule_changed = asyncio.Event()
        self._next_expiration: datetime | None = None

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

        targets, poll_targets = await self._resolve_targets(client)
        if not targets:
            raise RuntimeError("No target chats resolved from SCAVENGER_TARGETS")

        await self._run_startup_revocation_maintenance()
        logger.info("Watching {} targets", len(targets))

        self._register_handlers(client, targets)

        polling_task = None
        if poll_targets and self.settings.unsubscribed_poll_seconds > 0:
            logger.info(
                "Polling {} non-subscribed targets every {}s",
                len(poll_targets),
                self.settings.unsubscribed_poll_seconds,
            )
            self._polling_stop.clear()
            polling_task = asyncio.create_task(
                self._poll_unsubscribed_targets(client, poll_targets)
            )
        elif poll_targets:
            logger.info("Polling disabled for {} non-subscribed targets", len(poll_targets))

        self._revocation_refresh_stop.clear()
        refresh_task = asyncio.create_task(self._periodic_revocation_refresh())
        self._expiration_watch_stop.clear()
        expiration_task = asyncio.create_task(self._watch_expirations())
        try:
            await client.run_until_disconnected()
        finally:
            self._polling_stop.set()
            self._revocation_refresh_stop.set()
            self._expiration_watch_stop.set()
            for task in (refresh_task, expiration_task):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if polling_task is not None:
                polling_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await polling_task

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

    async def _resolve_targets(self, client: TelegramClient) -> tuple[list, list[PollTarget]]:
        resolved = []
        poll_targets: list[PollTarget] = []
        for target in self.settings.monitored_targets:
            try:
                entity = await client.get_entity(target)
                resolved.append(entity)
                label = self._format_target_label(target, entity)
                if self._requires_polling(entity):
                    poll_targets.append(
                        PollTarget(
                            entity=entity,
                            label=label,
                            peer_id=utils.get_peer_id(entity),
                        )
                    )
                    logger.info("Resolved target {} (polling enabled)", label)
                else:
                    logger.info("Resolved target {}", label)
            except Exception as exc:
                self.stats.errors += 1
                logger.error("Failed to resolve target {}: {}", target, exc)
        return resolved, poll_targets

    @staticmethod
    def _requires_polling(entity: object) -> bool:
        return isinstance(entity, Channel) and bool(entity.left)

    @staticmethod
    def _format_target_label(target: object, entity: object) -> str:
        title = getattr(entity, "title", None)
        if title:
            return str(title)
        username = getattr(entity, "username", None)
        if username:
            return f"@{username}"
        return str(target)

    async def _handle_message(self, event) -> None:
        await self._handle_message_payload(event.client, event.message, event.chat_id)

    async def _handle_message_payload(self, client: TelegramClient, message, chat_id: int | None) -> None:
        resolved_chat_id = chat_id if chat_id is not None else getattr(message, "chat_id", None)
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
                resolved_chat_id,
                message.id,
                file_size,
            )
            return

        try:
            payload = await client.download_media(message, bytes)
        except Exception as exc:
            self.stats.errors += 1
            logger.error(
                "Failed to download document chat={} message={}: {}",
                resolved_chat_id,
                message.id,
                exc,
            )
            return

        if payload is None:
            self.stats.errors += 1
            logger.error(
                "Download returned no payload chat={} message={}",
                resolved_chat_id,
                message.id,
            )
            return

        xml_payload = bytes(payload)
        try:
            normalized_xml_payload = normalize_xml_payload(xml_payload)
        except XmlNormalizationError as exc:
            logger.warning(
                "Skipping XML normalization chat={} message={} reason={}",
                resolved_chat_id,
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
                resolved_chat_id,
                message.id,
                exc,
            )
            return

        await self._maybe_handle_revocation_update()

        if not result.is_valid:
            self.stats.invalid += 1
            logger.info(
                "Rejected keybox chat={} message={} reasons={}",
                resolved_chat_id,
                message.id,
                "; ".join(result.reasons) if result.reasons else "unknown",
            )
            return

        should_skip, subset_paths = self._classify_repository_overlap(normalized_xml_payload)
        if should_skip:
            logger.info(
                "Skipped keybox already included chat={} message={}",
                resolved_chat_id,
                message.id,
            )
            return

        for subset_path in subset_paths:
            try:
                subset_path.unlink()
                logger.info("Removed subset keybox {}", subset_path)
            except OSError as exc:
                logger.warning("Failed removing subset keybox {}: {}", subset_path, exc)

        digest, _, wrote_digest_file = self.storage.persist_digest(normalized_xml_payload)
        self.stats.valid += 1

        async with self._revocation_maintenance_lock:
            _, replaced_latest = await self._run_keybox_maintenance()

        logger.info(
            "Stored valid keybox chat={} message={} digest={} new={} rkp={} banned={} replaced_latest={}",
            resolved_chat_id,
            message.id,
            digest,
            wrote_digest_file,
            result.is_rkp,
            result.has_banned_serial,
            replaced_latest,
        )

    async def _poll_unsubscribed_targets(
        self,
        client: TelegramClient,
        targets: list[PollTarget],
    ) -> None:
        interval = self.settings.unsubscribed_poll_seconds
        last_seen: dict[int, int | None] = {}
        for target in targets:
            last_seen[target.peer_id] = await self._prime_last_seen(client, target)

        while not self._polling_stop.is_set():
            for target in targets:
                cursor = last_seen.get(target.peer_id)
                if cursor is None:
                    last_seen[target.peer_id] = await self._prime_last_seen(client, target)
                    continue

                try:
                    cursor_value = cursor
                    async for message in client.iter_messages(
                        target.entity,
                        min_id=cursor,
                        reverse=True,
                    ):
                        if message.id is None or message.id <= cursor_value:
                            continue
                        last_seen[target.peer_id] = max(last_seen[target.peer_id] or 0, message.id)
                        await self._handle_message_payload(
                            client,
                            message,
                            getattr(message, "chat_id", None) or target.peer_id,
                        )
                except Exception as exc:
                    logger.warning("Polling failed for {}: {}", target.label, exc)

            try:
                await asyncio.wait_for(self._polling_stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    async def _prime_last_seen(
        self,
        client: TelegramClient,
        target: PollTarget,
    ) -> int | None:
        try:
            async for message in client.iter_messages(target.entity, limit=1):
                if message.id is not None:
                    return message.id
        except Exception as exc:
            logger.warning("Failed to prime polling cursor for {}: {}", target.label, exc)
        return None

    async def _maybe_handle_revocation_update(self) -> None:
        if not self.validator.consume_revocation_update_flag():
            return

        async with self._revocation_maintenance_lock:
            moved_count, replaced_latest = await self._run_keybox_maintenance()
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
                removed_count = self._deduplicate_repository()
            except Exception as exc:
                logger.warning("Startup repository deduplication failed: {}", exc)
            else:
                if removed_count:
                    logger.info("Startup deduplication removed {} redundant keyboxes", removed_count)

            try:
                moved_count, replaced_latest = await self._run_keybox_maintenance()
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

    async def _watch_expirations(self) -> None:
        while not self._expiration_watch_stop.is_set():
            self._expiration_schedule_changed.clear()
            timeout = self._seconds_until_next_expiration()
            try:
                await asyncio.wait_for(self._expiration_schedule_changed.wait(), timeout=timeout)
                continue
            except asyncio.TimeoutError:
                pass

            try:
                async with self._revocation_maintenance_lock:
                    moved_count, replaced_latest = await self._run_keybox_maintenance()
                logger.info(
                    "Expiration maintenance complete moved={} replaced_latest={}",
                    moved_count,
                    replaced_latest,
                )
            except Exception as exc:
                logger.warning("Expiration maintenance failed: {}", exc)
                # Avoid a hot loop if maintenance keeps failing on an already-past expiration.
                await asyncio.sleep(60)

    def _seconds_until_next_expiration(self) -> float | None:
        if self._next_expiration is None:
            return None
        remaining = (self._next_expiration - datetime.now(timezone.utc)).total_seconds()
        # Wake slightly after the expiration so the validator sees the certificate as expired.
        return max(remaining, 0) + 1

    async def _run_keybox_maintenance(self) -> tuple[int, bool]:
        output_dir = self.storage.output_dir
        revoked_dir = output_dir / "revoked"
        revoked_dir.mkdir(parents=True, exist_ok=True)

        candidates: list[KeyboxCandidate] = []
        expirations: list[datetime] = []
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

            if result.revoked_serials or result.has_expired_certificate:
                destination = self._next_revoked_destination(revoked_dir, keybox_path)
                keybox_path.replace(destination)
                moved_count += 1
                logger.warning(
                    "Moved {} keybox {} to {}",
                    "revoked" if result.revoked_serials else "expired",
                    keybox_path,
                    destination,
                )
                continue

            if not result.is_valid:
                continue

            # Banned keyboxes stay in the repository (and still expire), but never become keybox.xml.
            if result.nearest_expiration_date is not None:
                expirations.append(result.nearest_expiration_date)
            if not result.has_banned_serial:
                candidates.append(
                    KeyboxCandidate(
                        payload=payload,
                        is_rkp=result.is_rkp,
                        is_complete=self._is_complete_keybox(payload),
                        expiration=result.nearest_expiration_date,
                        mtime_ns=keybox_path.stat().st_mtime_ns,
                    )
                )

        self._next_expiration = min(expirations) if expirations else None
        self._expiration_schedule_changed.set()

        replaced_latest = False
        best = self._select_latest_candidate(candidates)
        if best is not None:
            replaced_latest = self.storage.write_latest(best.payload)

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

    def _deduplicate_repository(self) -> int:
        """Re-normalize stored keyboxes and drop the ones another stored keybox already covers.

        Keyboxes stored by older versions may differ only in PEM wrapping or a tampered
        algorithm label, which defeated both the digest file names and overlap detection.
        """
        output_dir = self.storage.output_dir
        entries: dict[Path, tuple[float, set[tuple[str, ...]]]] = {}
        removed_count = 0

        for path in self._repository_keyboxes(output_dir):
            if path in entries:
                # Already produced by re-normalizing an earlier file.
                continue

            try:
                payload = path.read_bytes()
                mtime = path.stat().st_mtime
                normalized = normalize_xml_payload(payload)
            except (OSError, XmlNormalizationError) as exc:
                logger.warning("Skipping keybox {} during deduplication: {}", path, exc)
                continue

            if normalized != payload:
                _, normalized_path, wrote_digest_file = self.storage.persist_digest(normalized)
                if normalized_path != path:
                    path.unlink()
                    logger.info("Re-normalized keybox {} as {}", path, normalized_path)
                    if not wrote_digest_file:
                        removed_count += 1
                        mtime = max(mtime, normalized_path.stat().st_mtime)
                    os.utime(normalized_path, (mtime, mtime))
                    path = normalized_path

            signatures = self._extract_key_signatures(normalized)
            if signatures:
                entries[path] = (mtime, signatures)

        # Largest and newest first, so the keybox that survives is the most complete one.
        ordered = sorted(entries.items(), key=lambda item: (len(item[1][1]), item[1][0]), reverse=True)
        kept: list[set[tuple[str, ...]]] = []
        for path, (_, signatures) in ordered:
            if any(signatures <= kept_signatures for kept_signatures in kept):
                path.unlink()
                removed_count += 1
                logger.info("Removed redundant keybox {}", path)
                continue
            kept.append(signatures)

        latest_path = output_dir / "keybox.xml"
        if latest_path.exists():
            try:
                latest_payload = latest_path.read_bytes()
                normalized_latest = normalize_xml_payload(latest_payload)
            except (OSError, XmlNormalizationError) as exc:
                logger.warning("Failed to re-normalize latest keybox {}: {}", latest_path, exc)
            else:
                if normalized_latest != latest_payload:
                    self.storage.write_latest(normalized_latest)

        return removed_count

    def _classify_repository_overlap(self, incoming_payload: bytes) -> tuple[bool, list[Path]]:
        incoming_signatures = self._extract_key_signatures(incoming_payload)
        if not incoming_signatures:
            return False, []

        existing: list[tuple[Path, set[tuple[str, ...]]]] = []
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
    def _extract_key_signatures(payload: bytes) -> set[tuple[str, ...]]:
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            logger.warning("Failed to parse keybox XML for overlap detection: {}", exc)
            return set()

        # A key is identified by its certificate chain alone: the algorithm label is
        # derivable from the chain and is sometimes tampered with in reposted keyboxes.
        signatures: set[tuple[str, ...]] = set()
        for keybox in root.findall(".//Keybox"):
            for key in keybox.findall("Key"):
                certificate_chain = tuple(
                    KeyboxScavengerUserbot._normalize_key_material(certificate.text)
                    for certificate in key.findall('.//Certificate[@format="pem"]')
                    if certificate.text
                )
                if certificate_chain:
                    signatures.add(certificate_chain)

        return signatures

    @staticmethod
    def _normalize_key_material(raw_text: str) -> str:
        # Compare only the PEM body so line wrapping cannot make identical material look distinct.
        return "".join(
            line.strip()
            for line in raw_text.splitlines()
            if line.strip() and not line.strip().startswith("-----")
        )

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
    def _is_complete_keybox(payload: bytes) -> bool:
        # Stored payloads are normalized, so the algorithm label is derived from the key material.
        try:
            root = ET.fromstring(payload)
        except ET.ParseError:
            return False
        algorithms = {
            (key.get("algorithm") or "").strip().lower()
            for key in root.findall(".//Keybox/Key")
        }
        return {"ecdsa", "rsa"} <= algorithms

    @staticmethod
    def _select_latest_candidate(candidates: list[KeyboxCandidate]) -> KeyboxCandidate | None:
        # Priority: RKP first, then complete (ecdsa + rsa), then the soonest expiration.
        # Ties go to the most recently stored keybox.
        if not candidates:
            return None
        return min(
            candidates,
            key=lambda candidate: (
                not candidate.is_rkp,
                not candidate.is_complete,
                candidate.expiration or datetime.max.replace(tzinfo=timezone.utc),
                -candidate.mtime_ns,
            ),
        )
