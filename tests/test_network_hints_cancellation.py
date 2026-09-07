"""Real-crypto, synthetic established-query cancellation on existing state."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import os
import stat
import hashlib
import threading
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network import NetworkClient
from memory_vault_storage import StorageError
import memory_vault_network_recovery as recovery
from tests.test_network_hints import CONTENT_SCHEMA, control, policy, remember, query_offer, select_pending, outbox_row
from tests.test_network_hints_pagination import sessions
from tests.test_network_message_semantics import agent, records, proofs, vault_snapshot, inject_ciphertext
from tests.test_network_recovery import archive
from tests.test_network_worker import fixture


def session(endpoint, query_id):
    return strict_json_loads(sessions(endpoint)["hint-session:" + query_id])


def cancel_control(query, offer, page):
    return control("cancel", query_message_id=query["message_id"], offer_message_id=offer["message_id"],
                   expires_at=page["expires_at"])


def cancel(endpoint, owner, query, offer, page, suffix="initial"):
    return endpoint.send("req_hint_cancel_" + suffix, [owner.identity.key_id],
                         control=cancel_control(query, offer, page))


def established(test, owner, requester, transport, suffix="initial", *, short_offer=False):
    mid = remember(test, owner, transport, "cancel_" + suffix, "Synthetic needle cancellation " + suffix)
    owner.set_hint_policy(policy(owner, requester, [mid], [mid],
        expires_at=int(time.time()) + 120 if short_offer else None))
    query, offer, page = query_offer(test, owner, requester, transport, suffix="cancel_" + suffix)
    return mid, query, offer, page


def outbox_count(endpoint):
    with endpoint.db() as db:
        return db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]


class HintCancellationTests(unittest.TestCase):
    def assert_cancelled(self, endpoint, query, result, offer, page):
        self.assertEqual(result["cancellation"], {"query_message_id": query["message_id"], "local_cancelled": True})
        saved = session(endpoint, query["message_id"])
        self.assertEqual(saved["schema_version"], "memory-vault-hint-session/v2")
        self.assertEqual(saved["state"], "cancelled")
        self.assertEqual(saved["cancellation"], {"message_id": result["message_id"],
            "offer_message_id": offer["message_id"], "expires_at": page["expires_at"]})

    def test_offline_local_cancel_is_immediate_idempotent_isolated_and_explicit_ack_survives_revocation(self):
        with fixture() as (owner, requester, transport):
            mid, query, offer, page = established(self, owner, requester, transport, short_offer=True)
            other, other_offer, other_page = query_offer(self, owner, requester, transport, suffix="independent")
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            original_session = session(requester, query["message_id"])
            self.assertLess(page["expires_at"], original_session["expires_at"])
            transport.offline.update([*owner.relays, owner.authority_url])
            result = cancel(requester, owner, query, offer, page)
            self.assertEqual(result["stored_nodes"], 0)
            self.assertTrue(result["errors"])
            self.assert_cancelled(requester, query, result, offer, page)
            self.assertEqual(session(requester, query["message_id"])["expires_at"], original_session["expires_at"])
            self.assertEqual(session(owner, query["message_id"])["state"], "active")
            self.assertEqual(session(requester, other["message_id"])["state"], "active")
            count, cancelled = outbox_count(requester), sessions(requester)
            again = cancel(requester, owner, query, offer, page)
            self.assertEqual(again["message_id"], result["message_id"])
            self.assertEqual(again["cancellation"], result["cancellation"])
            with self.assertRaises(MemoryError) as duplicate:
                cancel(requester, owner, query, offer, page, suffix="different_id")
            self.assertEqual(duplicate.exception.code, "network_hint_not_available")
            self.assertEqual(outbox_count(requester), count)
            self.assertEqual(sessions(requester), cancelled)
            transport.offline.clear()
            # The unrelated query remains usable under the same local policy.
            select_pending(self, owner, requester, other_offer, mid, suffix="uncancelled")
            sent = cancel(requester, owner, query, offer, page)
            self.assertEqual(sent["stored_nodes"], 2)
            self.assertFalse(owner.receive()["errors"])
            self.assertEqual(session(owner, query["message_id"])["state"], "active", "receipt is not owner processing")
            owner.set_hint_policy(policy(owner, requester, [], [], revision=2))
            ack = owner.respond_to(sent["message_id"])
            self.assertEqual(ack["cancellation"], result["cancellation"])
            self.assertEqual(session(owner, query["message_id"])["cancellation"]["message_id"], sent["message_id"])
            self.assertEqual(session(owner, other["message_id"])["state"], "active")
            self.assertFalse(requester.receive()["errors"])
            self.assertEqual(requester.read_message(ack["message_id"])["control"], control("cancel_ack",
                request_message_id=sent["message_id"], query_message_id=query["message_id"], expires_at=page["expires_at"]))
            frozen = outbox_row(owner, ack["message_id"])
            repeated = owner.respond_to(sent["message_id"])
            self.assertEqual(repeated["message_id"], ack["message_id"])
            self.assertEqual(outbox_row(owner, ack["message_id"])["envelope"], frozen["envelope"])
            self.assertEqual(requester.receive()["messages"], [])
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_optional_wal_disappearance_is_tolerated_but_unsafe_or_replaced_names_are_rejected(self):
        import memory_vault_network as network
        with fixture() as (owner, requester, transport):
            _, query, _, _ = established(self, owner, requester, transport)
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            original_sessions = sessions(requester)
            sidecar = requester.directory / "network.sqlite3-wal"
            self.assertFalse(sidecar.exists())
            self.assertFalse(sidecar.is_symlink())
            sidecar.write_bytes(b"")
            sidecar.chmod(0o600)
            open_target, open_attribute = (network.os, "open") if os.name == "posix" else (network, "open_file")
            original_open, disappeared = getattr(open_target, open_attribute), []
            def remove_optional_before_real_open(path, flags, *args, **kwargs):
                if Path(path) == sidecar and not disappeared:
                    disappeared.append(True)
                    sidecar.unlink()
                return original_open(path, flags, *args, **kwargs)
            with patch.object(open_target, open_attribute, side_effect=remove_optional_before_real_open):
                with requester.db() as db:
                    self.assertIsNotNone(db.execute("SELECT value FROM state WHERE key='configuration_binding'").fetchone())
            self.assertEqual(disappeared, [True])
            self.assertEqual(sessions(requester), original_sessions)
            self.assertEqual(session(requester, query["message_id"])["state"], "active")
            target = requester.directory / "synthetic-never-read-aux-target"
            for fault in ("dangling", "hardlink", "permissions", "dangling_after_enoent"):
                with self.subTest(fault=fault):
                    self.assertFalse(sidecar.exists())
                    self.assertFalse(sidecar.is_symlink())
                    self.assertFalse(target.exists())
                    if fault == "dangling":
                        sidecar.symlink_to(target)
                    elif fault == "hardlink":
                        target.write_bytes(b"Synthetic target must remain untouched.")
                        target.chmod(0o600)
                        os.link(target, sidecar)
                    else:
                        sidecar.write_bytes(b"")
                        sidecar.chmod(0o644 if fault == "permissions" else 0o600)
                    target_before = target.read_bytes() if target.exists() else None
                    replacements = []
                    def replace_name_after_real_enoent(path, flags, *args, **kwargs):
                        if Path(path) == sidecar and not replacements:
                            replacements.append(True)
                            sidecar.unlink()
                            try:
                                return original_open(path, flags, *args, **kwargs)
                            except FileNotFoundError:
                                # The failed open is real, but a new dangling
                                # entry now occupies its name. Absence cannot be
                                # inferred from the earlier ENOENT alone.
                                sidecar.symlink_to(target)
                                raise
                        return original_open(path, flags, *args, **kwargs)
                    try:
                        with patch.object(network.sqlite3, "connect", side_effect=AssertionError("unsafe sidecar reached SQLite")):
                            if fault == "dangling_after_enoent":
                                with patch.object(open_target, open_attribute, side_effect=replace_name_after_real_enoent):
                                    with self.assertRaises(FileNotFoundError):
                                        with requester.db():
                                            self.fail("replaced optional name was ignored")
                                self.assertEqual(replacements, [True])
                            else:
                                with self.assertRaises(OSError) as rejected:
                                    with requester.db():
                                        self.fail("unsafe optional file was ignored")
                                if fault == "hardlink":
                                    self.assertEqual(rejected.exception.code, "unsafe_storage_file")
                                elif fault == "permissions":
                                    self.assertEqual(rejected.exception.code, "unprotected_private_file")
                        self.assertEqual(target.read_bytes() if target.exists() else None, target_before)
                    finally:
                        sidecar.unlink()
                        if target.exists():
                            target.unlink()
            self.assertEqual(sessions(requester), original_sessions)
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_opened_optional_sidecar_unlink_is_safe_only_for_private_unreplaced_regular_files(self):
        import memory_vault_network as network
        if os.name != "posix":
            self.skipTest("This regression exercises POSIX descriptor unlink semantics; native Windows gates are unchanged")
        with fixture() as (owner, requester, transport):
            _, query, _, _ = established(self, owner, requester, transport)
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            original_sessions = sessions(requester)
            sidecar = requester.directory / "network.sqlite3-wal"
            target = requester.directory / "synthetic-retained-sidecar-target"
            real_open = os.open
            for entry in ("db", "_read_transport"):
                for fault in ("safe_unlink", "unsafe_unlink", "hardlink", "symlink", "dangling", "replaced", "other_error"):
                    with self.subTest(entry=entry, fault=fault):
                        self.assertFalse(sidecar.exists() or sidecar.is_symlink())
                        self.assertFalse(target.exists())
                        if fault in {"hardlink", "symlink"}:
                            target.write_bytes(b"Synthetic target must stay unchanged.")
                            target.chmod(0o600)
                        if fault == "hardlink":
                            os.link(target, sidecar)
                        elif fault in {"symlink", "dangling"}:
                            sidecar.symlink_to(target)
                        else:
                            sidecar.write_bytes(b"")
                            sidecar.chmod(0o644 if fault == "unsafe_unlink" else 0o600)
                        target_before = target.read_bytes() if target.exists() else None
                        opened, unlinked = [], []
                        def unlink_after_actual_open(path, flags, *args, **kwargs):
                            descriptor = real_open(path, flags, *args, **kwargs)
                            if Path(path) == sidecar and not opened:
                                opened.append(descriptor)
                                actual = os.fstat(descriptor)
                                self.assertTrue(stat.S_ISREG(actual.st_mode))
                                self.assertEqual(actual.st_uid, os.getuid())
                                if fault in {"safe_unlink", "unsafe_unlink", "replaced", "other_error"}:
                                    self.assertEqual(actual.st_nlink, 1)
                                    self.assertEqual(actual.st_mode & 0o777, 0o644 if fault == "unsafe_unlink" else 0o600)
                                    sidecar.unlink()
                                    self.assertEqual(os.fstat(descriptor).st_nlink, 0)
                                    unlinked.append(True)
                                    if fault == "replaced":
                                        replacement = real_open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                                        try:
                                            os.write(replacement, b"Synthetic replacement must not reach SQLite.")
                                        finally:
                                            os.close(replacement)
                            return descriptor
                        try:
                            with patch.object(network.os, "open", side_effect=unlink_after_actual_open):
                                if fault == "safe_unlink":
                                    with getattr(requester, entry)() as database:
                                        self.assertIsNotNone(database.execute("SELECT value FROM state WHERE key='configuration_binding'").fetchone())
                                    self.assertEqual(unlinked, [True])
                                else:
                                    with patch.object(network.sqlite3, "connect", side_effect=AssertionError("unsafe opened sidecar reached SQLite")):
                                        if fault == "other_error":
                                            # A typed error outside the exact safe
                                            # nlink-zero condition must propagate.
                                            original_check = network.check_fd
                                            def unrelated_storage_error(descriptor, **kwargs):
                                                if descriptor in opened:
                                                    raise StorageError("synthetic_storage_denied")
                                                return original_check(descriptor, **kwargs)
                                            with patch.object(network, "check_fd", side_effect=unrelated_storage_error):
                                                with self.assertRaises(StorageError) as rejected:
                                                    with getattr(requester, entry)():
                                                        self.fail("unrelated storage error was swallowed")
                                            self.assertEqual(rejected.exception.code, "synthetic_storage_denied")
                                        else:
                                            with self.assertRaises(OSError) as rejected:
                                                with getattr(requester, entry)():
                                                    self.fail("unsafe opened optional file was ignored")
                                            if fault in {"unsafe_unlink", "hardlink", "replaced"}:
                                                self.assertIsInstance(rejected.exception, StorageError)
                                    if fault in {"unsafe_unlink", "replaced", "other_error"}:
                                        self.assertEqual(unlinked, [True])
                                self.assertEqual(target.read_bytes() if target.exists() else None, target_before)
                                if fault == "replaced":
                                    self.assertEqual(sidecar.read_bytes(), b"Synthetic replacement must not reach SQLite.")
                        finally:
                            sidecar.unlink(missing_ok=True)
                            target.unlink(missing_ok=True)
            self.assertEqual(sessions(requester), original_sessions)
            self.assertEqual(session(requester, query["message_id"])["state"], "active")
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_postcommit_storage_failure_preserves_cancellation_but_reports_notification_delivery_unknown(self):
        for role in ("requester", "owner"):
            with self.subTest(role=role), fixture() as (owner, requester, transport):
                _, query, offer, page = established(self, owner, requester, transport)
                before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
                # Reproduce the observed typed SQLite sidecar failure at the
                # delivery refresh boundary. The preceding local transaction,
                # bindings, policy and crypto setup remain the real code paths.
                endpoint = requester if role == "requester" else owner
                if role == "owner":
                    notification = cancel(requester, owner, query, offer, page)
                    self.assertFalse(owner.receive()["errors"])
                count = outbox_count(endpoint)
                with patch.object(endpoint, "_refresh_bound", side_effect=StorageError("unsafe_storage_file")):
                    result = (cancel(requester, owner, query, offer, page) if role == "requester"
                              else owner.respond_to(notification["message_id"]))
                self.assertEqual(result["state"], "delivery_unknown")
                self.assertEqual(result["errors"], [{"code": "unsafe_storage_file", "retryable": False}])
                self.assertEqual(result["cancellation"], {"query_message_id": query["message_id"], "local_cancelled": True})
                self.assertEqual(result["content_kind"], "hint_control")
                self.assertIsNone(result["text_memory_id"])
                self.assertTrue(result["retry_same_request_id"])
                self.assertFalse(result["understood"])
                for unavailable in ("stored_nodes", "validated_recipients", "endpoint_validated"):
                    self.assertNotIn(unavailable, result)
                self.assertEqual(outbox_count(endpoint), count + 1)
                marker = session(endpoint, query["message_id"])
                self.assertEqual(marker["state"], "cancelled")
                self.assertEqual(marker["cancellation"]["message_id"],
                                 result["message_id"] if role == "requester" else notification["message_id"])
                durable = outbox_row(endpoint, result["message_id"])
                self.assertIsNone(durable["envelope"])
                self.assertEqual([vault_snapshot(item) for item in (owner, requester)], before)
                retried = (cancel(requester, owner, query, offer, page) if role == "requester"
                           else owner.respond_to(notification["message_id"]))
                self.assertEqual(retried["message_id"], result["message_id"])
                self.assertEqual(retried["stored_nodes"], 2)
                self.assertEqual(outbox_count(endpoint), count + 1)

    def test_capacity_and_request_conflict_roll_back_cancellation_and_notification_together(self):
        with fixture() as (owner, requester, transport):
            _, query, offer, page = established(self, owner, requester, transport)
            before, count, calls = sessions(requester), outbox_count(requester), len(transport.calls)
            with patch("memory_vault_network.MAX_QUEUE_BYTES", 0):
                with self.assertRaises(MemoryError) as full:
                    cancel(requester, owner, query, offer, page)
            self.assertEqual(full.exception.code, "network_outbox_capacity")
            self.assertEqual(sessions(requester), before)
            self.assertEqual(outbox_count(requester), count)
            with self.assertRaises(MemoryError) as conflict:
                requester.send("req_hint_query_cancel_initial", [owner.identity.key_id],
                               control=cancel_control(query, offer, page))
            self.assertEqual(conflict.exception.code, "network_request_id_conflict")
            self.assertEqual(sessions(requester), before)
            self.assertEqual(outbox_count(requester), count)
            self.assertEqual(len(transport.calls), calls)
            notification = cancel(requester, owner, query, offer, page)
            self.assert_cancelled(requester, query, notification, offer, page)
            self.assertFalse(owner.receive()["errors"])
            owner_before, owner_count = sessions(owner), outbox_count(owner)
            with patch("memory_vault_network.MAX_QUEUE_BYTES", 0):
                with self.assertRaises(MemoryError) as ack_full:
                    owner.respond_to(notification["message_id"])
            self.assertEqual(ack_full.exception.code, "network_outbox_capacity")
            self.assertEqual(sessions(owner), owner_before)
            self.assertEqual(outbox_count(owner), owner_count)
            acknowledged = owner.respond_to(notification["message_id"])
            self.assertEqual(acknowledged["cancellation"], notification["cancellation"])
            self.assertEqual(session(owner, query["message_id"])["state"], "cancelled")

    def test_local_cancel_does_not_wait_behind_started_unrelated_http(self):
        with fixture() as (owner, requester, transport):
            _, query, offer, page = established(self, owner, requester, transport)
            started, release = threading.Event(), threading.Event()
            original = transport.request
            def blocked_request(base, method, path, value=None):
                if path == "/v1/messages" and not started.is_set():
                    started.set()
                    if not release.wait(5):
                        raise AssertionError("test did not release synthetic in-flight HTTP")
                return original(base, method, path, value)
            with patch.object(transport, "request", side_effect=blocked_request), ThreadPoolExecutor(max_workers=2) as pool:
                running = pool.submit(requester.send, "req_cancel_unrelated_inflight", [owner.identity.key_id], "Synthetic ordinary chat already started.")
                try:
                    self.assertTrue(started.wait(3))
                    local = pool.submit(cancel, requester, owner, query, offer, page, "during_http")
                    result = local.result(timeout=3)
                    self.assert_cancelled(requester, query, result, offer, page)
                    self.assertFalse(running.done(), "held HTTP should still be running")
                finally:
                    release.set()
                self.assertEqual(running.result(timeout=3)["stored_nodes"], 2)

    def test_authenticated_late_batch_is_rejected_without_changing_existing_memories_or_receipts(self):
        with fixture() as (owner, requester, transport):
            previous = remember(self, owner, transport, "cancel_previous", "Synthetic previously shared persistent evidence.")
            owner.send("req_cancel_previous_share", [requester.identity.key_id], memory_ids=[previous])
            self.assertFalse(requester.receive()["errors"])
            mid, query, offer, page = established(self, owner, requester, transport)
            selected = select_pending(self, owner, requester, offer, mid, suffix="late_cancel")
            transferred = owner.respond_to(selected["message_id"])
            before = vault_snapshot(requester)
            original, original_proofs = records(requester), proofs(requester)
            result = cancel(requester, owner, query, offer, page)
            self.assert_cancelled(requester, query, result, offer, page)
            # The sender and share are valid. Session cancellation alone must
            # stop admission before opening/importing any Vault.
            with patch("memory_vault_sharing.import_share", side_effect=AssertionError("late batch opened Vault")):
                received = requester.receive()
            self.assertFalse(received["errors"], received)
            message, = received["messages"]
            self.assertEqual(message["message_id"], transferred["message_id"])
            self.assertEqual(message["state"], "rejected")
            self.assertEqual(vault_snapshot(requester), before)
            self.assertEqual(records(requester), original)
            self.assertEqual(proofs(requester), original_proofs)
            with requester.db() as db:
                self.assertIsNone(db.execute("SELECT 1 FROM inbox WHERE message_id=?", (transferred["message_id"],)).fetchone())
                self.assertIsNotNone(db.execute("SELECT 1 FROM quarantine WHERE message_id=?", (transferred["message_id"],)).fetchone())
            self.assertEqual(requester.receive()["messages"], [])
            self.assertFalse(owner.receive()["errors"])
            with owner.db() as db:
                self.assertIsNone(db.execute("SELECT 1 FROM acknowledgements WHERE message_id=?", (transferred["message_id"],)).fetchone())

    def test_cancelled_pending_batch_does_not_starve_live_query_and_retains_frozen_bytes(self):
        with fixture() as (owner, requester, transport):
            mid, query, offer, page = established(self, owner, requester, transport)
            other, other_offer, _ = query_offer(self, owner, requester, transport, suffix="live_pump")
            selected = select_pending(self, owner, requester, offer, mid, suffix="stopped_pump")
            live_selected = select_pending(self, owner, requester, other_offer, mid, suffix="live_pump")
            transport.offline.add(owner.relays[1])
            pending = owner.respond_to(selected["message_id"])
            frozen = outbox_row(owner, pending["message_id"])
            self.assertEqual(pending["stored_nodes"], 1)
            transport.offline.clear()
            notification = cancel(requester, owner, query, offer, page)
            self.assertFalse(owner.receive()["errors"])
            transport.offline.update(owner.relays)
            live = owner.respond_to(live_selected["message_id"])
            ack = owner.respond_to(notification["message_id"])
            self.assertEqual(ack["stored_nodes"], 0)
            self.assertEqual(live["stored_nodes"], 0)
            transport.offline.clear()
            with NetworkClient(owner.config_path, transport=transport) as restarted:
                before_calls = len(transport.calls)
                stopped = restarted.respond_to(selected["message_id"])
                self.assertEqual(stopped["state"], "stopped_query")
                self.assertEqual(len(transport.calls), before_calls)
                pumped = restarted.pump(maximum_messages=2, receive_limit=0)
                self.assertGreaterEqual(pumped["stopped_query_messages"], 1)
                self.assertEqual(outbox_row(restarted, live["message_id"])["envelope"] is not None, True)
                self.assertEqual(len(strict_json_loads(outbox_row(restarted, live["message_id"])["receipts"])), 2)
                for field in ("body", "envelope", "receipts"):
                    self.assertEqual(outbox_row(restarted, pending["message_id"])[field], frozen[field])
            received = requester.receive()
            self.assertFalse(received["errors"], received)
            by_id = {item["message_id"]: item for item in received["messages"]}
            self.assertEqual(by_id[live["message_id"]]["state"], "validated_saved")
            self.assertEqual(by_id[pending["message_id"]]["state"], "rejected")
            self.assertEqual(session(requester, other["message_id"])["state"], "active")

    def test_wrong_cancel_and_ack_bindings_cannot_cancel_or_confirm_another_session(self):
        with fixture() as (owner, requester, transport):
            _, query, offer, page = established(self, owner, requester, transport)
            other, other_offer, other_page = query_offer(self, owner, requester, transport, suffix="binding_other")
            valid = cancel_control(query, offer, page)
            variants = [(requester, {**valid, "query_message_id": other["message_id"]}),
                (requester, {**valid, "offer_message_id": "msg_" + "f" * 64}),
                (requester, {**valid, "expires_at": page["expires_at"] - 1}),
                (requester, {**valid, "expires_at": page["expires_at"] + 1}), (owner, valid)]
            before, policy_before = sessions(owner), (owner.directory / "hint-policy.json").read_bytes()
            memories = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            for index, (sender, value) in enumerate(variants):
                identifier = "msg_" + hashlib.sha256(("wrong-cancel-" + str(index)).encode()).hexdigest()
                inject_ciphertext(sender, owner, canonical_bytes({"schema_version": CONTENT_SCHEMA,
                    "kind": "hint_control", "control": value}), identifier)
                self.assertFalse(owner.receive()["errors"])
                response = owner.respond_to(identifier)
                body = strict_json_loads(outbox_row(owner, response["message_id"])["body"])
                self.assertEqual(body["control"], control("refusal", request_message_id=identifier, reason="not_available"))
                self.assertEqual(sessions(owner), before)
                self.assertFalse(requester.receive()["errors"])
            self.assertEqual((owner.directory / "hint-policy.json").read_bytes(), policy_before)
            notification = cancel(requester, owner, query, offer, page)
            self.assertFalse(owner.receive()["errors"])
            ack = control("cancel_ack", request_message_id=notification["message_id"],
                          query_message_id=query["message_id"], expires_at=page["expires_at"])
            bad_acks = [(owner, {**ack, "query_message_id": other["message_id"]}),
                        (owner, {**ack, "expires_at": page["expires_at"] - 1}),
                        (owner, {**ack, "request_message_id": "msg_" + "e" * 64}), (requester, ack)]
            for index, (sender, value) in enumerate(bad_acks):
                identifier = "msg_" + hashlib.sha256(("wrong-ack-" + str(index)).encode()).hexdigest()
                inject_ciphertext(sender, requester, canonical_bytes({"schema_version": CONTENT_SCHEMA,
                    "kind": "hint_control", "control": value}), identifier)
                received = requester.receive()
                self.assertFalse(received["errors"], received)
                self.assertEqual(received["messages"][0]["state"], "rejected")
                with requester.db() as db:
                    self.assertIsNone(db.execute("SELECT 1 FROM inbox WHERE message_id=?", (identifier,)).fetchone())
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], memories)
            self.assertEqual(session(requester, other["message_id"])["state"], "active")
            actual = owner.respond_to(notification["message_id"])
            self.assertFalse(requester.receive()["errors"])
            self.assertEqual(requester.read_message(actual["message_id"])["control"], ack)

    def test_restart_keeps_cancelled_state_and_encrypted_recovery_never_revives_cancel_or_batch(self):
        with fixture() as (owner, requester, transport):
            mid, query, offer, page = established(self, owner, requester, transport)
            select_pending(self, owner, requester, offer, mid, suffix="recovery_pending")
            transport.offline.update([*owner.relays, owner.authority_url])
            notification = cancel(requester, owner, query, offer, page)
            preserved = outbox_row(requester, notification["message_id"])
            with NetworkClient(requester.config_path, transport=transport) as restarted:
                self.assert_cancelled(restarted, query, notification, offer, page)
                self.assertEqual(cancel(restarted, owner, query, offer, page)["message_id"], notification["message_id"])
            before = sessions(requester)
            report, args = archive(requester)
            self.assertFalse(report["hint_sessions_included"])
            self.assertEqual(sessions(requester), before)
            restored = recovery.restore_endpoint(directory=requester.config_path.parent.parent / "cancel-restored", **args)
            with NetworkClient(Path(restored["network_config"]), transport=transport) as recovered:
                self.assertEqual(sessions(recovered), {})
                self.assertEqual(records(recovered), records(requester))
                transport.offline.clear()
                calls = len(transport.calls)
                recovered.pump(receive_limit=0)
                self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls[calls:]))
                self.assertEqual(sessions(recovered), {})
                for field in ("body", "envelope"):
                    self.assertEqual(outbox_row(recovered, notification["message_id"])[field], preserved[field])
                fresh, _, _ = query_offer(self, owner, recovered, transport, suffix="fresh_after_cancel_restore")
                self.assertEqual(session(recovered, fresh["message_id"])["state"], "active")
                self.assertNotIn("hint-session:" + query["message_id"], sessions(recovered))

    def test_cancel_between_real_parse_and_final_admission_rejects_but_started_admission_preserves_history(self):
        import memory_vault_sharing as sharing
        for winner in ("cancel", "admission"):
            with self.subTest(winner=winner), fixture() as (owner, requester, transport):
                mid, query, offer, page = established(self, owner, requester, transport)
                selected = select_pending(self, owner, requester, offer, mid, suffix="race")
                transferred = owner.respond_to(selected["message_id"])
                before = vault_snapshot(requester)
                if winner == "cancel":
                    original_scan, cancelled = sharing._scan, []
                    def cancel_after_real_scan(*args, **kwargs):
                        parsed = original_scan(*args, **kwargs)
                        if not cancelled:
                            cancelled.append(cancel(requester, owner, query, offer, page, "after_scan"))
                        return parsed
                    with patch.object(sharing, "_scan", side_effect=cancel_after_real_scan), patch.object(
                            sharing, "import_share", side_effect=AssertionError("cancel won but Vault admission started")):
                        result = requester.receive()
                    self.assertEqual(len(cancelled), 1)
                    self.assertFalse(result["errors"], result)
                    self.assertEqual(result["messages"][0]["state"], "rejected")
                    self.assertEqual(vault_snapshot(requester), before)
                else:
                    entered, release, cancel_started = threading.Event(), threading.Event(), threading.Event()
                    original_import = sharing.import_share
                    def paused_real_import(*args, **kwargs):
                        entered.set()
                        if not release.wait(3):
                            raise AssertionError("test did not release protected synthetic admission")
                        return original_import(*args, **kwargs)
                    def competing_cancel():
                        cancel_started.set()
                        return cancel(requester, owner, query, offer, page, "during_admission")
                    with patch.object(sharing, "import_share", side_effect=paused_real_import), ThreadPoolExecutor(max_workers=2) as pool:
                        receiving = pool.submit(requester.receive)
                        try:
                            self.assertTrue(entered.wait(3))
                            cancellation = pool.submit(competing_cancel)
                            self.assertTrue(cancel_started.wait(1))
                            # The public cancellation has started; its LOCAL
                            # commit must wait for protected admission. Checking
                            # the persisted state also catches an early commit
                            # hidden behind a slower notification HTTP request.
                            with self.assertRaises(TimeoutError):
                                cancellation.result(timeout=0.1)
                            # A plain read-only observer avoids the endpoint
                            # helper's separate initialization writer reservation.
                            with closing(sqlite3.connect((requester.directory / "network.sqlite3").as_uri() + "?mode=ro", uri=True)) as observer:
                                raw = observer.execute("SELECT value FROM state WHERE key=?",
                                    ("hint-session:" + query["message_id"],)).fetchone()[0]
                            self.assertEqual(strict_json_loads(raw)["state"], "active")
                        finally:
                            release.set()
                        result = receiving.result(timeout=4)
                        cancelled = cancellation.result(timeout=4)
                    self.assertFalse(result["errors"], result)
                    self.assertEqual(result["messages"][0]["state"], "validated_saved")
                    self.assert_cancelled(requester, query, cancelled, offer, page)
                    self.assertIn(mid, records(requester))
                    snapshot = vault_snapshot(requester)
                    self.assertEqual(requester.read_message(transferred["message_id"])["state"], "validated_saved")
                    self.assertEqual(requester.receive()["messages"], [])
                    self.assertEqual(vault_snapshot(requester), snapshot)


if __name__ == "__main__":
    unittest.main()
