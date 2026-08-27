from __future__ import annotations

import dataclasses
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
import sys

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from memory_vault_runtime import crypto_adapter, memory_network, sharing  # noqa: E402
from memory_vault_runtime.protocol import jcs_json_bytes, sha256_bytes  # noqa: E402


def _source_bundle(root: Path) -> tuple[Path, dict[str, dict]]:
    (episode_path, first_episode), (event_path, first_event) = memory_network.build_episode_packet(
        source_key_sha256="a" * 64,
        turn_key="b" * 32,
        source_sequence=0,
        prompt="增量同步保留可见证据。",
        assistant="已保存第一条记忆。",
        created_at="2026-08-16T00:00:00Z",
    )
    (second_episode_path, second_episode), (second_event_path, second_event) = memory_network.build_episode_packet(
        source_key_sha256="a" * 64,
        turn_key="c" * 32,
        source_sequence=1,
        prompt="选择性传输只应包含明确选择的记忆。",
        assistant="已保存第二条记忆。",
        created_at="2026-08-16T00:01:00Z",
        parent_episode_ids=[first_episode["episode_id"]],
    )
    values = {
        episode_path: jcs_json_bytes(first_episode),
        event_path: jcs_json_bytes(first_event),
        second_episode_path: jcs_json_bytes(second_episode),
        second_event_path: jcs_json_bytes(second_event),
    }
    entries = [
        {"path": path, "sha256": sha256_bytes(raw), "size": len(raw)}
        for path, raw in sorted(values.items())
    ]
    domain = {
        "schema_version": "memory-network-bundle/v1",
        "network_contract": "memory-network-graph/v1",
        "remote_commit_sha": "d" * 40,
        "exported_at": "2026-08-16T00:02:00Z",
        "native_conversation_ids_included": False,
        "credentials_included": False,
        "entries": entries,
    }
    manifest = {**domain, "network_sha256": sha256_bytes(jcs_json_bytes(domain))}
    source = root / "network.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("MANIFEST.json", jcs_json_bytes(manifest))
        for path, raw in sorted(values.items()):
            archive.writestr(path, raw)
    return source, {
        "first_episode": first_episode,
        "second_episode": second_episode,
        "first_event": first_event,
        "second_event": second_event,
    }


class SharingTests(unittest.TestCase):
    def test_selector_rejects_owner_fields_and_closes_relation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, documents = _source_bundle(root)
            with self.assertRaises(sharing.ShareError):
                sharing.parse_selector(
                    {
                        "schema_version": sharing.SELECTION_SCHEMA,
                        "evidence_ids": [],
                        "claim_keys": [],
                        "concepts": ["sync"],
                        "captured_after": None,
                        "captured_before": None,
                        "task_id": "never",
                    }
                )
            selector = sharing.ShareSelector(
                evidence_ids=(documents["second_episode"]["episode_id"],),
            )
            output = root / "selected.share.zip"
            summary = sharing.select_subgraph(source, output, selector)
            self.assertEqual(summary.episode_count, 2)
            self.assertEqual(summary.event_count, 2)
            verified = sharing.verify_share_bundle(output)
            self.assertEqual(dataclasses.asdict(summary), dataclasses.asdict(verified))
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                self.assertNotIn("sources", " ".join(names))
                manifest = json.loads(archive.read("MANIFEST.json"))
                self.assertFalse(manifest["task_fields_included"])
                self.assertFalse(manifest["credentials_included"])

    def test_concept_and_time_selection_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = _source_bundle(root)
            selector = sharing.parse_selector(
                {
                    "schema_version": sharing.SELECTION_SCHEMA,
                    "evidence_ids": [],
                    "claim_keys": [],
                    "concepts": ["选择性传输"],
                    "captured_after": "2026-08-16T00:00:30Z",
                    "captured_before": "2026-08-16T00:02:00Z",
                }
            )
            first = root / "first.share.zip"
            second = root / "second.share.zip"
            sharing.select_subgraph(source, first, selector)
            sharing.select_subgraph(source, second, selector)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            # The selected second episode pulls its continuity parent into the
            # evidence closure, so the encrypted share remains explainable.
            self.assertEqual(sharing.verify_share_bundle(first).episode_count, 2)

    def test_time_bounds_apply_even_when_concept_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, documents = _source_bundle(root)
            selector = sharing.parse_selector(
                {
                    "schema_version": sharing.SELECTION_SCHEMA,
                    "evidence_ids": [],
                    "claim_keys": [],
                    "concepts": ["记忆"],
                    "captured_after": "2026-08-16T00:00:00Z",
                    "captured_before": "2026-08-16T00:00:30Z",
                }
            )
            output = root / "bounded.share.zip"
            sharing.select_subgraph(source, output, selector)
            verified = sharing.verify_share_bundle(output)
            self.assertEqual(verified.episode_count, 1)
            self.assertEqual(verified.event_count, 1)
            with zipfile.ZipFile(output) as archive:
                self.assertIn(documents["first_episode"]["episode_id"], "".join(archive.namelist()))
                self.assertNotIn(documents["second_episode"]["episode_id"], "".join(archive.namelist()))

    def test_missing_relation_target_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, documents = _source_bundle(root)
            event = dict(documents["second_event"])
            event["parents"] = ["evt-" + ("e" * 40)]
            # Rebuild a source archive with the altered event and a matching
            # outer manifest; relation closure must still reject it.
            with zipfile.ZipFile(source) as archive:
                members = {name: archive.read(name) for name in archive.namelist()}
            event_name = next(name for name in members if name.endswith(documents["second_event"]["memory_event_id"] + ".json"))
            members[event_name] = jcs_json_bytes(event)
            manifest = json.loads(members["MANIFEST.json"])
            domain = dict(manifest)
            domain.pop("network_sha256")
            entries = []
            for name, raw in sorted(members.items()):
                if name == "MANIFEST.json":
                    continue
                entries.append({"path": name, "sha256": sha256_bytes(raw), "size": len(raw)})
            domain["entries"] = entries
            manifest = {**domain, "network_sha256": sha256_bytes(jcs_json_bytes(domain))}
            members["MANIFEST.json"] = jcs_json_bytes(manifest)
            altered = root / "altered.zip"
            with zipfile.ZipFile(altered, "w", compression=zipfile.ZIP_STORED) as output:
                for name, raw in sorted(members.items()):
                    output.writestr(name, raw)
            with self.assertRaises(sharing.ShareError):
                sharing.select_subgraph(
                    altered,
                    root / "should-not-exist.zip",
                    sharing.ShareSelector(evidence_ids=(documents["second_episode"]["episode_id"],)),
                )

    def test_source_owner_field_is_not_copied_into_share(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, documents = _source_bundle(root)
            with zipfile.ZipFile(source) as archive:
                members = {name: archive.read(name) for name in archive.namelist()}
            episode_name = next(
                name for name in members
                if name.endswith(documents["first_episode"]["episode_id"] + ".json")
            )
            episode = json.loads(members[episode_name])
            episode["task_id"] = "task-should-never-cross"
            members[episode_name] = jcs_json_bytes(episode)
            manifest = json.loads(members["MANIFEST.json"])
            domain = dict(manifest)
            domain.pop("network_sha256")
            domain["entries"] = [
                {"path": name, "sha256": sha256_bytes(raw), "size": len(raw)}
                for name, raw in sorted(members.items()) if name != "MANIFEST.json"
            ]
            members["MANIFEST.json"] = jcs_json_bytes(
                {**domain, "network_sha256": sha256_bytes(jcs_json_bytes(domain))}
            )
            altered = root / "owner-field.zip"
            with zipfile.ZipFile(altered, "w", compression=zipfile.ZIP_STORED) as output:
                for name, raw in sorted(members.items()):
                    output.writestr(name, raw)
            with self.assertRaises(sharing.ShareError):
                sharing.select_subgraph(
                    altered,
                    root / "owner-output.zip",
                    sharing.ShareSelector(evidence_ids=(documents["first_episode"]["episode_id"],)),
                )


class _TestProvider:
    info = crypto_adapter.ProviderInfo(
        profile="test-provider-fixture-v1",
        version="1.0.0",
        recipient_fingerprint="recipient:test",
    )

    def encrypt_to_file(self, plaintext: Path, ciphertext: Path, *, key_epoch: int) -> None:
        ciphertext.write_bytes(b"TEST-CIPHERTEXT\0" + plaintext.read_bytes())

    def decrypt_to_file(self, ciphertext: Path, plaintext: Path, *, key_epoch: int) -> None:
        raw = ciphertext.read_bytes()
        if not raw.startswith(b"TEST-CIPHERTEXT\0"):
            raise crypto_adapter.CryptoError("test provider ciphertext is invalid")
        plaintext.write_bytes(raw.removeprefix(b"TEST-CIPHERTEXT\0"))


class CryptoAdapterTests(unittest.TestCase):
    def test_unconfigured_provider_never_leaves_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plaintext = root / "plain.zip"
            plaintext.write_bytes(b"private plaintext")
            output = root / "share.memory"
            with self.assertRaises(crypto_adapter.CryptoUnavailable):
                crypto_adapter.seal_with_provider(
                    plaintext,
                    output,
                    crypto_adapter.UnconfiguredCryptoProvider(),
                    capability_scope_sha256="a" * 64,
                    key_epoch=1,
                )
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob("*.ciphertext.*")), [])

    def test_envelope_round_trip_and_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, documents = _source_bundle(root)
            share = root / "selected.share.zip"
            sharing.select_subgraph(
                source,
                share,
                sharing.ShareSelector(evidence_ids=(documents["second_episode"]["episode_id"],)),
            )
            envelope = root / "selected.share.enc"
            provider = _TestProvider()
            summary = crypto_adapter.seal_with_provider(
                share,
                envelope,
                provider,
                capability_scope_sha256="b" * 64,
                key_epoch=2,
            )
            header, epoch = crypto_adapter.read_envelope(envelope)
            self.assertEqual(epoch, 2)
            self.assertEqual(header["ciphertext_sha256"], summary.ciphertext_sha256)
            restored = root / "restored.share.zip"
            restored_summary = crypto_adapter.open_with_provider(envelope, restored, provider)
            self.assertEqual(restored_summary.object_count, 4)
            self.assertEqual(restored.read_bytes(), share.read_bytes())
            tampered = bytearray(envelope.read_bytes())
            tampered[-1] ^= 1
            envelope.write_bytes(tampered)
            with self.assertRaises(crypto_adapter.CryptoError):
                crypto_adapter.open_with_provider(envelope, root / "tampered-output.zip", provider)
            self.assertFalse((root / "tampered-output.zip").exists())

    def test_recipient_mismatch_rejects_before_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, documents = _source_bundle(root)
            share = root / "selected.share.zip"
            sharing.select_subgraph(source, share, sharing.ShareSelector(evidence_ids=(documents["first_episode"]["episode_id"],)))
            envelope = root / "selected.share.enc"
            crypto_adapter.seal_with_provider(share, envelope, _TestProvider(), capability_scope_sha256="c" * 64, key_epoch=1)
            wrong = _TestProvider()
            wrong.info = crypto_adapter.ProviderInfo("test-provider-fixture-v1", "1.0.0", "recipient:wrong")
            with self.assertRaises(crypto_adapter.CryptoError):
                crypto_adapter.open_with_provider(envelope, root / "wrong.zip", wrong)
            self.assertFalse((root / "wrong.zip").exists())


if __name__ == "__main__":
    unittest.main()
