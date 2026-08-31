"""One temporary, unsigned v0.21 migration workflow; NOT RUN while authored.

Frozen contract: v0.21.0 / 030ed411ed9ddb969a03f0b5caec87dac9b0dd57,
plugins/memory-vault-sync/scripts/memory_vault_runtime/{packs,checkpoint,core}.py.
The fixture independently encodes the inspected old frame/index/footer and
integer-only, ASCII-key checksum domain. It is synthetic, not an old runtime
execution, a private export, an authenticated author or an independently
implemented consumer. The current pack/checkpoint/conversion/extraction,
canonical import, alias registration, views and host remember paths run without
replacing their validators, graph projection, database or admission behavior.

Only safety guards and the temporary scratch root are patched. All configured
data paths are inside one resolved TemporaryDirectory; no account, identity,
trust, sync, plugin, native host, subprocess or network is used. This small
workflow does not establish large-pack, cryptographic or cross-device parity.
Any execution result must be recorded separately against its exact source.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_compat as compat
import memory_vault_legacy_pack as packs
from memory_vault import AUTHORITY, MemoryError, Vault, canonical_bytes
from memory_vault_client import CONFIG_SCHEMA, ClientConfig


def fixture_bytes(value: object) -> bytes:
    # Every fixture object key is ASCII; values use only the old safe integer,
    # string, bool and null domain. No encoder from the converter is reused.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def fixture_hash(value: object) -> str:
    return hashlib.sha256(fixture_bytes(value)).hexdigest()


def fixture_episode(number: int, *, second: int, parent: dict | None = None) -> dict:
    timestamp = f"2026-01-01T00:00:{second:02d}Z"
    value = {
        "schema_version": "memory-episode/v1", "episode_id": "ep-" + format(number, "040x"),
        "source_id": "src-" + "a" * 40, "source_sequence": number,
        "parent_episode_ids": [] if parent is None else [parent["episode_id"]],
        "captured_at": timestamp, "created_at": timestamp, "coverage": "partial_active_turn",
        "included_content": ["visible user prompt", "visible final assistant message"],
        "excluded_content": ["hidden reasoning", "credentials", "native conversation identifiers"],
        "messages": [
            {"ordinal": 0, "role": "user", "phase": "unknown", "text": f"  Synthetic migration round {number}: 中文\n\n"},
            {"ordinal": 1, "role": "assistant", "phase": "final_answer", "text": "Keep historical memory independent of tasks."},
        ],
        "hash_profile": "jcs-rfc8785+sha256/episode-v1",
    }
    value["episode_sha256"] = fixture_hash(value)
    return value


def fixture_event(anchor: dict, *, second: int, kind: str, statement: str = "",
                  continuity: bool = False, **relations: list[str]) -> dict:
    references = {name: list(relations.get(name, [])) for name in ("parents", "supersedes", "conflicts_with", "resolves")}
    claim_key = None if continuity else "storage-direction"
    if continuity:
        payload = {"memory_form": "episodic", "profile": "memory-network-episode-event/v1",
                   "message_count": 2, "roles": ["user", "assistant"],
                   "continuity": "continues" if references["parents"] else "origin"}
        identity = "evt-" + hashlib.sha256(
            ("episode\0" + anchor["source_id"] + "\0" + anchor["episode_id"]).encode("utf-8")
        ).hexdigest()[:40]
    else:
        payload = {"profile": "memory-network-semantic/v1",
                   "claim": {"statement": statement, "reason": None, "concepts": ["memory", "continuity"]}}
        identity = "evt-" + fixture_hash({"source_id": anchor["source_id"], "episode_id": anchor["episode_id"],
                                        "kind": kind, "claim_key": claim_key, **references, "payload": payload})[:40]
    value = {
        "schema_version": "memory-event/v2", "memory_event_id": identity, "kind": kind,
        "confidence": "source_explicit" if continuity else "assistant_inferred",
        "source": {"source_id": anchor["source_id"], "revision_id": anchor["episode_id"],
                   "source_sequence": anchor["source_sequence"], "evidence_anchor_sha256": anchor["episode_sha256"]},
        "claim_key": claim_key, **references, "payload": payload, "payload_sha256": fixture_hash(payload),
        "hash_profile": "jcs-rfc8785+sha256/event-v2", "created_at": f"2026-01-01T00:00:{second:02d}Z",
    }
    value["event_sha256"] = fixture_hash(value)
    return value


def fixture_members(documents: list[dict]) -> dict[str, bytes]:
    members = {}
    for value in documents:
        if value["schema_version"] == "memory-episode/v1":
            identity = value["episode_id"]
            path = f"memory/episodes/{identity[3:5]}/{identity}.json"
        else:
            identity = value["memory_event_id"]
            path = f"memory/events/{identity[4:6]}/{identity}.json"
        members[path] = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    manifest = {
        "schema_version": "memory-network-bundle/v1", "network_contract": "memory-network-graph/v1",
        "remote_commit_sha": "b" * 40, "exported_at": "2026-01-01T01:00:00Z",
        "native_conversation_ids_included": False, "credentials_included": False,
        "entries": [{"path": path, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                    for path, raw in sorted(members.items())],
    }
    manifest["network_sha256"] = fixture_hash(manifest)
    members["MANIFEST.json"] = fixture_bytes(manifest) + b"\n"
    return members


def fixture_pack(members: dict[str, bytes]) -> bytes:
    output = bytearray(b"memory-pack/v1\n")
    entries = []
    for path, raw in sorted(members.items()):
        compressed = zlib.compress(raw, level=6)
        header = {"path": path, "sha256": hashlib.sha256(raw).hexdigest(),
                  "raw_size": len(raw), "compressed_size": len(compressed)}
        entries.append({**header, "offset": len(output)})
        encoded = fixture_bytes(header)
        output.extend(struct.pack(">I", len(encoded)) + encoded + compressed)
    index = fixture_bytes({"schema_version": "memory-pack-index/v1", "entries": entries})
    output.extend(index + struct.pack(">Q", len(index)) + b"memory-pack-index/v1\n")
    return bytes(output)


@unittest.skipUnless(os.name == "posix", "this protected-storage fixture targets POSIX")
class LegacyWorkflowTests(unittest.TestCase):
    def test_checkpoint_chain_conversion_preserves_claims_and_reusable_old_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-v025-legacy-workflow-") as directory:
            root = Path(directory).resolve()
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            config_path, vault_path = root / "client.json", root / "vault.sqlite3"
            config_path.write_bytes(fixture_bytes({"schema_version": CONFIG_SCHEMA,
                                                  "vault_path": str(vault_path), "capture_visible_turns": False}))
            config_path.chmod(0o600)
            original_vault = ClientConfig.vault

            def only_fixture(config: ClientConfig, **options):
                self.assertEqual(config.path, config_path)
                self.assertEqual(config.vault_path, vault_path)
                self.assertIsNone(config.identity_path)
                self.assertIsNone(config.trust_path)
                self.assertIsNone(config.sync_config_path)
                return original_vault(config, **options)

            with contextlib.ExitStack() as guards:
                guards.enter_context(mock.patch.object(tempfile, "tempdir", str(scratch)))
                guards.enter_context(mock.patch.object(ClientConfig, "vault", new=only_fixture))
                for target in ("subprocess.Popen", "socket.create_connection", "socket.socket.connect",
                               "memory_vault_client.notify_sync"):
                    guards.enter_context(mock.patch(target, side_effect=AssertionError("offline fixture must not launch or connect")))

                first = fixture_episode(1, second=0)
                first_chain = fixture_event(first, second=0, kind="checkpoint_note", continuity=True)
                decision = fixture_event(first, second=1, kind="decision", statement="Retain the original storage decision.",
                                         parents=[first_chain["memory_event_id"]])
                second = fixture_episode(2, second=2, parent=first)
                second_chain = fixture_event(second, second=2, kind="checkpoint_note", continuity=True,
                                             parents=[first_chain["memory_event_id"]])
                revised = fixture_event(second, second=3, kind="correction", statement="Refine the same storage decision.",
                                        parents=[second_chain["memory_event_id"], decision["memory_event_id"]],
                                        supersedes=[decision["memory_event_id"]])
                conflict = fixture_event(second, second=4, kind="conflict_declared", statement="Record both historical alternatives.",
                                         parents=[revised["memory_event_id"]],
                                         conflicts_with=[decision["memory_event_id"], revised["memory_event_id"]])
                resolution = fixture_event(second, second=5, kind="conflict_resolved", statement="Resolve the declared conflict with evidence.",
                                           parents=[conflict["memory_event_id"]], resolves=[conflict["memory_event_id"]])
                older = fixture_members([first, first_chain, decision])
                newer = fixture_members([first, first_chain, decision, second, second_chain, revised, conflict, resolution])
                sources, checkpoints, checkpoint_values = [], [], []
                for generation, members in enumerate((older, newer)):
                    source, checkpoint = root / f"generation-{generation}.pack", root / f"checkpoint-{generation}.json"
                    source.write_bytes(fixture_pack(members))
                    source.chmod(0o600)
                    checked = packs.verify(source)
                    expected_root = fixture_hash([{"path": path, "raw_size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                                                  for path, raw in sorted(members.items())])
                    self.assertEqual(checked["object_root_sha256"], expected_root)
                    self.assertTrue(checked["legacy_checksums_verified"])
                    self.assertFalse(checked["original_author_authenticated"])
                    self.assertEqual(checked["authority"], AUTHORITY)
                    previous = checkpoint_values[-1]["checkpoint_sha256"] if checkpoint_values else None
                    created = packs.create_checkpoint(source, checkpoint, generation=generation, previous_checkpoint_sha256=previous)
                    expected = {"schema_version": "memory-network-checkpoint/v1", "network_contract": "memory-network-checkpoint-catalog/v1",
                                "generation": generation, "object_count": len(members), "object_root_sha256": expected_root,
                                "remote_commit_sha": "b" * 40, "previous_checkpoint_sha256": previous}
                    expected["checkpoint_sha256"] = fixture_hash(expected)
                    self.assertEqual(json.loads(checkpoint.read_bytes()), expected)
                    self.assertEqual(created["checkpoint_sha256"], expected["checkpoint_sha256"])
                    self.assertFalse(created["checkpoint_is_signature"])
                    sources.append(source)
                    checkpoints.append(checkpoint)
                    checkpoint_values.append(expected)
                source_bytes = sources[1].read_bytes()
                checkpoint_bytes = [path.read_bytes() for path in checkpoints]
                first_pin, last_pin = (item["checkpoint_sha256"] for item in checkpoint_values)
                chain = packs.verify_checkpoint_chain(checkpoints, trusted_checkpoint_sha256=first_pin)
                self.assertEqual(chain["last_checkpoint_sha256"], last_pin)
                self.assertTrue(chain["trusted_anchor_checked"])
                self.assertFalse(chain["pack_object_root_checked"])
                self.assertFalse(chain["trust_granted"])
                self.assertTrue(packs.verify(sources[1], checkpoint=checkpoints[1], trusted_checkpoint_sha256=last_pin)["checkpoint_checked"])
                with self.assertRaises(MemoryError) as wrong_pack:
                    packs.verify(sources[0], checkpoint=checkpoints[1])
                self.assertEqual(wrong_pack.exception.code, "legacy_checkpoint_object_mismatch")
                with self.assertRaises(MemoryError) as wrong_chain:
                    packs.verify_checkpoint_chain(list(reversed(checkpoints)))
                self.assertEqual(wrong_chain.exception.code, "legacy_checkpoint_chain_mismatch")

                zipped, repacked = root / "repacked.zip", root / "repacked.pack"
                packs.repack(sources[1], zipped, format="zip", checkpoint=checkpoints[1], trusted_checkpoint_sha256=last_pin)
                with zipfile.ZipFile(zipped) as archive:
                    self.assertEqual({name: archive.read(name) for name in archive.namelist()}, newer)
                packs.repack(zipped, repacked, format="pack")
                self.assertEqual(packs.verify(repacked)["object_root_sha256"], checkpoint_values[1]["object_root_sha256"])
                capsule = root / "converted.zip"
                converted = packs.convert(repacked, capsule, checkpoint=checkpoints[1], trusted_checkpoint_sha256=last_pin)
                self.assertEqual(converted["source_documents"], 8)
                self.assertEqual(converted["signed_records"], 0)
                self.assertEqual(converted["import_admission_default"], "quarantined")
                self.assertFalse(converted["trust_granted"])
                with zipfile.ZipFile(capsule) as archive:
                    manifest = json.loads(archive.read("MANIFEST.json"))
                    records = [item["record"] for part in manifest["record_parts"]
                               for line in archive.read(part["path"]).splitlines()
                               if (item := json.loads(line)).get("type") == "record"]
                    mappings = [json.loads(line) for part in manifest["mapping_parts"] for line in archive.read(part["path"]).splitlines()]
                    self.assertEqual(archive.read("source/checkpoint.json"), checkpoint_bytes[1])
                restored_source = root / "original-again.pack"
                packs.extract(capsule, restored_source, original=True)
                self.assertEqual(restored_source.read_bytes(), repacked.read_bytes())
                by_id = {record["memory_id"]: record for record in records}
                by_old = {mapping["legacy_id"]: mapping for mapping in mappings}
                self.assertEqual(len(by_old), 8)
                self.assertEqual(len(by_id), manifest["records"])
                for mapping in mappings:
                    raw = b""
                    for reference in mapping["original_evidence_records"]:
                        proof_record = by_id[reference["memory_id"]]
                        self.assertEqual(proof_record["record_sha256"], reference["record_sha256"])
                        envelope = json.loads(proof_record["text"].split("\n", 1)[1])
                        self.assertEqual(envelope["offset"], len(raw))
                        raw += base64.b64decode(envelope["data"], validate=True)
                    self.assertEqual(raw, newer[mapping["source_path"]])
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), mapping["source_document_sha256"])

                vault = Vault(vault_path)
                parts = []
                for number, part in enumerate(manifest["record_parts"], 1):
                    path = root / f"records-{number}.ndjson"
                    packs.extract(capsule, path, part=number)
                    result = vault.import_bundle(path)
                    self.assertEqual(result["records_added"], part["record_count"])
                    self.assertEqual(result["admission"], "quarantined")
                    self.assertEqual(vault.import_bundle(path)["records_added"], 0)
                    parts.append(path)
                registered = 0
                for number in range(1, len(manifest["mapping_parts"]) + 1):
                    result = packs.register_aliases(capsule, config_path, part=number)
                    registered += result["added"]
                    self.assertFalse(result["trust_granted"])
                    self.assertFalse(result["canonical_records_changed"])
                    self.assertEqual(packs.register_aliases(capsule, config_path, part=number)["added"], 0)
                self.assertEqual(registered, 8)

                def get(memory_id: str) -> dict:
                    response = vault.handle({"op": "get", "memory_id": memory_id})
                    self.assertTrue(response["ok"], response)
                    self.assertEqual(response["authority"], AUTHORITY)
                    self.assertFalse(response["result"]["verification"]["grants_authority"])
                    return response["result"]

                second_id = by_old[second["episode_id"]]["memory_id"]
                held = get(second_id)
                self.assertEqual(held["verification"]["admission"], "quarantined")
                self.assertFalse(held["verification"]["eligible_for_context"])
                request = {
                    "schema_version": compat.REQUEST_SCHEMA, "protocol_version": "1.0", "request_id": "synthetic.legacy.before-admission",
                    "operation": "memory.remember",
                    # Version identifies this fixture, not the tested application.
                    "adapter": {"id": "synthetic-legacy-workflow", "version": "1.0.0", "host_family": "generic_stdio"},
                    "payload": {"proposal": {"schema_version": "memory-network-semantic-proposal/v1",
                        "source_id": second["source_id"], "episode_id": second["episode_id"],
                        "kind": "decision", "claim_key": "storage-direction", "parents": [resolution["memory_event_id"]],
                        "supersedes": [], "conflicts_with": [], "resolves": [],
                        "payload": {"statement": "Continue the reviewed synthetic history after migration.", "reason": None, "concepts": ["continuity"]}}},
                }
                rejected = compat.handle(config_path, request)
                self.assertEqual(rejected["status"], "rejected", rejected)
                self.assertEqual(rejected["error"]["code"], "evidence_not_admitted")
                self.assertEqual(rejected["authority"], compat._authority())
                for path in parts:
                    accepted = vault.import_bundle(path, accept_unsigned=True)
                    self.assertEqual(accepted["records_added"], 0)
                    self.assertEqual(accepted["admission"], "accepted_unsigned")
                for record in records:
                    actual = get(record["memory_id"])
                    self.assertEqual(canonical_bytes(actual["record"]), canonical_bytes(record))
                    self.assertTrue(actual["verification"]["eligible_for_context"])
                    self.assertFalse(actual["verification"]["claimed_provenance_is_authenticated"])

                def assert_edge(source: dict, relation: str, target: dict) -> None:
                    source_old = source.get("memory_event_id", source.get("episode_id"))
                    target_old = target.get("memory_event_id", target.get("episode_id"))
                    projected = by_id[by_old[source_old]["memory_id"]]
                    self.assertIn({"type": relation, "target": by_old[target_old]["memory_id"]}, projected["relations"])

                assert_edge(second, "continues", first)
                assert_edge(second_chain, "continues", first_chain)
                assert_edge(second_chain, "derived_from", second)
                assert_edge(revised, "derived_from", second_chain)
                assert_edge(revised, "derived_from", decision)
                assert_edge(revised, "supersedes", decision)
                assert_edge(conflict, "conflicts_with", decision)
                assert_edge(conflict, "conflicts_with", revised)
                assert_edge(resolution, "resolves", conflict)
                views = vault.handle({"op": "memory.views", "entity": "claim:v021:storage-direction",
                                      "maximum_nodes": 16, "include_proposals": False})
                self.assertTrue(views["ok"], views)
                view = views["result"]["views"][0]
                expected_claim_ids = [by_old[value["memory_event_id"]]["memory_id"] for value in (decision, revised, conflict, resolution)]
                self.assertEqual([item["memory_id"] for item in view["timeline"]], expected_claim_ids)
                self.assertEqual(view["grouping"], "exact_entity")
                self.assertFalse(view["inferred_grouping_is_ownership"])
                self.assertFalse(view["has_more"])
                states = {item["memory_id"]: item["status"] for item in view["timeline"]}
                self.assertEqual(states[expected_claim_ids[0]], "superseded")
                self.assertEqual(states[expected_claim_ids[2]], "resolved")

                request["request_id"] = "synthetic.legacy.after-admission"
                remembered = compat.handle(config_path, request)
                self.assertEqual(remembered["status"], "accepted_local", remembered)
                self.assertEqual(remembered["request_id"], request["request_id"])
                self.assertEqual(remembered["authority"], compat._authority())
                result = remembered["result"]
                self.assertTrue(result["evidence_mapping"]["original_v021_identity"])
                self.assertEqual(result["evidence_mapping"]["memory_id"], second_id)
                self.assertEqual(result["evidence_mapping"]["evidence_anchor_sha256"], second["episode_sha256"])
                self.assertFalse(result["network_accessed"])
                self.assertIsNone(result["remote_commit_sha"])
                new_record = get(result["canonical_memory_id"])["record"]
                self.assertIn({"type": "derived_from", "target": expected_claim_ids[-1]}, new_record["relations"])
                self.assertIn({"type": "derived_from", "target": second_id}, new_record["relations"])
                self.assertIn("claim:v021:storage-direction", new_record["entities"])
                request["request_id"] = "synthetic.legacy.exact-proposal-retry"
                repeated = compat.handle(config_path, request)
                self.assertEqual(repeated["status"], "duplicate", repeated)
                self.assertEqual(repeated["result"]["canonical_memory_id"], result["canonical_memory_id"])
                for path in parts:
                    self.assertEqual(vault.import_bundle(path, accept_unsigned=True)["records_added"], 0)
                status = vault.handle({"op": "status"})
                self.assertTrue(status["ok"], status)
                self.assertEqual(status["result"]["records"], len(records) + 1)
                for record in records:
                    self.assertEqual(canonical_bytes(get(record["memory_id"])["record"]), canonical_bytes(record))
                self.assertEqual(sources[1].read_bytes(), source_bytes)
                self.assertEqual([path.read_bytes() for path in checkpoints], checkpoint_bytes)


if __name__ == "__main__":
    unittest.main()
