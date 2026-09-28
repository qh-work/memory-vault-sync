"""Recover exact ACK-owner source evidence using an existing open identity.

This explicit command contacts the independently selected source and writes a
new private evidence file. It does not import memories, change authority, or
alter the configured Vault. Each phase has separate independent expected
inputs; occupied recovery additionally authenticates B's saved-message receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import b64url, document, object_fields, unb64url
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_state import DEFAULT_LIMITS, DEFAULT_POLICY, RECEIPT_WORKFLOW_LIMITS
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_trust import TrustError, _absolute_path, _read_private, _write_new_private

REQUEST_SCHEMA = "memory-vault-open-ack-recovery-request/v1"
EMPTY_REQUEST_SCHEMA = "memory-vault-open-ack-empty-recovery-request/v1"
OCCUPIED_REQUEST_SCHEMA = "memory-vault-open-ack-occupied-recovery-request/v1"
EVIDENCE_SCHEMA = "memory-vault-open-ack-recovery-evidence/v1"
MAX_BUNDLE_BYTES = 1024 * 1024
# Full occupied history has three generations. These are client acceptance
# ceilings, not modifications to the source's already signed grant or ledger.
OCCUPIED_LIMITS = RECEIPT_WORKFLOW_LIMITS


def _entry(value):
    item = object_fields(value, {"raw_base64url", "ref"})
    return dict(raw=unb64url(item["raw_base64url"], maximum=DEFAULT_POLICY.max_document_bytes), ref=item["ref"])


def _encoded(raw, ref):
    return dict(raw_base64url=b64url(raw), ref=ref.as_dict())


def _retained_statuses(authenticated_entries):
    """Compact only authenticated originals, preserving every remembered floor.

    This is not an authority check: recover() must have authenticated the whole
    input set first. The archive preserves all exact originals; the bounded
    reusable set discards an observation only when one retained original alone
    covers all of its scopes, revision floors and revoked operation bits.
    """
    archive = {canonical_bytes(item["ref"]): item for item in authenticated_entries}
    if len(archive) > 32:
        raise RepairWireError("repair_status_history_capacity")
    candidates = []
    for item in archive.values():
        payload = document(_entry(item)["raw"], maximum=DEFAULT_POLICY.max_document_bytes)["payload"]
        candidates.append((item, payload))

    def dominates(new, old):
        if (new["scope_key"] != old["scope_key"] or new["signing_key"] != old["signing_key"]
                or new["revision"] < old["revision"]):
            return False
        scopes = {(entry["scope_kind"], entry["scope_id"]): entry for entry in new["entries"]}
        for entry in old["entries"]:
            replacement = scopes.get((entry["scope_kind"], entry["scope_id"]))
            if (replacement is None
                    or replacement["minimum_document_revision"] < entry["minimum_document_revision"]):
                return False
            if entry["status"] == "revoked" and (replacement["status"] != "revoked"
                    or replacement["operation_mask"] & entry["operation_mask"] != entry["operation_mask"]):
                return False
        return True

    retained = []
    # Prefer newer revisions and, for equal observations, the latest exact wire.
    for candidate in sorted(reversed(candidates), key=lambda value: value[1]["revision"], reverse=True):
        if not any(dominates(other[1], candidate[1]) for other in retained):
            retained.append(candidate)
    if len(retained) > 16:
        raise RepairWireError("repair_status_history_capacity")
    return [item for item, _ in retained], list(archive.values())


def recover_ack(network_config: Path, request_path: Path, output: Path, *, timeout=30, phase="unbound"):
    """New-only evidence export; never open or modify the configured Vault."""
    if phase not in {"unbound", "empty", "occupied"}:
        raise RepairWireError("repair_invalid_request_bundle")
    request_path, output = _absolute_path(request_path), _absolute_path(output)
    if os.path.lexists(output):
        raise RepairWireError("repair_output_exists")
    raw = _read_private(request_path, MAX_BUNDLE_BYTES)
    if raw is None:
        raise RepairWireError("repair_request_missing")
    request = document(raw, maximum=MAX_BUNDLE_BYTES)
    fields = {"schema_version", "target", "ack_slot", "node", "root", "read", "bootstrap", "known_statuses"}
    if phase != "unbound":
        fields.update({"receipt_writer", "message_id", "envelope_ref"})
    if type(request) is dict and "archive_statuses" in request:
        fields.add("archive_statuses")
    request = object_fields(request, fields)
    schemas = dict(unbound=REQUEST_SCHEMA, empty=EMPTY_REQUEST_SCHEMA, occupied=OCCUPIED_REQUEST_SCHEMA)
    if request["schema_version"] != schemas[phase]:
        raise RepairWireError("repair_invalid_request_bundle")
    known = request["known_statuses"]
    if type(known) is not list or len(known) > 16:
        raise RepairWireError("repair_invalid_status")
    archived = request.get("archive_statuses", [])
    if type(archived) is not list or len(archived) > 32:
        raise RepairWireError("repair_status_history_capacity")
    entries = {name: _entry(request[name]) for name in ("node", "root", "read", "bootstrap")}
    # The client independently verifies this same signed descriptor and checks
    # its endpoint before the first request; this preview grants no access.
    node = document(entries["node"]["raw"], maximum=DEFAULT_POLICY.max_document_bytes)
    try:
        base_url = node["payload"]["base_url"]
    except (KeyError, TypeError):
        raise RepairWireError("repair_invalid_request_bundle") from None
    with OpenNetworkClient(_absolute_path(network_config)) as network:
        client = AckOwnerRecoveryClient(network.identity, network.encryption,
            limit_policy=OCCUPIED_LIMITS if phase == "occupied" else DEFAULT_LIMITS,
            allow_loopback=network.participant.transport.allow_loopback,
            transport=network.participant.transport)
        recover = dict(unbound=client.recover, empty=client.recover_empty, occupied=client.recover_occupied)[phase]
        expected = dict(expected_receipt_writer=request["receipt_writer"],
            expected_message_id=request["message_id"], expected_envelope_ref=request["envelope_ref"]) if phase != "unbound" else {}
        result = recover(base_url, target_node_entry=entries["node"], expected_target=request["target"],
            expected_ack_slot=request["ack_slot"], root_entry=entries["root"], read_entry=entries["read"],
            bootstrap_entry=entries["bootstrap"], known_statuses=[_entry(item) for item in known],
            archive_statuses=[_entry(item) for item in archived], timeout=timeout, **expected)
    historical = list(result.source.statuses)
    predecessor = getattr(result.source, "predecessor", None)
    while predecessor is not None:
        historical.extend(predecessor.statuses)
        predecessor = getattr(predecessor, "predecessor", None)
    retained, archive = _retained_statuses(
        [*archived, *known, *[_encoded(value.raw, value.ref) for value in historical],
         *[_encoded(value.raw, value.ref) for value in result.current_statuses]])
    evidence = dict(schema_version=EVIDENCE_SCHEMA, state=f"ack_{phase}_source_recovered",
        ack_slot=request["ack_slot"], target=request["target"],
        handle=_encoded(result.proof.handle.raw, result.proof.handle.ref),
        manifest=_encoded(result.proof.manifest.raw, result.proof.manifest_ref),
        originals=[_encoded(body, ref) for ref, body in sorted(result.originals.items(),
            key=lambda item: (item[0].namespace, item[0].key, item[0].raw_sha256, item[0].size))],
        current_statuses=[_encoded(item.raw, item.ref) for item in result.current_statuses],
        known_statuses=retained, archive_statuses=archive,
        metrics=dict(result.metrics))
    if phase != "unbound":
        evidence.update(receipt_writer=request["receipt_writer"], message_id=request["message_id"],
            envelope_ref=request["envelope_ref"])
    if phase == "occupied":
        receipt = result.source.inputs["receipt"]
        evidence["recipient_receipt"] = _encoded(receipt.raw, receipt.ref)
    encoded = canonical_bytes(evidence) + b"\n"
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise RepairWireError("repair_over_budget")
    _write_new_private(output, encoded)
    return dict(state=evidence["state"], evidence_path=str(output),
        evidence_sha256=hashlib.sha256(encoded).hexdigest(),
        original_count=len(result.originals), requests=result.metrics["requests"],
        vault_modified=False, recipient_saved=phase == "occupied")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("recover-ack", "recover unbound ACK source originals"),
                            ("recover-empty", "recover a message-bound empty ACK source"),
                            ("recover-occupied", "recover the recipient's signed saved-message receipt")):
        recover = commands.add_parser(name, help=help_text)
        recover.add_argument("--network-config", required=True, type=Path)
        recover.add_argument("--request", required=True, type=Path, help="private original request bundle")
        recover.add_argument("--output", required=True, type=Path, help="new private evidence file; never overwritten")
        recover.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    try:
        result = recover_ack(args.network_config, args.request, args.output, timeout=args.timeout,
            phase={"recover-ack":"unbound", "recover-empty":"empty", "recover-occupied":"occupied"}[args.command])
    except (MemoryError, TrustError, RepairWireError, OSError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "repair_storage_unavailable")}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
