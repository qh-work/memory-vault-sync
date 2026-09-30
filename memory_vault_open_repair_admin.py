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
from memory_vault_open_repair_state import DEFAULT_LIMITS, DEFAULT_POLICY, RECEIPT_WORKFLOW_LIMITS, INDEX_WORKFLOW_LIMITS
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_trust import TrustError, _absolute_path, _read_private, _write_new_private

REQUEST_SCHEMA = "memory-vault-open-ack-recovery-request/v1"
EMPTY_REQUEST_SCHEMA = "memory-vault-open-ack-empty-recovery-request/v1"
OCCUPIED_REQUEST_SCHEMA = "memory-vault-open-ack-occupied-recovery-request/v1"
REPLICA_REQUEST_SCHEMA = "memory-vault-open-ack-replica-unbound-recovery-request/v1"
EMPTY_REPLICA_REQUEST_SCHEMA = "memory-vault-open-ack-replica-empty-recovery-request/v1"
OCCUPIED_REPLICA_REQUEST_SCHEMA = "memory-vault-open-ack-replica-occupied-recovery-request/v1"
EVIDENCE_SCHEMA = "memory-vault-open-ack-recovery-evidence/v1"
MAX_BUNDLE_BYTES = 1024 * 1024
# Full occupied history has three generations. These are client acceptance
# ceilings, not modifications to the source's already signed grant or ledger.
OCCUPIED_LIMITS = RECEIPT_WORKFLOW_LIMITS


class _ReplicaStatusJournal:
    """Keep authenticated full references across failed commands and targets."""
    def __init__(self,db,root,*,original_source=False):
        self.db=db;self.root=canonical_bytes(root)
        # Preserve existing replica journal keys. Original-source observations
        # have a separate domain because their permitted status scopes differ.
        material=(b"original-source\0"+self.root) if original_source else self.root
        self.key=hashlib.sha256(material).hexdigest()
        with db:
            db.execute('CREATE TABLE IF NOT EXISTS open_ack_replica_roots(root_id TEXT PRIMARY KEY,root BLOB NOT NULL,blocked INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS open_ack_replica_statuses(root_id TEXT NOT NULL,ref_id TEXT NOT NULL,issuer TEXT NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL,PRIMARY KEY(root_id,ref_id))')

    def _check(self):
        held=self.db.execute('SELECT root,blocked FROM open_ack_replica_roots WHERE root_id=?',(self.key,)).fetchone()
        if held is not None:
            if bytes(held[0])!=self.root:raise RepairWireError('repair_storage_corrupt')
            if held[1]:raise RepairWireError('repair_status_history_capacity')
        return held

    def statuses(self,parties):
        self._check();issuers={p['signing_key']['key_id'] for p in parties}
        rows=self.db.execute('SELECT issuer,raw,ref FROM open_ack_replica_statuses WHERE root_id=? ORDER BY ref_id',(self.key,)).fetchall()
        if len(rows)>32 or sum(len(r[1])+len(r[2]) for r in rows)>262144:raise RepairWireError('repair_status_history_capacity')
        return [dict(raw=bytes(raw),ref=json.loads(bytes(ref))) for issuer,raw,ref in rows if issuer in issuers]

    def observe(self,item):
        from memory_vault_open_repair_status import AuthenticatedStatusOriginal
        if not isinstance(item,AuthenticatedStatusOriginal) or canonical_bytes(item.payload['scope_key']['root_key'])!=self.root:
            raise RepairWireError('repair_invalid_context')
        encoded=canonical_bytes(item.ref.as_dict());reference=hashlib.sha256(encoded).hexdigest();full=False
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if self._check() is None:
                if self.db.execute('SELECT count(*) FROM open_ack_replica_roots').fetchone()[0]>=16:raise RepairWireError('repair_status_history_capacity')
                self.db.execute('INSERT INTO open_ack_replica_roots VALUES(?,?,0)',(self.key,self.root))
            old=self.db.execute('SELECT raw,ref FROM open_ack_replica_statuses WHERE root_id=? AND ref_id=?',(self.key,reference)).fetchone()
            if old is not None:
                if bytes(old[0])!=item.raw or bytes(old[1])!=encoded:raise RepairWireError('repair_storage_corrupt')
                return
            count,size=self.db.execute('SELECT count(*),coalesce(sum(length(raw)+length(ref)),0) FROM open_ack_replica_statuses WHERE root_id=?',(self.key,)).fetchone()
            if count>=32 or size+len(item.raw)+len(encoded)>262144:
                self.db.execute('UPDATE open_ack_replica_roots SET blocked=1 WHERE root_id=?',(self.key,));full=True
            else:
                self.db.execute('INSERT INTO open_ack_replica_statuses VALUES(?,?,?,?,?)',(self.key,reference,item.payload['signing_key']['key_id'],item.raw,encoded))
        if full:raise RepairWireError('repair_status_history_capacity')


def _recover_replica(network,client,request,arguments,archived,phase):
    import memory_vault_open_repair_wire as wire
    import memory_vault_open_repair_resource as resource
    import memory_vault_open_repair_history as history
    parties=(dict(signing_key=network.identity.public_descriptor(),encryption_key=network.encryption.public_descriptor()),
        request['source'],request['maintainer'],request['target'])+((request['receipt_writer'],) if phase=='replica_occupied' else ())
    budget=wire.RepairBudget(DEFAULT_POLICY)
    for party in parties:resource._dual_key(party,budget)
    resource._opaque(request['source_storage_epoch'])
    slot=request['ack_slot']
    if type(slot) is not dict or 'root_key' not in slot:raise RepairWireError('repair_invalid_request_bundle')
    history._root(slot['root_key']);history._slot(slot,slot['root_key'],ack=True)
    with network.participant.state.db() as db:
        journal=_ReplicaStatusJournal(db,request['ack_slot']['root_key'])
        retained=journal.statuses(parties)
        merged={canonical_bytes(item['ref']):item for item in [*retained,*[_entry(e) for e in archived]]}
        if len(merged)>32:raise RepairWireError('repair_status_history_capacity')
        client.status_observer=journal.observe
        recover={'replica_empty':client.recover_replica_empty,'replica_occupied':client.recover_replica_occupied,'replica_unbound':client.recover_replica}[phase]
        result=recover(**dict(arguments,archive_statuses=list(merged.values())),
            expected_source=request['source'],source_storage_epoch=request['source_storage_epoch'],expected_maintainer=request['maintainer'])
        for item in result.archive_statuses:journal.observe(item)
        return result


def _recover_original(network,client,request,arguments,phase):
    import memory_vault_open_repair_wire as wire
    import memory_vault_open_repair_resource as resource
    import memory_vault_open_repair_history as history
    parties=[dict(signing_key=network.identity.public_descriptor(),encryption_key=network.encryption.public_descriptor()),
        request['target']]
    if phase=='occupied':parties.append(request['receipt_writer'])
    budget=wire.RepairBudget(DEFAULT_POLICY)
    for party in parties:resource._dual_key(party,budget)
    slot=request['ack_slot']
    if type(slot) is not dict or 'root_key' not in slot:raise RepairWireError('repair_invalid_request_bundle')
    history._root(slot['root_key']);history._slot(slot,slot['root_key'],ack=True)
    with network.participant.state.db() as db:
        journal=_ReplicaStatusJournal(db,slot['root_key'],original_source=True)
        retained=journal.statuses(parties)
        merged={canonical_bytes(item['ref']):item for item in [*retained,*arguments['archive_statuses']]}
        if len(merged)>32:raise RepairWireError('repair_status_history_capacity')
        client.status_observer=journal.observe
        result=dict(unbound=client.recover,empty=client.recover_empty,occupied=client.recover_occupied)[phase](
            **dict(arguments,archive_statuses=list(merged.values())))
        source=result.source
        while source is not None:
            for item in source.statuses:journal.observe(item)
            source=getattr(source,'predecessor',None)
        for item in result.current_statuses:journal.observe(item)
        # Include retained originals in the exported evidence as well as the
        # protected journal. They were reauthenticated by this recovery.
        return result,list(merged.values())


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


def recover_ack(network_config: Path, request_path: Path, output: Path, *, timeout=30, phase="unbound", repair_profile=None):
    """New-only evidence export; never open or modify the configured Vault."""
    if phase not in {"unbound", "empty", "occupied", "replica_unbound", "replica_empty", "replica_occupied"}:
        raise RepairWireError("repair_invalid_request_bundle")
    profiles = {"unbound": DEFAULT_LIMITS, "receipt": RECEIPT_WORKFLOW_LIMITS, "receipt-index": INDEX_WORKFLOW_LIMITS}
    if repair_profile is None:
        repair_profile = "receipt" if phase == "occupied" else "unbound"
    if type(repair_profile) is not str or repair_profile not in profiles:
        raise RepairWireError("repair_invalid_request_bundle")
    request_path, output = _absolute_path(request_path), _absolute_path(output)
    if os.path.lexists(output):
        raise RepairWireError("repair_output_exists")
    raw = _read_private(request_path, MAX_BUNDLE_BYTES)
    if raw is None:
        raise RepairWireError("repair_request_missing")
    request = document(raw, maximum=MAX_BUNDLE_BYTES)
    fields = {"schema_version", "target", "ack_slot", "node", "root", "read", "bootstrap", "known_statuses"}
    if phase in {"empty","occupied","replica_empty","replica_occupied"}:
        fields.update({"receipt_writer", "message_id", "envelope_ref"})
    if phase in {'replica_unbound','replica_empty','replica_occupied'}:fields.update({'source','source_storage_epoch','maintainer'})
    if type(request) is dict and "archive_statuses" in request:
        fields.add("archive_statuses")
    request = object_fields(request, fields)
    schemas = dict(unbound=REQUEST_SCHEMA, empty=EMPTY_REQUEST_SCHEMA, occupied=OCCUPIED_REQUEST_SCHEMA,replica_unbound=REPLICA_REQUEST_SCHEMA,replica_empty=EMPTY_REPLICA_REQUEST_SCHEMA,replica_occupied=OCCUPIED_REPLICA_REQUEST_SCHEMA)
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
            limit_policy=profiles[repair_profile],
            allow_loopback=network.participant.transport.allow_loopback,
            transport=network.participant.transport)
        expected = dict(expected_receipt_writer=request["receipt_writer"],
            expected_message_id=request["message_id"], expected_envelope_ref=request["envelope_ref"]) if phase in {'empty','occupied','replica_empty','replica_occupied'} else {}
        arguments=dict(base_url=base_url, target_node_entry=entries["node"], expected_target=request["target"],
            expected_ack_slot=request["ack_slot"], root_entry=entries["root"], read_entry=entries["read"],
            bootstrap_entry=entries["bootstrap"], known_statuses=[_entry(item) for item in known],
            archive_statuses=[_entry(item) for item in archived], timeout=timeout, **expected)
        if phase in {'replica_unbound','replica_empty','replica_occupied'}:result=_recover_replica(network,client,request,arguments,archived,phase)
        else:
            result,retained_archive=_recover_original(network,client,request,arguments,phase)
            archived=[dict(raw_base64url=b64url(item['raw']),ref=item['ref']) for item in retained_archive]
    source=result.replica['source'] if phase in {'replica_unbound','replica_empty','replica_occupied'} else result.source
    historical = list(result.archive_statuses) if phase in {'replica_unbound','replica_empty','replica_occupied'} else list(source.statuses)
    predecessor = getattr(source, "predecessor", None)
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
    if phase in {'empty','occupied','replica_empty','replica_occupied'}:
        evidence.update(receipt_writer=request["receipt_writer"], message_id=request["message_id"],
            envelope_ref=request["envelope_ref"])
    if phase in {"occupied","replica_occupied"}:
        receipt = source.event.inputs["receipt"] if phase=="replica_occupied" else source.inputs["receipt"]
        evidence["recipient_receipt"] = _encoded(receipt.raw, receipt.ref)
    if phase in {'replica_unbound','replica_empty','replica_occupied'}:
        custody=result.replica['custody']
        evidence.update(source=request['source'],source_storage_epoch=request['source_storage_epoch'],maintainer=request['maintainer'],
            replica_custody=_encoded(custody.raw,custody.ref))
    encoded = canonical_bytes(evidence) + b"\n"
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise RepairWireError("repair_over_budget")
    _write_new_private(output, encoded)
    return dict(state=evidence["state"], evidence_path=str(output),
        evidence_sha256=hashlib.sha256(encoded).hexdigest(),
        original_count=len(result.originals), requests=result.metrics["requests"],
        vault_modified=False, recipient_saved=phase in {"occupied","replica_occupied"})


COPY_REQUEST_SCHEMA = "memory-vault-open-ack-copy-request/v1"
COPY_RESULT_SCHEMA = "memory-vault-open-ack-copy-result/v1"
EMPTY_COPY_REQUEST_SCHEMA = "memory-vault-open-ack-copy-empty-request/v1"
OCCUPIED_COPY_REQUEST_SCHEMA = "memory-vault-open-ack-copy-occupied-request/v1"
EMPTY_COPY_RESULT_SCHEMA = "memory-vault-open-ack-copy-empty-result/v1"
OCCUPIED_COPY_RESULT_SCHEMA = "memory-vault-open-ack-copy-occupied-result/v1"
MAX_COPY_BUNDLE_BYTES = 8 * 1024 * 1024


def copy_ack(network_config, request_path, output, *, operation, timeout=30, repair_profile=None,source_state='unbound'):
    """Explicit maintainer reservation/assignment or upload; no inferred grants."""
    import time
    import memory_vault_open_repair_wire as wire
    from memory_vault_open_repair_copy_client import AckCopyUploadClient
    from memory_vault_open_repair_copy_prepare import AckCopyPreparation
    from memory_vault_open_repair_index_state import encode_entry
    profiles = {"unbound": DEFAULT_LIMITS, "receipt": RECEIPT_WORKFLOW_LIMITS, "receipt-index": INDEX_WORKFLOW_LIMITS}
    if (operation not in {"reserve", "upload"} or source_state not in {'unbound','empty','occupied'}
            or (repair_profile is not None and repair_profile not in profiles)):
        raise RepairWireError("repair_invalid_request_bundle")
    request_path, output = _absolute_path(request_path), _absolute_path(output)
    if os.path.lexists(output):
        raise RepairWireError("repair_output_exists")
    raw = _read_private(request_path, MAX_COPY_BUNDLE_BYTES)
    if raw is None:
        raise RepairWireError("repair_request_missing")
    fields = {"schema_version", "operation", "node", "ack_slot", "owner", "source", "source_storage_epoch",
              "manifest", "custody", "reservation", "intent", "originals", "current_statuses"}
    if operation == "upload":
        fields.update({"allocation", "offer", "assignment", "owner_disclosure", "source_disclosure"})
    if source_state in ('empty','occupied'):fields.update({'receipt_writer','message_id','envelope_ref'})
    if source_state=='occupied':
        fields.add('recipient_reservation')
        if operation=='upload':fields.add('recipient_disclosure')
    request = object_fields(document(raw, maximum=MAX_COPY_BUNDLE_BYTES), fields)
    schema={'unbound':COPY_REQUEST_SCHEMA,'empty':EMPTY_COPY_REQUEST_SCHEMA,'occupied':OCCUPIED_COPY_REQUEST_SCHEMA}[source_state]
    if request["schema_version"] != schema or request["operation"] != operation:
        raise RepairWireError("repair_invalid_request_bundle")
    if type(request["originals"]) is not list or not 1 <= len(request["originals"]) <= 64:
        raise RepairWireError("repair_invalid_request_bundle")
    if type(request["current_statuses"]) is not list or not 1 <= len(request["current_statuses"]) <= 16:
        raise RepairWireError("repair_invalid_status")
    names = ["node", "manifest", "custody", "reservation"]
    if operation == "upload":
        names += ["allocation", "offer", "assignment", "owner_disclosure", "source_disclosure"]
    if source_state=='occupied':
        names.append('recipient_reservation')
        if operation=='upload':names.append('recipient_disclosure')
    entries = {name: _entry(request[name]) for name in names}
    originals = [_entry(item) for item in request["originals"]]
    statuses = [_entry(item) for item in request["current_statuses"]]
    node = document(entries["node"]["raw"], maximum=DEFAULT_POLICY.max_document_bytes)
    try:
        base_url = node["payload"]["base_url"]
        target = request["intent"]["target"]
        epoch = request["intent"]["target_storage_epoch"]
    except (KeyError, TypeError):
        raise RepairWireError("repair_invalid_request_bundle") from None

    def resolver():
        result = wire.LocalRawResolver(DEFAULT_POLICY, wire.RepairBudget(DEFAULT_POLICY))
        for entry in originals:
            ref = wire.raw_ref(entry["ref"])
            if result.put(ref.namespace, ref.key, entry["raw"]).ref != ref:
                raise RepairWireError("repair_ref_mismatch")
        return result

    context = dict(expected_ack_slot=request["ack_slot"], expected_owner=request["owner"],
        expected_source=request["source"], source_storage_epoch=request["source_storage_epoch"],
        current_statuses=statuses, limit_policy=profiles[repair_profile or "unbound"])
    if source_state in ('empty','occupied'):context.update(expected_receipt_writer=request['receipt_writer'],
        expected_message_id=request['message_id'],expected_envelope_ref=request['envelope_ref'])
    if source_state=='occupied':
        context['recipient_reservation_entry']=entries['recipient_reservation']
        if operation=='upload':context['recipient_disclosure_entry']=entries['recipient_disclosure']
    with OpenNetworkClient(_absolute_path(network_config)) as network, network.participant.state.db() as db:
        journal = AckCopyPreparation(db, network.identity, network.encryption, policy=DEFAULT_POLICY)
        client = AckCopyUploadClient(journal, encryption_identity=network.encryption,
            transport=network.participant.transport, allow_loopback=network.participant.transport.allow_loopback)
        try:
            if operation == "reserve":
                reserve={'unbound':client.reserve,'empty':client.reserve_empty,'occupied':client.reserve_occupied}[source_state]
                assign={'unbound':journal.assign_unbound,'empty':journal.assign_empty,'occupied':journal.assign_occupied}[source_state]
                result = reserve(base_url, entries["manifest"], resolver(), entries["custody"],
                    entries["reservation"], request["intent"], target_node_entry=entries["node"], timeout=timeout, **context)
                source = resolver()
                assignment = assign(entries["manifest"], source, entries["custody"],
                    entries["reservation"], request["intent"], offer_entry=result["offer"], at=int(time.time()),
                    budget=source.budget, **context)
                evidence = dict(state="capacity_reserved_and_assigned",
                    **{name: encode_entry(result[name]) for name in ("allocation", "offer")}, assignment=encode_entry(assignment))
            else:
                allocation = document(entries["allocation"]["raw"], maximum=DEFAULT_POLICY.max_document_bytes)
                if (type(allocation) is not dict or type(allocation.get("payload")) is not dict
                        or allocation["payload"].get("intent") != request["intent"]):
                    raise RepairWireError("repair_copy_upload_conflict")
                upload={'unbound':client.upload,'empty':client.upload_empty,'occupied':client.upload_occupied}[source_state]
                result = upload(base_url, entries["manifest"], resolver(), entries["custody"],
                    entries["allocation"], entries["offer"], entries["assignment"], entries["reservation"],
                    entries["owner_disclosure"], entries["source_disclosure"], target_node_entry=entries["node"],
                    expected_target=target, target_storage_epoch=epoch, timeout=timeout, **context)
                evidence = dict(state=result["state"], **{name: encode_entry(result[name]) for name in ("manifest", "custody")})
        finally:
            client.close()
    evidence.update(schema_version={'unbound':COPY_RESULT_SCHEMA,'empty':EMPTY_COPY_RESULT_SCHEMA,'occupied':OCCUPIED_COPY_RESULT_SCHEMA}[source_state],
        ack_slot=request["ack_slot"], target=target,
        target_storage_epoch=epoch, recipient_saved=False, vault_modified=False)
    if source_state in ('empty','occupied'):evidence.update(source_state=source_state,receipt_admission_authorized=False,
        receipt_writer=request['receipt_writer'],message_id=request['message_id'],envelope_ref=request['envelope_ref'])
    encoded = canonical_bytes(evidence) + b"\n"
    if len(encoded) > MAX_COPY_BUNDLE_BYTES:
        raise RepairWireError("repair_over_budget")
    _write_new_private(output, encoded)
    return dict(state=evidence["state"], evidence_path=str(output), evidence_sha256=hashlib.sha256(encoded).hexdigest(),
        recipient_saved=False, vault_modified=False)


REPLICA_CONFIG_SCHEMA = "memory-vault-open-ack-replica-read-config/v1"
EMPTY_REPLICA_CONFIG_SCHEMA = "memory-vault-open-ack-replica-empty-read-config/v1"
OCCUPIED_REPLICA_CONFIG_SCHEMA = "memory-vault-open-ack-replica-occupied-read-config/v1"


def configure_replica(node_config, request_path, output, *, source_state='unbound'):
    """Install independently signed return permissions on an existing local node."""
    from memory_vault_network_crypto import EncryptionIdentity
    from memory_vault_open_node import OpenParticipant
    from memory_vault_open_repair_index_admin import _node_config
    from memory_vault_open_repair_copy_service import ReplicaReadService,ReplicaEmptyReadService,ReplicaOccupiedReadService
    from memory_vault_open_repair_mailbox_copy_service import MailboxRootReplicaReadService,MailboxFeedReplicaReadService,MailboxMessageReplicaReadService
    if source_state not in {"unbound","empty","occupied","root","feed","message"}:raise RepairWireError("repair_invalid_request_bundle")
    from memory_vault_trust import Identity
    request_path, output = _absolute_path(request_path), _absolute_path(output)
    if os.path.lexists(output):
        raise RepairWireError("repair_output_exists")
    raw = _read_private(request_path, MAX_BUNDLE_BYTES)
    if raw is None:
        raise RepairWireError("repair_request_missing")
    request = object_fields(document(raw, maximum=MAX_BUNDLE_BYTES),
        {"schema_version", "resource_id", "context", "consents", "current_statuses"})
    if request["schema_version"] != {"unbound":REPLICA_CONFIG_SCHEMA,"empty":EMPTY_REPLICA_CONFIG_SCHEMA,"occupied":OCCUPIED_REPLICA_CONFIG_SCHEMA,
            "root":"memory-vault-open-mailbox-root-replica-read-config/v1", "feed":"memory-vault-open-mailbox-feed-replica-read-config/v1", "message":"memory-vault-open-mailbox-message-replica-read-config/v1"}[source_state]:
        raise RepairWireError("repair_invalid_request_bundle")
    consents = object_fields(request["consents"], {"owner", "source", "maintainer"}|({"recipient"} if source_state=="occupied" else {"sender"} if source_state in ("feed","message") else set()))
    if type(request["current_statuses"]) is not list or not 1 <= len(request["current_statuses"]) <= 16:
        raise RepairWireError("repair_invalid_status")
    config = _node_config(_absolute_path(node_config))
    identity = Identity.load(_absolute_path(Path(config["identity_path"])))
    encryption = EncryptionIdentity.load(_absolute_path(Path(config["encryption_key_path"])))
    with OpenParticipant(identity, _absolute_path(Path(config['state_directory'])),
            seeds=config['seeds'], descriptor=config['node'], encryption_identity=encryption,
            allow_loopback=config['allow_loopback'], index_policy=config['index_policy'],
            contact_policy=config.get('contact_policy'), delivery_policy=config.get('delivery_policy'),
            provider_policy=config.get('provider_policy'), repair_policy=config['repair_policy']) as participant:
        with participant.state.db() as db:
            service = {"unbound":ReplicaReadService,"empty":ReplicaEmptyReadService,"occupied":ReplicaOccupiedReadService,
                "root":MailboxRootReplicaReadService,"feed":MailboxFeedReplicaReadService,"message":MailboxMessageReplicaReadService}[source_state](participant._repair_service(db,mailbox_workflow=source_state in ("feed","message")).state)
            service.initialize()
            result = service.configure(request["resource_id"], context=request["context"],
                consents={name: _entry(entry) for name, entry in consents.items()},
                current_statuses=[_entry(entry) for entry in request["current_statuses"]])
    evidence = dict(result, schema_version="memory-vault-open-mailbox-"+source_state+"-replica-read-config-result/v1" if source_state in ('root','feed') else "memory-vault-open-ack-replica-read-config-result/v1",
        recipient_saved=False, vault_modified=False, network_started=False)
    encoded = canonical_bytes(evidence) + b"\n"
    _write_new_private(output, encoded)
    return dict(evidence, evidence_path=str(output), evidence_sha256=hashlib.sha256(encoded).hexdigest())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("recover-ack", "recover unbound ACK source originals"),
                            ("recover-empty", "recover a message-bound empty ACK source"),
                            ("recover-occupied", "recover the recipient's signed saved-message receipt"),
                            ("recover-replica", "recover an independently authorized unbound ACK replica"),
                            ("recover-replica-empty", "recover a bound slot from an independently authorized replica"),
                            ("copy-reserve", "reserve capacity and assign an explicitly authorized unbound replica"),
                            ("copy-upload", "upload and commit the separately authorized unbound replica"),
                            ("copy-reserve-empty", "reserve an explicitly authorized bound empty ACK copy"),
                            ("copy-upload-empty", "retain the exact bound slot and its complete original history"),
                            ("copy-reserve-occupied", "reserve an existing receipt replica with explicit recipient consent"),
                            ("copy-upload-occupied", "copy an existing receipt with all three original history generations"),
                            ("copy-reserve-root", "reserve space for an independently authorized mailbox directory copy"),
                            ("copy-reserve-feed", "reserve a message index copy with separate sender consent"),
                            ("copy-reserve-message", "reserve ciphertext space with separate sender consent"),
                            ("copy-upload-root", "upload an independently authorized mailbox directory replica"),
                            ("copy-upload-feed", "upload an exact message index with independent sender disclosure"),
                            ("copy-upload-message", "store exact original ciphertext with independent message authority"),
                            ("receive-replica-message", "recover a message and import explicitly shared memory into the recipient inbox"),
                            ("recover-replica-root", "recover the original mailbox directory from an explicitly selected replica"),
                            ("recover-replica-feed", "recover and decrypt the original message index from an authorized replica"),
                            ("recover-replica-occupied", "recover the original signed receipt from an authorized replica")):
        recover = commands.add_parser(name, help=help_text)
        recover.add_argument("--network-config", required=True, type=Path)
        recover.add_argument("--request", required=True, type=Path, help="private original request bundle")
        recover.add_argument("--output", required=True, type=Path, help="new private evidence file; never overwritten")
        recover.add_argument("--timeout", type=float, default=30)
        recover.add_argument("--repair-profile", choices=("unbound", "receipt", "receipt-index") + (("mailbox",) if name in ("copy-reserve-root", "copy-reserve-feed", "copy-reserve-message", "copy-upload-root", "copy-upload-feed", "recover-replica-root", "recover-replica-feed", "copy-upload-message", "receive-replica-message") else ()),
            help="explicit client acceptance ceiling; never changes the source's signed limits")
    for name in ("configure-replica","configure-replica-empty","configure-replica-occupied","configure-replica-root","configure-replica-feed","configure-replica-message"):
        configure = commands.add_parser(name, help="install separately signed replica return consents locally")
        configure.add_argument("--node-config", required=True, type=Path)
        configure.add_argument("--request", required=True, type=Path)
        configure.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command in {"configure-replica","configure-replica-empty","configure-replica-occupied","configure-replica-root","configure-replica-feed","configure-replica-message"}:
            result = configure_replica(args.node_config, args.request, args.output,
                source_state="message" if args.command.endswith("-message") else "feed" if args.command.endswith("-feed") else "root" if args.command.endswith("-root") else "occupied" if args.command.endswith("-occupied") else "empty" if args.command.endswith("-empty") else "unbound")
        elif args.command in {"copy-reserve-root", "copy-reserve-feed", "copy-reserve-message"}:
            from memory_vault_open_repair_mailbox_copy_admin import reserve_mailbox
            result = reserve_mailbox(args.network_config, args.request, args.output,
                source_state=args.command.rsplit("-", 1)[1], timeout=args.timeout, repair_profile=args.repair_profile)
        elif args.command in {"copy-upload-root", "copy-upload-feed", "recover-replica-root", "recover-replica-feed", "copy-upload-message", "receive-replica-message"}:
            from memory_vault_open_repair_mailbox_copy_admin import upload_root, upload_feed, recover_root, recover_feed, upload_message, receive_message
            method={'copy-upload-root':upload_root,'copy-upload-feed':upload_feed,'recover-replica-root':recover_root,'recover-replica-feed':recover_feed,'copy-upload-message':upload_message,'receive-replica-message':receive_message}[args.command]
            result=method(args.network_config,args.request,args.output,timeout=args.timeout,repair_profile=args.repair_profile)
        elif args.command in {"copy-reserve", "copy-upload", "copy-reserve-empty", "copy-upload-empty", "copy-reserve-occupied", "copy-upload-occupied"}:
            result = copy_ack(args.network_config, args.request, args.output, timeout=args.timeout,
                repair_profile=args.repair_profile, operation=args.command.split("-")[1],
                source_state='occupied' if args.command.endswith('-occupied') else 'empty' if args.command.endswith('-empty') else 'unbound')
        else:
            result = recover_ack(args.network_config, args.request, args.output, timeout=args.timeout, repair_profile=args.repair_profile,
                phase={"recover-ack":"unbound", "recover-empty":"empty", "recover-occupied":"occupied","recover-replica":"replica_unbound","recover-replica-empty":"replica_empty","recover-replica-occupied":"replica_occupied"}[args.command])
    except (MemoryError, TrustError, RepairWireError, OSError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "repair_storage_unavailable")}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
