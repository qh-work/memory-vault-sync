"""Explicit publication of a delivery client's actually saved original receipt.

Calling publish_saved opts this exact receipt into B's signed four-role ACK
return consent. Receiving a message alone never calls it or changes consent.
No Vault is opened: the existing delivery inbox and ACK originals are used.
The local journal retains exact B originals and an authenticated historical
result; a completed local retry returns history, not a fresh network claim.
"""
from dataclasses import dataclass
from types import MappingProxyType

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document
import memory_vault_open_delivery as delivery
from memory_vault_open_delivery_client import OpenDeliveryClient, MAX_INBOX_SESSION_BYTES, MAX_RESULT_BYTES
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import DEFAULT_POLICY

REQUEST_FIELDS = frozenset(("message_id","envelope_ref","ack_slot","owner","target","target_node_entry",
    "root_entry","write_entry","bootstrap_entry","binding_entry","current_statuses","read_until","retain_until"))
MAX_RECORDS = 16
MAX_RECORD_BYTES = 1048576


def _fail(code):
    wire._fail(code)


def _entry(item):
    return dict(raw=item.raw,ref=item.ref.as_dict())


def _frozen_entry(entry, policy, budget):
    return MappingProxyType(dict(raw=bytes(entry["raw"]),ref=wire.raw_ref(wire.build_new_wire(entry["ref"],policy,budget).value)))


@dataclass(frozen=True, slots=True)
class PublishedSavedAck:
    source: occupied.AuthenticatedAckOccupiedSourceEvent
    originals: object
    from_local_history: bool


class SavedAckReceiptPublisher:
    def __init__(self, delivery_client, ack_client, *, policy=DEFAULT_POLICY):
        if not isinstance(delivery_client,OpenDeliveryClient):
            _fail("repair_saved_client_required")
        self.delivery,self.client,self.policy=delivery_client,ack_client,policy
        if (ack_client.subject["signing_key"] != delivery_client.identity.public_descriptor()
                or ack_client.subject["encryption_key"] != delivery_client.encryption.public_descriptor()):
            _fail("repair_saved_identity_mismatch")
        with self.delivery.participant.state.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS open_repair_saved_ack_roots(root_digest TEXT PRIMARY KEY,revision INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS open_repair_saved_acks(slot_digest TEXT PRIMARY KEY,root_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,issued_at INTEGER NOT NULL,status_revision INTEGER NOT NULL,
                    originals BLOB,result BLOB,attempted INTEGER NOT NULL DEFAULT 0);
            """)
            columns={row[1] for row in db.execute("PRAGMA table_info(open_repair_saved_acks)")}
            if "attempted" not in columns:
                db.execute("ALTER TABLE open_repair_saved_acks ADD COLUMN attempted INTEGER NOT NULL DEFAULT 0")
                db.execute("UPDATE open_repair_saved_acks SET attempted=1 WHERE originals IS NOT NULL AND result IS NULL")
            for name in ("put_journal","put_response"):
                if name not in columns:
                    db.execute("ALTER TABLE open_repair_saved_acks ADD COLUMN "+name+" BLOB")

    def _saved(self, request, budget):
        message_id=request["message_id"]
        delivery._hex(message_id,prefix="msg_")
        row=self.delivery._inbox(message_id)
        if row is None or row["phase"] != "saved":
            _fail("repair_receipt_not_saved")
        raw=bytes(row["envelope"])
        if budget._hash(raw)!=row["envelope_sha256"]:
            _fail("repair_saved_tuple_mismatch")
        envelope_ref=delivery.envelope_ref(raw)
        session=document(bytes(row["session"]),maximum=MAX_INBOX_SESSION_BYTES)
        keys=self.delivery._keys(session)
        if (row["sender"]!=request["owner"]["signing_key"]["key_id"]
                or envelope_ref!=request["envelope_ref"]
                or keys!={"sender_signing_key":request["owner"]["signing_key"],"sender_encryption_key":request["owner"]["encryption_key"],
                    "recipient_signing_key":self.client.subject["signing_key"],"recipient_encryption_key":self.client.subject["encryption_key"]}):
            _fail("repair_saved_tuple_mismatch")
        result=document(bytes(row["result"]),maximum=MAX_RESULT_BYTES)
        if (result.get("state")!="validated_saved" or result.get("message_id")!=message_id
                or result.get("sender_key_id")!=row["sender"] or result.get("content_kind") not in ("message","memory_transfer")):
            _fail("repair_receipt_not_saved")
        # This is the live inbox method, not a caller-supplied receipt or flag.
        self.delivery._saved_receipt(message_id)
        saved=self.delivery._inbox(message_id)
        if (saved is None or saved["phase"]!="saved" or bytes(saved["envelope"])!=raw
                or saved["sender"]!=row["sender"] or bytes(saved["body"])!=bytes(row["body"])):
            _fail("repair_saved_tuple_mismatch")
        receipt_raw=bytes(saved["receipt"])
        digest=budget._hash(receipt_raw)
        receipt=dict(raw=receipt_raw,ref=dict(namespace="meta",key=digest,raw_sha256=digest,size=len(receipt_raw)))
        checked=occupied._receipt(receipt,self.client.subject,request["owner"],message_id,envelope_ref,self.policy,budget)
        return row,checked

    def _request(self, value, budget):
        wire.object_fields(value,REQUEST_FIELDS)
        # Snap closed scalar/descriptor inputs separately from original bytes.
        request=dict(wire.build_new_wire({name:value[name] for name in REQUEST_FIELDS if not name.endswith("_entry") and name!="current_statuses"},self.policy,budget).value)
        for name in ("target_node_entry","root_entry","write_entry","bootstrap_entry","binding_entry"):
            raw,ref=ack._entry(value[name]);request[name]=dict(raw=wire._snapshot(raw,self.policy,budget),ref=ref.as_dict())
        if type(value["current_statuses"]) not in (list,tuple) or not 1<=len(value["current_statuses"])<=7:
            _fail("repair_invalid_status")
        request["current_statuses"]=[dict(raw=wire._snapshot(ack._entry(item)[0],self.policy,budget),ref=ack._entry(item)[1].as_dict()) for item in value["current_statuses"]]
        return request

    def _encode_originals(self, entries, budget):
        return wire._canonical({name:dict(raw=entry["raw"].decode("utf-8"),ref=entry["ref"]) for name,entry in entries.items()},budget)

    def _decode_originals(self, raw, budget):
        value=wire.parse_new_wire(bytes(raw),self.policy,budget).value
        wire.object_fields(value,{"receipt","disclosure","put","status"})
        return {name:dict(raw=item["raw"].encode(),ref=item["ref"]) for name,item in value.items()}

    def _archive(self, result, budget):
        value=dict(manifest_ref=result.source.commit.payload["historical_manifest_ref"],commit_ref=result.source.commit.ref.as_dict(),
            originals=[dict(ref=ref.as_dict(),raw_base64url=probe._encode(raw,budget)) for ref,raw in sorted(result.originals.items(),key=lambda item:(item[0].namespace,item[0].key))])
        raw=wire.build_new_wire(value,self.policy,budget).raw
        if len(raw)>MAX_RECORD_BYTES:
            _fail("repair_saved_capacity")
        return raw

    def _restore(self, raw, request, entries, budget):
        value=wire.parse_new_wire(bytes(raw),self.policy,budget).value
        wire.object_fields(value,{"manifest_ref","commit_ref","originals"})
        resolver=wire.LocalRawResolver(self.policy,budget);originals={}
        if type(value["originals"]) is not wire._DraftList or not 1<=len(value["originals"])<=128:
            _fail("repair_saved_corrupt")
        for item in value["originals"]:
            wire.object_fields(item,{"ref","raw_base64url"});ref=wire.raw_ref(item["ref"])
            body=original._decode64(item["raw_base64url"],ref.size,budget,url=True)
            if ref in originals or len(body)!=ref.size or budget._hash(body)!=ref.raw_sha256:
                _fail("repair_saved_corrupt")
            originals[ref]=body
            resolver.put(ref.namespace,ref.key,body)
        manifest_ref,commit_ref=wire.raw_ref(value["manifest_ref"]),wire.raw_ref(value["commit_ref"])
        if manifest_ref not in originals or commit_ref not in originals:
            _fail("repair_saved_corrupt")
        checked=occupied.verify_ack_occupied_source_event(dict(raw=originals[manifest_ref],ref=manifest_ref.as_dict()),resolver,
            dict(raw=originals[commit_ref],ref=commit_ref.as_dict()),expected_ack_slot=request["ack_slot"],expected_owner=request["owner"],
            expected_receipt_writer=self.client.subject,expected_message_id=request["message_id"],expected_envelope_ref=request["envelope_ref"],
            expected_target=request["target"],target_storage_epoch=checked_epoch(request,self.policy,budget),
            limit_policy=self.client.limits,policy=self.policy,budget=budget)
        if any(_entry(checked.inputs[name])!=entries[name] for name in ("receipt","disclosure","put")):
            _fail("repair_saved_corrupt")
        return PublishedSavedAck(checked,MappingProxyType(originals),True)

    def publish_saved(self,base_url,request,*,timeout=30):
        """Explicitly sign FULL consent for one saved receipt and publish it.

        The request is a closed local API, not a new signed network protocol.
        It requires the original binding returned by the ACK source; the
        existing put client independently checks it in its real preflight.
        Local validation and the existing finite wire workflow have separate
        bounded meters; neither stage resets or inflates the other's budget.
        """
        budget=wire.RepairBudget(self.policy);request=self._request(request,budget)
        row,receipt=self._saved(request,budget)
        now=self.client._now()
        authorities=bound.verify_ack_offer_bootstrap_original(request["bootstrap_entry"],dict(root=request["root_entry"],write=request["write_entry"]),
            expected_ack_slot=request["ack_slot"],expected_owner=request["owner"],expected_receipt_writer=self.client.subject,
            expected_message_id=request["message_id"],expected_envelope_ref=request["envelope_ref"],at=now,
            limit_policy=self.client.limits,policy=self.policy,budget=budget)
        binding=empty._signed(request["binding_entry"],request["target"],"ack.binding",self.policy,budget)
        root,write,grant=(authorities.originals[name] for name in ("root","write","bootstrap"))
        if (binding.payload["ack_slot"]!=request["ack_slot"] or binding.payload["root_authority_ref"]!=root.ref.as_dict()
                or binding.payload["grant_ref"]!=write.ref.as_dict() or binding.payload["bound_at"]>receipt.payload["saved_at"]
                or not receipt.payload["saved_at"]<=now<wire.u53(request["read_until"])<=wire.u53(request["retain_until"])
                or request["read_until"]>root.payload["windows"]["read_until"]
                or request["retain_until"]>min(binding.payload["retain_until"],write.payload["windows"]["retain_until"],root.payload["windows"]["retain_until"])):
            _fail("repair_saved_tuple_mismatch")
        root_digest=budget._hash(wire._canonical(request["ack_slot"]["root_key"],budget))
        slot_digest=budget._hash(wire._canonical(request["ack_slot"],budget))
        request_digest=budget._hash(wire._canonical(dict(slot=request["ack_slot"],receipt=receipt.ref.as_dict(),
            **{name:request[name] for name in ("owner","target","read_until","retain_until")},
            **{name:request[name]["ref"] for name in ("root_entry","write_entry","bootstrap_entry","binding_entry")}),budget))
        with self.delivery.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            saved=db.execute("SELECT * FROM open_repair_saved_acks WHERE slot_digest=?",(slot_digest,)).fetchone()
            if saved is None:
                if db.execute("SELECT count(*) FROM open_repair_saved_acks").fetchone()[0]>=MAX_RECORDS:
                    _fail("repair_saved_capacity")
                prior=db.execute("SELECT revision FROM open_repair_saved_ack_roots WHERE root_digest=?",(root_digest,)).fetchone()
                revision=wire.u53((prior[0] if prior else 0)+1,1)
                db.execute("INSERT INTO open_repair_saved_ack_roots VALUES(?,?) ON CONFLICT(root_digest) DO UPDATE SET revision=excluded.revision",(root_digest,revision))
                db.execute("INSERT INTO open_repair_saved_acks(slot_digest,root_digest,request_digest,issued_at,status_revision) VALUES(?,?,?,?,?)",
                    (slot_digest,root_digest,request_digest,now,revision))
                saved=db.execute("SELECT * FROM open_repair_saved_acks WHERE slot_digest=?",(slot_digest,)).fetchone()
            saved=dict(saved)
            if saved["root_digest"]!=root_digest or saved["request_digest"]!=request_digest:
                _fail("repair_saved_retry_mismatch")
        if saved["originals"] is None:
            issued=wire.u53(saved["issued_at"]);retain=request["retain_until"];read=request["read_until"]
            expiry=min(retain,write.payload["expires_at"],grant.payload["upload_until"],issued+300)
            if expiry<=issued:
                _fail("repair_access_expired")
            def signed(payload):
                frozen=wire.build_new_wire(payload,self.policy,budget).value
                return _entry(probe._sign(frozen,self.delivery.identity,self.policy,budget))
            common=dict(schema_version="memory-vault-open-repair/v1",signing_key=self.client.subject["signing_key"])
            disclosure=signed(dict(**common,kind="ack.disclosure",issued_at=issued,expires_at=retain,consent_id="consent_"+slot_digest,
                ack_slot=request["ack_slot"],root_authority_ref=root.ref.as_dict(),grant_ref=write.ref.as_dict(),receipt_ref=receipt.ref.as_dict(),
                recipient=request["ack_slot"]["receipt_writer"],owner=request["ack_slot"]["root_key"]["owner"],allowed_roles=sorted(occupied.B_ROLES),
                operation_mask=67,consent_until=retain,bootstrap_return=dict(subject=request["ack_slot"]["root_key"]["owner"],consumer="ack_owner",
                roles=list(occupied.RETURN_ROLES_FULL),until=read),revision=1))
            put=signed(dict(**common,kind="ack.put",issued_at=issued,expires_at=expiry,put_id="put_"+slot_digest,
                ack_slot=request["ack_slot"],grant_ref=write.ref.as_dict(),binding_ref=binding.ref.as_dict(),receipt_ref=receipt.ref.as_dict(),
                disclosure_ref=disclosure["ref"],operation="receipt.put"))
            scope=status.status_scope(request["ack_slot"]["root_key"],"authority",dict(authority_kind="ack.disclosure",authority_sha256=disclosure["ref"]["raw_sha256"]),self.policy,budget)
            observation=signed(dict(schema_version=status.SCHEMA,kind="authority.status",signing_key=self.client.subject["signing_key"],
                scope_key=dict(root_key=request["ack_slot"]["root_key"],issuer_key_id=self.delivery.identity.key_id),revision=saved["status_revision"],
                issued_at=issued,valid_until=min(retain,issued+3600),entries=[dict(scope_kind="authority",scope_id=scope,minimum_document_revision=1,status="active",operation_mask=67)]))
            entries=dict(receipt=_entry(receipt),disclosure=disclosure,put=put,status=observation)
            encoded=self._encode_originals(entries,budget)
            if len(encoded)>65536:_fail("repair_saved_capacity")
            with self.delivery.participant.state.db() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE open_repair_saved_acks SET originals=? WHERE slot_digest=? AND request_digest=? AND originals IS NULL",(encoded,slot_digest,request_digest))
                saved=dict(db.execute("SELECT * FROM open_repair_saved_acks WHERE slot_digest=?",(slot_digest,)).fetchone())
        entries=self._decode_originals(saved["originals"],budget)
        if entries["receipt"]!=_entry(receipt):_fail("repair_saved_corrupt")
        if saved["result"] is not None:
            return self._restore(saved["result"],request,entries,budget)
        # A failed preflight has sent no private originals and may be retried.
        # The before-send journal callback claims the first carrier atomically.
        with self.delivery.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            pending=db.execute("SELECT attempted,put_journal FROM open_repair_saved_acks WHERE slot_digest=? AND request_digest=?",(slot_digest,request_digest)).fetchone()
            if pending is None or (pending["attempted"] and pending["put_journal"] is None):
                _fail("repair_saved_reconciliation_required")
            resume=bytes(pending["put_journal"]) if pending["attempted"] else None

        def journal(phase,raw):
            if phase not in ("request","response") or type(raw) is not bytes or not 0<len(raw)<=MAX_RECORD_BYTES:
                _fail("repair_saved_capacity")
            column="put_journal" if phase=="request" else "put_response"
            with self.delivery.participant.state.db() as db:
                db.execute("BEGIN IMMEDIATE")
                held=db.execute("SELECT originals,put_journal,put_response,result FROM open_repair_saved_acks WHERE slot_digest=? AND request_digest=?",
                    (slot_digest,request_digest)).fetchone()
                if held is None or bytes(held["originals"])!=bytes(saved["originals"]):
                    _fail("repair_saved_corrupt")
                if held[column] is not None and bytes(held[column])!=raw:
                    _fail("repair_saved_retry_mismatch")
                if phase=="response" and held["put_journal"] is None:
                    _fail("repair_saved_corrupt")
                if sum(len(value) for name,value in dict(held).items() if name!=column and value is not None)+len(raw)>MAX_RECORD_BYTES:
                    _fail("repair_saved_capacity")
                db.execute("UPDATE open_repair_saved_acks SET "+column+"=?,attempted=1 WHERE slot_digest=?",(raw,slot_digest))

        operation=self.client.put if resume is None else self.client.resume
        args=(base_url,) if resume is None else (base_url,resume)
        result=operation(*args,entries["receipt"],entries["disclosure"],entries["put"],
            current_statuses=[*request["current_statuses"],entries["status"]],read_until=request["read_until"],retain_until=request["retain_until"],
            target_node_entry=request["target_node_entry"],expected_target=request["target"],expected_ack_slot=request["ack_slot"],
            expected_owner=request["owner"],expected_message_id=request["message_id"],expected_envelope_ref=request["envelope_ref"],
            root_entry=request["root_entry"],write_entry=request["write_entry"],bootstrap_entry=request["bootstrap_entry"],timeout=timeout,_journal=journal)
        archive=self._archive(result,budget)
        with self.delivery.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current=db.execute("SELECT originals,result,put_journal,put_response FROM open_repair_saved_acks WHERE slot_digest=? AND request_digest=?",(slot_digest,request_digest)).fetchone()
            if current is None or bytes(current["originals"])!=bytes(saved["originals"]):_fail("repair_saved_corrupt")
            if current["result"] is not None and bytes(current["result"])!=archive:_fail("repair_saved_retry_mismatch")
            if sum(len(current[name]) for name in ("originals","put_journal","put_response") if current[name] is not None)+len(archive)>MAX_RECORD_BYTES:
                _fail("repair_saved_capacity")
            db.execute("UPDATE open_repair_saved_acks SET result=? WHERE slot_digest=?",(archive,slot_digest))
        return PublishedSavedAck(result.source,result.originals,False)


def checked_epoch(request,policy,budget):
    raw,ref=ack._entry(request["target_node_entry"])
    parsed=original.verify_original_control(raw,expected_signing_key=request["target"]["signing_key"],
        expected_schema="memory-vault-open-control/v1",expected_kind="node",at=wire.parse_new_wire(raw,policy,budget).value["payload"]["issued_at"],policy=policy,budget=budget)
    if len(raw)!=ref.size or parsed.raw_sha256!=ref.raw_sha256:_fail("repair_ref_mismatch")
    return parsed.payload["storage_epoch"]
