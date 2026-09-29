"""Finite original-R owner binding after a complete owner service preflight.

This is a separate section-8 control operation. The B ack_offer grant never
acts as A's owner permission. Its two uploaded originals are authenticated
under A's already configured root and the existing durable bind transaction.
"""
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_empty_state import RepairAckEmptyState
from memory_vault_open_repair_service import RepairBootstrapService, ROW_CHARGE

MAX_BYTES = 65536
FIELDS = frozenset("schema_version kind signing_key issued_at expires_at request_id subject target target_storage_epoch purpose consumer probe_ref handle_ref manifest_ref service_generation write offer receipt_writer message_id envelope_ref current_statuses read_until retain_until".split())
RESULT_FIELDS = frozenset("schema_version kind request_ref binding manifest custody head packs".split())


def _fail(code):
    wire._fail(code)


def encode_entry(entry, policy, budget):
    raw, ref = ack._entry(entry)
    raw = wire._snapshot(raw, policy, budget)
    if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    return dict(ref=ref.as_dict(), raw_base64url=probe._encode(raw,budget))


def decode_entry(entry, policy, budget):
    value = wire.object_fields(entry,{"ref","raw_base64url"})
    ref = ack._ref(value["ref"])
    if ref.size > MAX_BYTES:
        _fail("repair_bind_too_large")
    raw = original._decode64(value["raw_base64url"],ref.size,budget,url=True)
    if budget._hash(raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    return dict(raw=raw,ref=ref.as_dict())


MAX_MAILBOX_DRAFT_BYTES = 131072


def encode_mailbox_draft(raw, policy, budget, *, compact=False):
    """Transport whole draft bytes; compression never changes signed originals."""
    import zlib
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_MAILBOX_DRAFT_BYTES:
        _fail('repair_message_capacity')
    digest = budget._hash(raw)
    ref = dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw))
    if not compact:
        return dict(raw=raw.decode('utf-8'), ref=ref)
    compressed = zlib.compress(raw)
    budget._bytes('output_bytes', len(compressed))
    return dict(codec='zlib-base64url-v1', compressed_size=len(compressed),
                raw_base64url=probe._encode(compressed, budget), ref=ref)


def decode_mailbox_draft(value, policy, budget):
    """Bound expansion before allocation, reject trailing/truncated streams."""
    import zlib
    if type(value) not in (dict, wire._DraftDict):
        _fail('repair_message_mismatch')
    compact = 'codec' in value
    wire.object_fields(value, {'codec','compressed_size','raw_base64url','ref'} if compact else {'raw','ref'})
    ref = wire.raw_ref(value['ref'])
    if ref.namespace != 'meta' or not 0 < ref.size <= MAX_MAILBOX_DRAFT_BYTES:
        _fail('repair_message_capacity')
    if compact:
        size = wire.u53(value['compressed_size'])
        if value['codec'] != 'zlib-base64url-v1' or not 0 < size <= MAX_BYTES:
            _fail('repair_message_mismatch')
        compressed = original._decode64(value['raw_base64url'], size, budget, url=True)
        # One extra byte detects expansion beyond the declared original size.
        budget._fits('output_bytes', ref.size + 1, policy.max_total_bytes - budget._usage['input_bytes'])
        decoder = zlib.decompressobj()
        try:
            raw = decoder.decompress(compressed, ref.size + 1)
        except zlib.error:
            _fail('repair_message_mismatch')
        budget._bytes('output_bytes', len(raw))
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            _fail('repair_message_mismatch')
    else:
        if type(value['raw']) is not str or len(value['raw']) > MAX_MAILBOX_DRAFT_BYTES:
            _fail('repair_message_mismatch')
        raw = value['raw'].encode('utf-8')
        budget._bytes('output_bytes', len(raw))
    if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        _fail('repair_ref_mismatch')
    return dict(raw=raw, ref=ref.as_dict())


class RepairOwnerBindService(RepairBootstrapService):
    """A live owner handle plus a fresh signature, never a bearer upload."""
    def initialize(self):
        super().initialize()
        RepairAckEmptyState(self.state).initialize()
        with self.state._transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_owner_bind_requests(
                subject TEXT NOT NULL,request_id TEXT NOT NULL,resource_id TEXT NOT NULL,
                digest TEXT NOT NULL,request_ref BLOB NOT NULL,handle_digest TEXT NOT NULL,
                generation INTEGER NOT NULL,committed_generation INTEGER,response BLOB,
                PRIMARY KEY(subject,request_id))""")

    def _context(self,resource_id,budget):
        # An exact successful retry still verifies the original unbound handle.
        # New requests are restricted to an unbound resource by _live_locked.
        row = self.state._row(resource_id)
        if row["status"] not in ("unbound","empty"):
            _fail("repair_service_unavailable")
        setup = wire.parse_new_wire(bytes(row["activation_inputs"]),budget.policy,budget).value
        grant = wire.parse_new_wire(setup["bootstrap"]["raw"].encode(),budget.policy,budget).value["payload"]
        owner = wire.parse_new_wire(bytes(row["owner_keys"]),budget.policy,budget).value
        return row,grant,dict(expected_subject=owner,expected_target=self.state.target,
            target_storage_epoch=self.state.node["payload"]["storage_epoch"],
            bootstrap_grant_sha256=setup["bootstrap"]["ref"]["raw_sha256"],selector=grant["selector"],
            at=self.state._now(),policy=budget.policy,budget=budget)

    def _request_row(self,payload):
        return self.state._one("SELECT * FROM open_repair_owner_bind_requests WHERE subject=? AND request_id=?",
            (payload["subject"]["signing_key_id"],payload["request_id"]))

    def _live_locked(self,context,*,generation=None):
        p, reference = context["payload"],context["reference"]
        now = self.state._now()
        source = self.state._row(context["source"]["resource_id"])
        live = self.state._one("SELECT * FROM open_repair_bootstrap_handles WHERE digest=?",(context["handle"]["digest"],))
        exchange = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE subject=? AND probe_id=?",
            (context["handle"]["subject"],context["handle"]["probe_id"]))
        if (live != context["handle"] or exchange != context["exchange"]
                or now >= min(p["expires_at"],live["expires_at"],context["grant"]["upload_until"])):
            return "repair_access_generation"
        current = self.state._one("SELECT generation FROM open_repair_access_state WHERE resource_id=?",(source["resource_id"],))
        request = self._request_row(p)
        if request is None:
            return "repair_bind_replay_missing"
        if (request["digest"] != reference.raw_sha256 or bytes(request["request_ref"]) != context["ref_raw"]
                or request["handle_digest"] != live["digest"] or request["resource_id"] != source["resource_id"]):
            return "repair_bind_replay_conflict"
        expected = generation if generation is not None else (request["committed_generation"] or request["generation"])
        if current is None or current["generation"] != expected:
            return "repair_access_generation"
        if source["status"] != ("empty" if request["committed_generation"] is not None else "unbound"):
            return "repair_access_generation"
        return None

    def _reserve(self,context):
        p,source,grant = context["payload"],context["source"],context["grant"]
        with self.state._transaction():
            old = self._request_row(p)
            if old is not None:
                if old["digest"] != context["reference"].raw_sha256 or bytes(old["request_ref"]) != context["ref_raw"]:
                    _fail("repair_bind_replay_conflict")
                if old["committed_generation"] is None:
                    _fail("repair_bind_replay_consumed")
            else:
                current = self.state._row(source["resource_id"])
                if current["metadata_bytes"]+ROW_CHARGE > context["capacity"]["max_meta_bytes"]:
                    _fail("repair_service_capacity")
                self.db.execute("INSERT INTO open_repair_owner_bind_requests VALUES(?,?,?,?,?,?,?,NULL,NULL)",
                    (p["subject"]["signing_key_id"],p["request_id"],source["resource_id"],context["reference"].raw_sha256,
                     context["ref_raw"],context["handle"]["digest"],p["service_generation"]))
                self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",
                    (ROW_CHARGE,source["resource_id"]))
            code = self._live_locked(context)
            usage,_ = self._usage(source["resource_id"])
            if code is None and usage["proof_bytes"]+context["input_charge"] > grant["limits"]["max_proof_bytes"]:
                code = "repair_service_capacity"
            if code is None:
                self.db.execute("UPDATE open_repair_bootstrap_usage SET proof_bytes=proof_bytes+? WHERE resource_id=?",
                    (context["input_charge"],source["resource_id"]))
        if code:
            _fail(code)

    def bind(self,entry):
        budget = wire.RepairBudget(self.state.policy)
        parsed,ref,payload = self._preview(entry,budget)
        p = wire.object_fields(payload,FIELDS)
        handle_ref = probe._ref(p["handle_ref"])
        handle = self.state._one("SELECT * FROM open_repair_bootstrap_handles WHERE digest=?",(handle_ref.raw_sha256,))
        if handle is None:
            _fail("repair_service_unavailable")
        source,grant,expected = self._context(handle["resource_id"],budget)
        if (p["schema_version"] != probe.SCHEMA or p["kind"] != "ack.bind_request" or p["purpose"] != "ack.owner_bind"
                or p["consumer"] != "ack_owner" or p["subject"] != probe._dual(expected["expected_subject"])
                or p["target"] != probe._dual(expected["expected_target"])
                or p["target_storage_epoch"] != expected["target_storage_epoch"]):
            _fail("repair_bind_mismatch")
        probe._window(p,self.state._now())
        original._opaque(p["request_id"])
        original._verify_control_signature(p,parsed.value["proof"],expected["expected_subject"]["signing_key"],budget)
        capacity = wire.parse_new_wire(bytes(source["active"]),budget.policy,budget).value["payload"]["budget"]
        # _work admits and meters this same private budget; failed evidence
        # never resets it. Fixed 64-check admission is deliberately finite.
        with self._work(source,grant,capacity,ref,p,budget):
            exchange = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE subject=? AND probe_id=?",
                (handle["subject"],handle["probe_id"]))
            if exchange is None:
                _fail("repair_service_unavailable")
            frozen = self._verify_response(bytes(handle["response"]),exchange,expected,budget)
            if (frozen.handle.ref != handle_ref or probe._ref(p["manifest_ref"]) != frozen.manifest_ref
                    or probe._ref(p["probe_ref"]) != probe._ref(frozen.handle.payload["probe_ref"])
                    or wire.u53(p["service_generation"],1) != frozen.handle.payload["service_generation"]
                    or handle["generation"] != p["service_generation"]
                    or p["expires_at"] > min(handle["expires_at"],grant["upload_until"])
                    or not {"ack.write_grant","bootstrap.grant"}.issubset(grant["upload_roles"])):
                _fail("repair_bind_mismatch")
            statuses = p["current_statuses"]
            if type(statuses) is not wire._DraftList or not 1 <= len(statuses) <= 7:
                _fail("repair_invalid_status")
            encoded = [p["write"],p["offer"],*statuses]
            # Exact size metadata is bounded before decoding and included in
            # the persistent encoded+decoded transfer allowance.
            sizes = [ack._ref(wire.object_fields(value,{"ref","raw_base64url"})["ref"]).size for value in encoded]
            context = dict(payload=p,reference=ref,ref_raw=wire._canonical(ref.as_dict(),budget),
                source=source,grant=grant,capacity=capacity,handle=handle,exchange=exchange,
                input_charge=len(parsed.raw)+sum(sizes),budget=budget)
            self._reserve(context)
            decoded = [decode_entry(value,budget.policy,budget) for value in encoded]
            target_status = decoded[2:]
            state = RepairAckEmptyState(self.state)

            def hook(phase,held,result):
                if phase in ("prepare","commit"):
                    return self._live_locked(context,generation=held.get("last_generation") if phase == "commit" else None)
                if phase == "result":
                    refs = sorted({wire.raw_ref(row["pack_ref"]) for row in
                        wire.parse_new_wire(result["manifest"]["raw"],budget.policy,budget).value["roles"]},
                        key=lambda item:(item.namespace,item.key,item.raw_sha256,item.size))
                    packs = [held["resolver"].resolve(reference) for reference in refs]
                    value = dict(schema_version=probe.SCHEMA,kind="ack.bind_response",request_ref=ref.as_dict(),
                        **{name:encode_entry(result[name],budget.policy,budget) for name in ("binding","manifest","custody","head")},
                        packs=[encode_entry(dict(raw=item.raw,ref=item.ref.as_dict()),budget.policy,budget) for item in packs])
                    response = wire.build_new_wire(value,budget.policy,budget).raw
                    if len(response)>MAX_BYTES:
                        _fail("repair_bind_too_large")
                    context["response"] = response
                    context["output_charge"] = len(response)+sum(len(result[name]["raw"]) for name in result)+sum(len(item.raw) for item in packs)
                    return None
                if phase == "publish":
                    request = self._request_row(p)
                    if request is None:
                        return "repair_bind_replay_missing"
                    response = context["response"]
                    if request["response"] is not None and bytes(request["response"]) != response:
                        return "repair_bind_replay_conflict"
                    usage,_ = self._usage(source["resource_id"])
                    current = self.state._row(source["resource_id"])
                    charge = 0 if request["response"] is not None else len(response)
                    if (usage["proof_bytes"]+context["output_charge"] > grant["limits"]["max_proof_bytes"]
                            or current["metadata_bytes"]+charge > capacity["max_meta_bytes"]):
                        return "repair_service_capacity"
                    generation = self.state._one("SELECT generation FROM open_repair_access_state WHERE resource_id=?",(source["resource_id"],))["generation"]
                    self.db.execute("UPDATE open_repair_owner_bind_requests SET committed_generation=?,response=? WHERE subject=? AND request_id=?",
                        (generation,response,p["subject"]["signing_key_id"],p["request_id"]))
                    self.db.execute("UPDATE open_repair_bootstrap_usage SET proof_bytes=proof_bytes+? WHERE resource_id=?",
                        (context["output_charge"],source["resource_id"]))
                    self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,source["resource_id"]))
                    return None
                _fail("repair_invalid_context")

            state.bind(source["resource_id"],decoded[0],decoded[1],expected_receipt_writer=p["receipt_writer"],
                expected_message_id=p["message_id"],expected_envelope_ref=p["envelope_ref"],current_statuses=target_status,
                read_until=p["read_until"],retain_until=p["retain_until"],_budget=budget,_transaction_hook=hook)
            return wire.parse_new_wire(context["response"],budget.policy,budget)
