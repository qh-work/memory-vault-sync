"""Bounded transport of the existing B put under a live bootstrap.use.

The unsigned outer carrier creates no authority. B signs the existing put and
the target-bound use; R rechecks its retained dual-key exchange and all original
permissions before the same transaction stores the receipt and replay result.
"""
from memory_vault_open_repair_offer_service import RepairOfferBootstrapService
from memory_vault_open_repair_occupied_state import RepairAckOccupiedState
from memory_vault_open_repair_service import ROW_CHARGE, _fail
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_wire as wire

MAX_BYTES = 65536
USE_FIELDS = frozenset("schema_version kind signing_key issued_at expires_at use_id subject target target_storage_epoch consumer operation bootstrap_probe_ref bootstrap_manifest_ref request_ref".split())
PACKET_FIELDS = frozenset("schema_version kind use receipt disclosure put current_statuses read_until retain_until".split())


def encode_entry(entry, policy, budget):
    item = wire.object_fields(entry,{"raw","ref"})
    ref = wire.raw_ref(item["ref"])
    raw = wire._snapshot(item["raw"],policy,budget)
    if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    return dict(ref=ref.as_dict(),raw_base64url=probe._encode(raw,budget))


def decode_entry(value, policy, budget, *, receipt=False):
    item = wire.object_fields(value,{"raw_base64url","ref"})
    ref = wire.raw_ref(item["ref"]) if receipt else probe._ref(item["ref"])
    if ref.size > (4096 if receipt else policy.max_document_bytes):
        _fail("repair_put_too_large")
    raw = original._decode64(item["raw_base64url"],ref.size,budget,url=True)
    if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    return dict(raw=raw,ref=ref.as_dict())


class RepairAckPutService(RepairOfferBootstrapService):
    resource_states = ("empty", "occupied")

    def initialize(self):
        super().initialize()
        RepairAckOccupiedState(self.state).initialize()
        with self.state._transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_put_requests(
                subject TEXT NOT NULL,use_id TEXT NOT NULL,resource_id TEXT NOT NULL,
                packet_digest TEXT NOT NULL,use_ref BLOB NOT NULL,handle_digest TEXT NOT NULL,
                generation INTEGER NOT NULL,committed_generation INTEGER,response BLOB,
                PRIMARY KEY(subject,use_id))""")

    def _request_row(self, context):
        p = context["use"]
        return self.state._one("SELECT * FROM open_repair_put_requests WHERE subject=? AND use_id=?",
            (p["subject"]["signing_key_id"],p["use_id"]))

    def _live_locked(self, context, *, generation=None):
        use, source = context["use"], self.state._row(context["source"]["resource_id"])
        handle = self.state._one("SELECT * FROM open_repair_bootstrap_handles WHERE digest=?",(context["handle"]["digest"],))
        exchange = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE subject=? AND probe_id=?",
            (context["handle"]["subject"],context["handle"]["probe_id"]))
        if (handle != context["handle"] or exchange != context["exchange"]
                or self.state._now() >= min(use["expires_at"],handle["expires_at"],context["grant"]["upload_until"])):
            return "repair_access_generation"
        request = self._request_row(context)
        if request is None:
            return "repair_put_replay_missing"
        if (request["packet_digest"] != context["packet_digest"] or bytes(request["use_ref"]) != context["use_ref_raw"]
                or request["handle_digest"] != handle["digest"] or request["resource_id"] != source["resource_id"]):
            return "repair_put_replay_conflict"
        current = self.state._one("SELECT generation FROM open_repair_access_state WHERE resource_id=?",(source["resource_id"],))
        expected = generation if generation is not None else (request["committed_generation"] or request["generation"])
        if (current is None or current["generation"] != expected
                or source["status"] != ("occupied" if request["committed_generation"] is not None else "empty")):
            return "repair_access_generation"
        return None

    def _reserve(self, context):
        p, source = context["use"], context["source"]
        with self.state._transaction():
            old = self._request_row(context)
            if old is not None:
                if old["packet_digest"] != context["packet_digest"] or bytes(old["use_ref"]) != context["use_ref_raw"]:
                    _fail("repair_put_replay_conflict")
                if old["committed_generation"] is None:
                    _fail("repair_put_replay_consumed")
            else:
                current = self.state._row(source["resource_id"])
                if current["metadata_bytes"] + ROW_CHARGE > context["capacity"]["max_meta_bytes"]:
                    _fail("repair_service_capacity")
                self.db.execute("INSERT INTO open_repair_put_requests VALUES(?,?,?,?,?,?,?,NULL,NULL)",
                    (p["subject"]["signing_key_id"],p["use_id"],source["resource_id"],context["packet_digest"],
                     context["use_ref_raw"],context["handle"]["digest"],context["handle"]["generation"]))
                self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",
                    (ROW_CHARGE,source["resource_id"]))
            code = self._live_locked(context)
            usage,_ = self._usage(source["resource_id"])
            if code is None and usage["proof_bytes"]+context["input_charge"] > context["grant"]["limits"]["max_proof_bytes"]:
                code = "repair_service_capacity"
            if code is None:
                self.db.execute("UPDATE open_repair_bootstrap_usage SET proof_bytes=proof_bytes+? WHERE resource_id=?",
                    (context["input_charge"],source["resource_id"]))
        if code:
            _fail(code)

    def put(self, raw):
        budget = wire.RepairBudget(self.state.policy)
        if wire._raw_size(raw,budget.policy) > MAX_BYTES:
            _fail("repair_put_too_large")
        packet = wire.parse_new_wire(raw,budget.policy,budget)
        body = wire.object_fields(packet.value,PACKET_FIELDS)
        if body["schema_version"] != probe.SCHEMA or body["kind"] != "ack.put_request":
            _fail("repair_put_mismatch")
        use_entry = decode_entry(body["use"],budget.policy,budget)
        use_doc, use_ref, use = self._preview(use_entry,budget)
        use = wire.object_fields(use,USE_FIELDS)
        if (use["schema_version"] != probe.SCHEMA or use["kind"] != "bootstrap.use"
                or use["consumer"] != "ack_offer" or use["operation"] != "ack.put"):
            _fail("repair_put_mismatch")
        probe._window(use,self.state._now())
        original._opaque(use["use_id"])
        subject = wire.object_fields(use["subject"],{"signing_key_id","encryption_key_id"})
        original._key_id(subject["signing_key_id"])
        original._key_id(subject["encryption_key_id"], "x25519")
        probe_ref = probe._ref(use["bootstrap_probe_ref"])
        rows = self.db.execute("""SELECT subject,probe_id FROM open_repair_bootstrap_challenges
            WHERE subject=? AND probe_digest=? LIMIT 2""",(subject["signing_key_id"],probe_ref.raw_sha256)).fetchall()
        if len(rows) != 1:
            _fail("repair_service_unavailable")
        exchange = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE subject=? AND probe_id=?",tuple(rows[0]))
        handle = self.state._one("SELECT * FROM open_repair_bootstrap_handles WHERE subject=? AND probe_id=?",tuple(rows[0]))
        if handle is None or exchange is None:
            _fail("repair_service_unavailable")
        source,grant,expected = self._context(handle["resource_id"],budget)
        if (use["subject"] != probe._dual(expected["expected_subject"])
                or use["target"] != probe._dual(self.state.target)
                or use["target_storage_epoch"] != expected["target_storage_epoch"]):
            _fail("repair_put_mismatch")
        original._verify_control_signature(use,use_doc.value["proof"],expected["expected_subject"]["signing_key"],budget)
        capacity = wire.parse_new_wire(bytes(source["active"]),budget.policy,budget).value["payload"]["budget"]
        with self._work(source,grant,capacity,use_ref,use,budget):
            frozen = self._verify_response(bytes(handle["response"]),exchange,expected,budget)
            if (probe_ref != probe._ref(frozen.handle.payload["probe_ref"])
                    or probe._ref(use["bootstrap_manifest_ref"]) != frozen.manifest_ref
                    or use["expires_at"] > min(handle["expires_at"],grant["upload_until"])):
                _fail("repair_put_mismatch")
            statuses = body["current_statuses"]
            if type(statuses) is not wire._DraftList or not 1 <= len(statuses) <= 8:
                _fail("repair_invalid_status")
            encoded = [body["receipt"],body["disclosure"],body["put"],*statuses]
            sizes = [wire.raw_ref(wire.object_fields(item,{"ref","raw_base64url"})["ref"]).size for item in encoded]
            context = dict(use=use,use_ref_raw=wire._canonical(use_ref.as_dict(),budget),packet_digest=budget._hash(packet.raw),
                source=source,grant=grant,capacity=capacity,handle=handle,exchange=exchange,input_charge=len(packet.raw)+len(use_doc.raw)+sum(sizes))
            self._reserve(context)
            decoded = [decode_entry(item,budget.policy,budget,receipt=index == 0) for index,item in enumerate(encoded)]
            if probe._ref(use["request_ref"]) != probe._ref(decoded[2]["ref"]):
                _fail("repair_put_mismatch")

            def hook(phase, held, result):
                if phase in ("prepare","commit"):
                    return self._live_locked(context,generation=held.get("last_generation") if phase == "commit" else None)
                if phase == "result":
                    refs = sorted({wire.raw_ref(row["pack_ref"]) for row in
                        wire.parse_new_wire(result["manifest"]["raw"],budget.policy,budget).value["roles"]},
                        key=lambda item:(item.namespace,item.key,item.raw_sha256,item.size))
                    packs = [held["resolver"].resolve(ref) for ref in refs]
                    response = wire.build_new_wire(dict(schema_version=probe.SCHEMA,kind="ack.put_response",use_ref=use_ref.as_dict(),
                        **{name:encode_entry(result[name],budget.policy,budget) for name in ("manifest","commit","head")},
                        packs=[encode_entry(dict(raw=item.raw,ref=item.ref.as_dict()),budget.policy,budget) for item in packs]),budget.policy,budget).raw
                    if len(response) > MAX_BYTES:
                        _fail("repair_put_too_large")
                    context["response"] = response
                    context["output_charge"] = len(response)+sum(len(item["raw"]) for item in result.values())+sum(len(item.raw) for item in packs)
                    return None
                if phase == "publish":
                    request = self._request_row(context)
                    if request is None:
                        return "repair_put_replay_missing"
                    response = context["response"]
                    if request["response"] is not None and bytes(request["response"]) != response:
                        return "repair_put_replay_conflict"
                    usage,_ = self._usage(source["resource_id"])
                    current = self.state._row(source["resource_id"])
                    charge = 0 if request["response"] is not None else len(response)
                    if (usage["proof_bytes"]+context["output_charge"] > grant["limits"]["max_proof_bytes"]
                            or current["metadata_bytes"]+charge > capacity["max_meta_bytes"]):
                        return "repair_service_capacity"
                    generation = self.state._one("SELECT generation FROM open_repair_access_state WHERE resource_id=?",(source["resource_id"],))["generation"]
                    self.db.execute("UPDATE open_repair_put_requests SET committed_generation=?,response=? WHERE subject=? AND use_id=?",
                        (generation,response,use["subject"]["signing_key_id"],use["use_id"]))
                    self.db.execute("UPDATE open_repair_bootstrap_usage SET proof_bytes=proof_bytes+? WHERE resource_id=?",
                        (context["output_charge"],source["resource_id"]))
                    self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,source["resource_id"]))
                    return None
                _fail("repair_invalid_context")

            RepairAckOccupiedState(self.state).put(source["resource_id"],*decoded[:3],current_statuses=decoded[3:],
                read_until=body["read_until"],retain_until=body["retain_until"],policy=budget.policy,budget=budget,_transaction_hook=hook)
            return context["response"]
