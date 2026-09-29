"""Durable ACK-owner mutual possession and finite protected proof reads.

Every permission refusal returned by the access ledger is committed before it
is raised. Crypto and response construction happen outside writer locks; the
current generation is checked again before publishing any prepared response.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import secrets

from memory_vault import canonical_bytes
from memory_vault_open_repair_access import RepairAckAccess
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire

ROW_CHARGE = 1024


def _fail(code):
    raise wire.RepairWireError(code)


def _entry(original):
    return dict(raw=original.raw, ref=original.ref.as_dict())


class RepairBootstrapService:
    resource_state = "unbound"
    consumer = "ack_owner"
    response_profile = "ack_owner_service_v1"

    def __init__(self, state):
        self.state, self.db = state, state.db
        self.access = RepairAckAccess(state)

    def initialize(self):
        self.access.initialize()
        with self.state._transaction():
            for sql in (
                """CREATE TABLE IF NOT EXISTS open_repair_bootstrap_usage(
                    resource_id TEXT PRIMARY KEY,requests INTEGER NOT NULL,signatures INTEGER NOT NULL,
                    proof_bytes INTEGER NOT NULL,replays INTEGER NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS open_repair_bootstrap_work(
                    attempt_id TEXT PRIMARY KEY,resource_id TEXT NOT NULL,request_digest TEXT NOT NULL,
                    signature_allowance INTEGER NOT NULL,signature_checks INTEGER,
                    created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS open_repair_bootstrap_challenges(
                    subject TEXT NOT NULL,probe_id TEXT NOT NULL,resource_id TEXT NOT NULL,probe_digest TEXT NOT NULL,
                    probe BLOB NOT NULL,probe_ref BLOB NOT NULL,challenge BLOB NOT NULL,challenge_ref BLOB NOT NULL,
                    challenge_digest TEXT NOT NULL UNIQUE,nonce BLOB NOT NULL,generation INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,answer_digest TEXT,response BLOB,handle_ref BLOB,
                    PRIMARY KEY(subject,probe_id))""",
                """CREATE TABLE IF NOT EXISTS open_repair_bootstrap_handles(
                    digest TEXT PRIMARY KEY,resource_id TEXT NOT NULL,subject TEXT NOT NULL,probe_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,response BLOB NOT NULL,expires_at INTEGER NOT NULL,
                    UNIQUE(subject,probe_id))""",
                """CREATE TABLE IF NOT EXISTS open_repair_bootstrap_requests(
                    subject TEXT NOT NULL,request_id TEXT NOT NULL,resource_id TEXT NOT NULL,handle_digest TEXT NOT NULL,
                    digest TEXT NOT NULL,PRIMARY KEY(subject,request_id))""",
            ):
                self.db.execute(sql)

    def _preview(self, entry, budget):
        raw, reference = ack._entry(entry)
        if wire._raw_size(raw, budget.policy) > proof.MAX_RESPONSE_BYTES:
            _fail("repair_proof_too_large")
        parsed = wire.parse_new_wire(raw, budget.policy, budget)
        if len(parsed.raw) != reference.size or budget._hash(parsed.raw) != reference.raw_sha256:
            _fail("repair_ref_mismatch")
        signed = ack._fields(parsed.value, {"payload", "proof"})
        if type(signed["payload"]) is not wire._DraftDict:
            _fail("repair_invalid_probe")
        return parsed, reference, signed["payload"]

    def _context(self, resource_id, budget):
        row = self.state._row(resource_id)
        if row["status"] != self.resource_state:
            _fail("repair_service_unavailable")
        setup = wire.parse_new_wire(bytes(row["activation_inputs"]), budget.policy, budget).value
        grant = wire.parse_new_wire(setup["bootstrap"]["raw"].encode(), budget.policy, budget).value["payload"]
        owner = wire.parse_new_wire(bytes(row["owner_keys"]), budget.policy, budget).value
        return row, grant, dict(expected_subject=owner, expected_target=self.state.target,
            target_storage_epoch=self.state.node["payload"]["storage_epoch"],
            bootstrap_grant_sha256=setup["bootstrap"]["ref"]["raw_sha256"], selector=grant["selector"],
            at=self.state._now(), policy=budget.policy, budget=budget, consumer=self.consumer)

    def _grant_entry(self, resource_id):
        setup = json.loads(bytes(self.state._row(resource_id)["activation_inputs"]))
        return dict(raw=setup["bootstrap"]["raw"].encode(), ref=setup["bootstrap"]["ref"])

    def _lookup_probe(self, payload):
        # A selector is only a lookup hint. The complete saved source and the
        # independently held owner/target keys are authenticated before use.
        closed = probe._fields(payload, probe._FIELDS["probe"])
        grant_hash = closed["bootstrap_grant_sha256"]
        probe._shape(probe.original._digest, grant_hash)
        subject = resource._dual_key_shape(closed["subject"])
        rows = self.db.execute("""SELECT resource_id FROM open_repair_ack_resources WHERE owner=? AND status=?
            AND json_extract(activation_inputs,'$.bootstrap.ref.raw_sha256')=? LIMIT 2""",
            (subject["signing_key"]["key_id"], self.resource_state, grant_hash)).fetchall()
        if len(rows) != 1:
            _fail("repair_service_unavailable")
        return rows[0][0]

    def _saved_original(self, row, name, budget):
        parsed, ref, payload = self._preview(dict(raw=bytes(row[name]), ref=json.loads(bytes(row[name+"_ref"]))), budget)
        return resource.AuthenticatedRepairOriginal(parsed.raw, ref, payload)

    def _usage(self, resource_id):
        row = self.state._one("SELECT * FROM open_repair_bootstrap_usage WHERE resource_id=?", (resource_id,))
        reserved = self.db.execute("SELECT coalesce(sum(signature_allowance),0) FROM open_repair_bootstrap_work WHERE resource_id=? AND signature_checks IS NULL", (resource_id,)).fetchone()[0]
        return row, reserved

    def _room(self, source, grant, active, row, reserved, signatures):
        usage = row or dict(requests=0, signatures=0, proof_bytes=0, replays=0)
        metadata = ROW_CHARGE * (1 if row else 2)
        limits = grant["limits"]
        return (usage["requests"] < min(limits["max_requests"], active["max_requests"])
            and usage["signatures"] + reserved + signatures <= limits["max_signature_checks"]
            and usage["replays"] < min(limits["max_replay_records"], active["max_replay_records"])
            and source["metadata_bytes"] + metadata <= active["max_meta_bytes"])

    @contextmanager
    def _work(self, source, grant, active, reference, payload, budget):
        # The one caller authentication is outside grant admission. A failed
        # proof never charges the nominated owner. Concurrent admissions are
        # serialized before any historical or current authority verification.
        allowance = budget.policy.max_signature_checks
        attempt = "work_" + secrets.token_hex(16)
        with self.state._transaction() as now:
            current = self.state._row(source["resource_id"])
            if any(current[name] != source[name] for name in ("status", "activation_inputs", "owner_keys", "active")):
                _fail("repair_access_generation")
            row, reserved = self._usage(source["resource_id"])
            if not self._room(current, grant, active, row, reserved, allowance):
                _fail("repair_service_capacity")
            metadata = ROW_CHARGE * (1 if row else 2)
            self.db.execute("""INSERT INTO open_repair_bootstrap_usage VALUES(?,1,0,0,1)
                ON CONFLICT(resource_id) DO UPDATE SET requests=requests+1,replays=replays+1""", (source["resource_id"],))
            self.db.execute("INSERT INTO open_repair_bootstrap_work VALUES(?,?,?,?,NULL,?,?)",
                (attempt, source["resource_id"], reference.raw_sha256, allowance, now, payload["expires_at"]))
            self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",
                (metadata, source["resource_id"]))
        try:
            yield
        finally:
            # Unused reservation is released; work already done is never
            # refunded. Interrupted processes leave their full reservation
            # charged indefinitely, including after restart or packet expiry.
            actual = budget.snapshot()["signature_checks"]
            with self.state._transaction():
                held = self.state._one("SELECT * FROM open_repair_bootstrap_work WHERE attempt_id=?", (attempt,))
                if held is None or held["signature_checks"] is not None or not 1 <= actual <= held["signature_allowance"]:
                    _fail("repair_service_work_corrupt")
                self.db.execute("UPDATE open_repair_bootstrap_work SET signature_checks=? WHERE attempt_id=?", (actual, attempt))
                self.db.execute("UPDATE open_repair_bootstrap_usage SET signatures=signatures+? WHERE resource_id=?",
                    (actual, source["resource_id"]))

    def _active_budget(self, source, budget):
        return wire.parse_new_wire(bytes(source["active"]),budget.policy,budget).value["payload"]["budget"]

    def _run(self, entry, kind, current_statuses=None):
        budget = wire.RepairBudget(self.state.policy)
        parsed, reference, payload = self._preview(entry, budget)
        payload = (proof._fields(payload, proof.CHILD_FIELDS-{"bootstrap_grant_sha256"}) if kind == "child"
                   else probe._fields(payload, probe._FIELDS[kind]))
        if kind == "probe":
            resource_id = self._lookup_probe(payload)
        elif kind == "answer":
            parent = probe._ref(payload["challenge_ref"])
            row = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE challenge_digest=?", (parent.raw_sha256,))
            if row is None or json.loads(bytes(row["challenge_ref"])) != parent.as_dict():
                _fail("repair_service_unavailable")
            resource_id = row["resource_id"]
        else:
            parent = probe._ref(payload["handle_ref"])
            row = self.state._one("SELECT * FROM open_repair_bootstrap_handles WHERE digest=?", (parent.raw_sha256,))
            if row is None:
                _fail("repair_service_unavailable")
            resource_id = row["resource_id"]
        source, grant, expected = self._context(resource_id, budget)
        active = self._active_budget(source, budget)
        row, reserved = self._usage(resource_id)
        remaining = grant["limits"]["max_signature_checks"] - reserved - (row["signatures"] if row else 0)
        allowance = min(remaining, self.state.policy.max_signature_checks)
        if allowance < 1 or not self._room(source, grant, active, row, reserved, allowance):
            _fail("repair_service_capacity")
        # Lookup parsing is a separately bounded, signature-free preflight.
        # The private execution meter is fixed before caller authentication;
        # no cryptographic work is reset when the grant has a smaller tail.
        # Admission may conservatively refuse if a concurrent caller reserved
        # that tail after this read. It never increases this private allowance.
        packet = dict(raw=parsed.raw, ref=reference.as_dict())
        budget = wire.RepairBudget(replace(self.state.policy, max_signature_checks=allowance))
        parsed, reference, payload = self._preview(packet, budget)
        source, grant, expected = self._context(resource_id, budget)
        active = self._active_budget(source, budget)
        subject, target = expected["expected_subject"], expected["expected_target"]
        if (payload["schema_version"] != proof.SCHEMA or payload["kind"] != "bootstrap." + ("proof_child_request" if kind == "child" else kind)
                or payload["purpose"] != ("bootstrap.service_proof_child" if kind == "child" else "bootstrap.service_proof")
                or payload["consumer"] != self.consumer
                or payload["subject"] != (subject if kind == "probe" else probe._dual(subject))
                or payload["target"] != (target if kind == "probe" else probe._dual(target))
                or payload["target_storage_epoch"] != expected["target_storage_epoch"]
                or (kind != "child" and payload["bootstrap_grant_sha256"] != expected["bootstrap_grant_sha256"])):
            _fail("repair_probe_mismatch")
        probe._window(payload, expected["at"])
        probe.original._verify_control_signature(payload, parsed.value["proof"], subject["signing_key"], budget)
        try:
            with self._work(source, grant, active, reference, payload, budget):
                packet = dict(raw=parsed.raw, ref=reference.as_dict())
                if kind == "probe":
                    return self._challenge(packet, current_statuses=current_statuses, budget=budget, capacity=active)
                return self._answer(packet, budget=budget, capacity=active) if kind == "answer" else self._child(packet, budget=budget, capacity=active)
        except wire.RepairWireError as exc:
            if exc.code == "repair_over_budget" and budget.snapshot()["signature_checks"] >= allowance:
                _fail("repair_service_capacity")
            raise

    def challenge(self, probe_entry, *, current_statuses=None):
        return self._run(probe_entry, "probe", current_statuses)

    def answer(self, answer_entry):
        return self._run(answer_entry, "answer")

    def child(self, request_entry):
        return self._run(request_entry, "child")

    def _charge_locked(self, decision, *, proof_bytes, metadata, capacity, replay=True):
        limits = decision.limit_policy
        row, _ = self._usage(decision.resource_id)
        source = self.state._row(decision.resource_id)
        # Only publication charges remain here. Each admitted attempt already
        # owns its request/work/replay row, including every refused operation.
        if row is None:
            _fail("repair_service_work_corrupt")
        if (row["proof_bytes"]+proof_bytes > limits["max_proof_bytes"] or
                row["replays"]+int(replay) > min(limits["max_replay_records"],capacity["max_replay_records"]) or
                source["metadata_bytes"]+metadata > capacity["max_meta_bytes"]):
            return False
        self.db.execute("UPDATE open_repair_bootstrap_usage SET proof_bytes=proof_bytes+?,replays=replays+? WHERE resource_id=?",
            (proof_bytes,int(replay),decision.resource_id))
        self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",
            (metadata,decision.resource_id))
        return True

    def _challenge(self, probe_entry, *, current_statuses=None, budget, capacity):
        parsed, reference, payload = self._preview(probe_entry, budget)
        resource_id = self._lookup_probe(payload)
        _, grant, expected = self._context(resource_id,budget)
        verified = probe.verify_bootstrap_probe(dict(raw=parsed.raw,ref=reference.as_dict()), **expected)
        if len(parsed.raw) > grant["limits"]["max_probe_bytes"]:
            _fail("repair_service_capacity")
        prepared = self.access.prepare(resource_id,action="challenge",current_statuses=current_statuses,
                                       policy=budget.policy,budget=budget)
        # Persist every authenticated status observation before a subsequent
        # encryption, output-budget or publication failure can abort service.
        with self.state._transaction():
            first_decision = self.access.check_locked(prepared)
        if not first_decision.allowed:
            _fail(first_decision.code)
        created = probe.issue_bootstrap_challenge(_entry(verified),signer=self.state.identity,
            encryption_identity=self.state.encryption_identity,**expected,expires_at=verified.payload["expires_at"])
        code, result, saved_result = None, created.original, None
        with self.state._transaction() as now:
            decision = self.access.check_locked(prepared)
            if not decision.allowed:
                code = decision.code
            elif now >= created.original.payload["expires_at"] or created.original.payload["expires_at"] > decision.expires_at:
                code = "repair_access_expired"
            else:
                subject, probe_id = verified.payload["subject"]["signing_key"]["key_id"], verified.payload["probe_id"]
                old = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE subject=? AND probe_id=?",(subject,probe_id))
                if old is not None:
                    if old["probe_digest"] != reference.raw_sha256 or bytes(old["probe_ref"]) != canonical_bytes(reference.as_dict()):
                        code = "repair_probe_replay_conflict"
                    elif old["generation"] != decision.generation or now >= old["expires_at"]:
                        code = "repair_access_generation"
                    else:
                        if self._charge_locked(decision,capacity=capacity,proof_bytes=0,metadata=0,replay=False):
                            saved_result = old
                        else:
                            code = "repair_service_capacity"
                else:
                    pending = self.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges WHERE resource_id=? AND answer_digest IS NULL AND expires_at>?",(resource_id,now)).fetchone()[0]
                    if pending >= decision.limit_policy["max_pending"]:
                        code = "repair_service_capacity"
                    else:
                        if self._charge_locked(decision,capacity=capacity,proof_bytes=0,
                                metadata=len(parsed.raw)+len(result.raw)+len(created.nonce)+ROW_CHARGE):
                            self.db.execute("""INSERT INTO open_repair_bootstrap_challenges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)""",
                                (subject,probe_id,resource_id,reference.raw_sha256,parsed.raw,canonical_bytes(reference.as_dict()),
                                 result.raw,canonical_bytes(result.ref.as_dict()),result.ref.raw_sha256,created.nonce,decision.generation,result.payload["expires_at"]))
                        else:
                            code = "repair_service_capacity"
        if code:
            _fail(code)
        if saved_result is not None:
            result = self._saved_original(saved_result,"challenge",budget)
        return result

    def _exchange(self, row, budget):
        return self._saved_original(row,"probe",budget), self._saved_original(row,"challenge",budget)

    def _verify_response(self, raw, row, expected, budget):
        p,c = self._exchange(row,budget)
        answer_ref = json.loads(bytes(row["handle_ref"]))["answer_ref"]
        grant = self._grant_entry(row["resource_id"])
        limits = json.loads(grant["raw"])["payload"]["limits"]
        return proof.verify_bootstrap_proof_response(raw,expected_subject=expected["expected_subject"],expected_target=expected["expected_target"],
            target_storage_epoch=expected["target_storage_epoch"],selector=expected["selector"],bootstrap_grant_ref=grant["ref"],
            probe_ref=p.ref.as_dict(),challenge_ref=c.ref.as_dict(),answer_ref=answer_ref,at=self.state._now(),
            max_proof_items=limits["max_proof_items"], max_proof_bytes=limits["max_proof_bytes"],
            expected_source_state=self.resource_state,consumer=self.consumer,policy=budget.policy,budget=budget)

    def _answer(self, answer_entry, *, budget, capacity):
        parsed, reference, payload = self._preview(answer_entry,budget)
        payload = probe._fields(payload,probe._FIELDS["answer"])
        challenge_ref = probe._ref(payload["challenge_ref"])
        row = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE challenge_digest=?",(challenge_ref.raw_sha256,))
        if row is None or challenge_ref.as_dict() != json.loads(bytes(row["challenge_ref"])):
            _fail("repair_service_unavailable")
        _,_,expected = self._context(row["resource_id"],budget)
        p,c = self._exchange(row,budget)
        exchange = probe.verify_bootstrap_answer(_entry(p),_entry(c),dict(raw=parsed.raw,ref=reference.as_dict()),
            caller_nonce=bytes(row["nonce"]),**expected)
        prepared = self.access.prepare(row["resource_id"],action="proof",expected_generation=row["generation"],
                                       policy=budget.policy,budget=budget)
        # Freeze source inputs in a short transaction. No response is signed or
        # exposed here; a second current check follows outside-lock construction.
        code, children, decision = None, (), None
        with self.state._transaction():
            decision = self.access.check_locked(prepared)
            if decision.allowed:
                decision,children = self.access.proof_inputs(prepared)
            if not decision.allowed:
                code = decision.code
        if code:
            _fail(code)
        if len(children)>decision.limit_policy["max_proof_items"]:
            _fail("repair_service_capacity")
        manifest = dict(schema_version=proof.SCHEMA,kind="bootstrap.proof_manifest",probe_ref=p.ref.as_dict(),
            subject=dict(decision.subject),target=probe._dual(self.state.target),target_storage_epoch=expected["target_storage_epoch"],
            consumer=self.consumer,selector=dict(decision.selector),bootstrap_grant_ref=decision.bootstrap_grant_ref.as_dict(),
            service_generation=decision.generation,response_profile=self.response_profile,
            children=[dict(index=index,role=item["role"],ref=item["ref"].as_dict()) for index,item in enumerate(children)])
        response = proof.make_bootstrap_proof_response(self.state.identity,manifest,probe_ref=p.ref.as_dict(),challenge_ref=c.ref.as_dict(),
            answer_ref=exchange.originals["answer"].ref.as_dict(),subject=expected["expected_subject"],target=self.state.target,
            at=self.state._now(),expires_at=min(c.payload["expires_at"],decision.expires_at),handle_id="handle_"+secrets.token_hex(16),
            policy=budget.policy,budget=budget)
        candidate = proof.verify_bootstrap_proof_response(response.raw,expected_subject=expected["expected_subject"],expected_target=self.state.target,
            target_storage_epoch=expected["target_storage_epoch"],selector=dict(decision.selector),bootstrap_grant_ref=decision.bootstrap_grant_ref.as_dict(),
            probe_ref=p.ref.as_dict(),challenge_ref=c.ref.as_dict(),answer_ref=exchange.originals["answer"].ref.as_dict(),at=self.state._now(),
            max_proof_items=decision.limit_policy["max_proof_items"],max_proof_bytes=decision.limit_policy["max_proof_bytes"],
            expected_source_state=self.resource_state,consumer=self.consumer,policy=budget.policy,budget=budget)
        # Reuse the authenticated immutable preparation. check_locked below
        # rechecks its complete retained-byte stamp and current status floors;
        # repeating the cryptography would consume the same operation budget
        # twice without strengthening that final publication guard.
        # An exact retry transmits encoded and decoded originals again. Its
        # saved response is authenticated outside the writer transaction.
        previous_response = None
        previous_size = None
        if row["answer_digest"] is not None:
            previous_response = bytes(row["response"])
            previous = self._verify_response(previous_response, row, expected, budget)
            previous_size = len(previous_response) + len(previous.handle.raw) + len(previous.manifest.raw)
        result, saved_response = response, None
        with self.state._transaction() as now:
            current = self.access.check_locked(prepared)
            if not current.allowed:
                code = current.code
            elif now >= candidate.handle.payload["expires_at"]:
                code = "repair_access_expired"
            else:
                held = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE challenge_digest=?",(challenge_ref.raw_sha256,))
                if held["answer_digest"] is not None:
                    if (held["answer_digest"] != reference.raw_sha256 or
                            json.loads(bytes(held["handle_ref"]))["answer_ref"] != reference.as_dict()):
                        code = "repair_probe_replay_conflict"
                    elif previous_response is None or bytes(held["response"]) != previous_response:
                        code = "repair_access_generation"
                    else:
                        if self._charge_locked(current,capacity=capacity,proof_bytes=previous_size,metadata=0,replay=False):
                            saved_response = previous_response
                        else:
                            code = "repair_service_capacity"
                else:
                    handles = self.db.execute("SELECT count(*) FROM open_repair_bootstrap_handles WHERE resource_id=? AND expires_at>?",(row["resource_id"],now)).fetchone()[0]
                    if handles >= current.limit_policy["max_concurrent_handles"]:
                        code = "repair_service_capacity"
                    else:
                        charge = len(response.raw)*2+ROW_CHARGE*2
                        output = len(response.raw)+len(candidate.handle.raw)+len(candidate.manifest.raw)
                        if self._charge_locked(current,capacity=capacity,proof_bytes=output,metadata=charge):
                            saved_ref = canonical_bytes(dict(handle_ref=candidate.handle.ref.as_dict(),answer_ref=reference.as_dict()))
                            self.db.execute("UPDATE open_repair_bootstrap_challenges SET answer_digest=?,response=?,handle_ref=? WHERE challenge_digest=?",
                                (reference.raw_sha256,response.raw,saved_ref,challenge_ref.raw_sha256))
                            self.db.execute("INSERT INTO open_repair_bootstrap_handles VALUES(?,?,?,?,?,?,?)",(candidate.handle.ref.raw_sha256,row["resource_id"],
                                row["subject"],row["probe_id"],current.generation,response.raw,candidate.handle.payload["expires_at"]))
                        else:
                            code = "repair_service_capacity"
        if code:
            _fail(code)
        if saved_response is not None:
            result = wire.parse_new_wire(saved_response,budget.policy,budget)
        return result

    def _child(self, request_entry, *, budget, capacity):
        parsed, reference, payload = self._preview(request_entry,budget)
        payload = proof._fields(payload,proof.CHILD_FIELDS-{"bootstrap_grant_sha256"})
        handle_ref = probe._ref(payload["handle_ref"])
        handle_row = self.state._one("SELECT * FROM open_repair_bootstrap_handles WHERE digest=?",(handle_ref.raw_sha256,))
        if handle_row is None:
            _fail("repair_service_unavailable")
        row = self.state._one("SELECT * FROM open_repair_bootstrap_challenges WHERE subject=? AND probe_id=?",(handle_row["subject"],handle_row["probe_id"]))
        _,_,expected = self._context(handle_row["resource_id"],budget)
        frozen = self._verify_response(bytes(handle_row["response"]),row,expected,budget)
        if frozen.handle.ref != handle_ref:
            _fail("repair_proof_mismatch")
        request = proof.verify_bootstrap_child_request(dict(raw=parsed.raw,ref=reference.as_dict()),frozen,
            expected_subject=expected["expected_subject"],expected_target=self.state.target,at=self.state._now(),policy=budget.policy,budget=budget)
        prepared = self.access.prepare(handle_row["resource_id"],action="child",expected_generation=handle_row["generation"],
                                       policy=budget.policy,budget=budget)
        # Permission observations commit before fallible output metering or
        # copying. Bytes remain local until the second current-state check and
        # durable request publication both commit.
        with self.state._transaction():
            decision = self.access.check_locked(prepared)
            if decision.allowed:
                decision, children = self.access.proof_inputs(prepared)
        if not decision.allowed:
            _fail(decision.code)
        p = request.payload
        row_child = frozen.manifest.value["children"][p["child_index"]]
        expected_ref = wire.raw_ref(row_child["ref"])
        candidates = [item for item in children if item["role"] == row_child["role"] and item["ref"] == expected_ref]
        if len(candidates) != 1:
            _fail("repair_access_generation")
        selected = candidates[0]["raw"]
        budget._bytes("output_bytes", p["requested_bytes"])
        result = selected[p["offset"]:p["offset"]+p["requested_bytes"]]
        code = None
        with self.state._transaction() as now:
            decision = self.access.check_locked(prepared)
            if decision.allowed:
                decision, current_children = self.access.proof_inputs(prepared)
            if not decision.allowed:
                code = decision.code
            elif now >= handle_row["expires_at"]:
                code = "repair_access_expired"
            elif not any(item["role"] == row_child["role"] and item["ref"] == expected_ref and item["raw"] == selected for item in current_children):
                code = "repair_access_generation"
            else:
                old = self.state._one("SELECT * FROM open_repair_bootstrap_requests WHERE subject=? AND request_id=?",(row["subject"],p["request_id"]))
                if old is not None:
                    code = "repair_child_replay"
                elif self._charge_locked(decision,capacity=capacity,proof_bytes=p["requested_bytes"],metadata=ROW_CHARGE):
                    self.db.execute("INSERT INTO open_repair_bootstrap_requests VALUES(?,?,?,?,?)",(row["subject"],p["request_id"],
                        row["resource_id"],handle_ref.raw_sha256,reference.raw_sha256))
                else:
                    code = "repair_service_capacity"
        if code:
            _fail(code)
        return result
