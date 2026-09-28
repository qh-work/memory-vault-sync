"""Same-resource durable execution journal for an original ACK publication job.

This is a private local storage adapter, never a grant or a network verifier.
The caller supplies a freshly authenticated publication plan and a transaction
guard that preserves current observations before allowing each state change.
Original receipt/head/job records remain immutable. Failed and interrupted
attempts retain their reserved work and transfer charges across restart.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import re
from contextlib import contextmanager

from memory_vault import canonical_bytes
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import ROW_CHARGE

MAX_JOURNAL_BYTES = 2 * 1024 * 1024
MAX_STEPS = 128
STATES = ("prepare", "allocated", "staged", "advertised", "usable")


def _fail(code):
    wire._fail(code)


class AckIndexJournal:
    def __init__(self, state):
        self.state, self.db = state, state.db

    def initialize(self):
        with self.state._transaction():
            # These are the existing shared counters, not a per-campaign meter.
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_bootstrap_usage(
                resource_id TEXT PRIMARY KEY,requests INTEGER NOT NULL,signatures INTEGER NOT NULL,
                proof_bytes INTEGER NOT NULL,replays INTEGER NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_bootstrap_work(
                attempt_id TEXT PRIMARY KEY,resource_id TEXT NOT NULL,request_digest TEXT NOT NULL,
                signature_allowance INTEGER NOT NULL,signature_checks INTEGER,
                created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_index_execution(
                resource_id TEXT PRIMARY KEY,plan_digest TEXT NOT NULL,plan BLOB NOT NULL,
                deadline INTEGER NOT NULL,maximum_bytes INTEGER NOT NULL,used_bytes INTEGER NOT NULL,
                state TEXT NOT NULL,next_due INTEGER NOT NULL,attempts INTEGER NOT NULL,
                last_error TEXT,result BLOB)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_index_steps(
                resource_id TEXT NOT NULL,step INTEGER NOT NULL,request_digest TEXT NOT NULL,
                request BLOB NOT NULL,response BLOB,PRIMARY KEY(resource_id,step))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_index_attempts(
                resource_id TEXT NOT NULL,attempt INTEGER NOT NULL,step INTEGER NOT NULL,
                signature_allowance INTEGER NOT NULL,wire_allowance INTEGER NOT NULL,
                signature_checks INTEGER,wire_bytes INTEGER,
                PRIMARY KEY(resource_id,attempt))""")
            self.db.execute("CREATE INDEX IF NOT EXISTS open_repair_index_due ON open_repair_index_execution(state,next_due)")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_index_artifacts(
                resource_id TEXT NOT NULL,name TEXT NOT NULL,created_at INTEGER NOT NULL,
                status_revision INTEGER,raw BLOB,digest TEXT,PRIMARY KEY(resource_id,name))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_index_issuer_sequence(
                root_digest TEXT NOT NULL,issuer TEXT NOT NULL,revision INTEGER NOT NULL,
                PRIMARY KEY(root_digest,issuer))""")

    def _row(self, resource_id):
        row = self.state._one("SELECT * FROM open_repair_index_execution WHERE resource_id=?", (resource_id,))
        if row is None:
            _fail("repair_index_job_missing")
        return row

    def _bounds(self, resource_id):
        source = self.state._row(resource_id)
        job = self.state._one("SELECT * FROM open_repair_ack_jobs WHERE resource_id=?", (resource_id,))
        committed = self.state._one("SELECT * FROM open_repair_ack_commits WHERE resource_id=?", (resource_id,))
        if (source["status"] != "occupied" or job is None or committed is None
                or job["kind"] != "ack.head.publish" or job["state"] != "pending"):
            _fail("repair_index_source_inactive")
        # The caller's authenticated snapshot guard verifies these exact bytes;
        # this read applies their hard storage ceiling to every local append.
        active = json.loads(bytes(source["active"]))["payload"]["budget"]
        available = min(MAX_JOURNAL_BYTES, active["max_job_bytes"] - committed["job_bytes"])
        if available < ROW_CHARGE or active["max_jobs"] < 1:
            _fail("repair_index_job_capacity")
        return source, active, available

    @staticmethod
    def _guard(guard):
        if not callable(guard):
            _fail("repair_invalid_context")
        code = guard()
        if code is not None and (type(code) is not str or not code.startswith("repair_")):
            _fail("repair_invalid_context")
        return code

    def _checkpoint_guard(self, guard):
        # New authenticated floors must survive a later capacity/conflict error.
        # The actual write transaction repeats the same immutable-source gate.
        with self.state._transaction():
            code = self._guard(guard)
        if code is not None:
            _fail(code)

    def _limits(self, source):
        setup = json.loads(bytes(source["activation_inputs"]))
        granted = json.loads(setup["bootstrap"]["raw"])["payload"]["limits"]
        return {name:min(value,granted[name]) for name,value in self.state.limits.items()}

    @contextmanager
    def preparation_work(self, resource_id, budget):
        """Reserve before local source/consent crypto, even before start().

        A process disappearing in yield leaves its full shared allowance live.
        Ordinary errors settle only the work actually counted by this meter.
        The operation is local operator work, never remote pre-auth admission.
        """
        wire._context(budget.policy,budget)
        before = budget.snapshot()["signature_checks"]
        allowance = min(self.state.policy.max_signature_checks,
                        budget.policy.max_signature_checks-before)
        if allowance <= 0:
            _fail("repair_over_budget")
        attempt = "index_prepare_" + secrets.token_hex(16)
        with self.state._transaction() as now:
            source, capacity, _ = self._bounds(resource_id)
            limits = self._limits(source)
            usage = self.state._one("SELECT * FROM open_repair_bootstrap_usage WHERE resource_id=?",(resource_id,))
            if usage is None and (self.state._one("SELECT 1 FROM open_repair_bootstrap_work WHERE resource_id=?",(resource_id,))
                    or self.state._one("SELECT 1 FROM open_repair_index_attempts WHERE resource_id=?",(resource_id,))):
                _fail("repair_receipt_ledger_missing")
            used = usage or dict(requests=0,signatures=0,proof_bytes=0,replays=0)
            pending = self.db.execute("SELECT coalesce(sum(signature_allowance),0) FROM open_repair_bootstrap_work WHERE resource_id=? AND signature_checks IS NULL",(resource_id,)).fetchone()[0]
            metadata = ROW_CHARGE*(1 if usage else 2)
            if (now >= source["retain_until"]
                    or used["requests"] >= min(limits["max_requests"],capacity["max_requests"])
                    or used["replays"] >= min(limits["max_replay_records"],capacity["max_replay_records"])
                    or used["signatures"]+pending+allowance > limits["max_signature_checks"]
                    or source["metadata_bytes"]+metadata > capacity["max_meta_bytes"]):
                _fail("repair_index_job_capacity")
            self.db.execute("""INSERT INTO open_repair_bootstrap_usage VALUES(?,1,0,0,1)
                ON CONFLICT(resource_id) DO UPDATE SET requests=requests+1,replays=replays+1""",(resource_id,))
            self.db.execute("INSERT INTO open_repair_bootstrap_work VALUES(?,?,?,?,NULL,?,?)",
                (attempt,resource_id,source["request_digest"],allowance,now,source["retain_until"]))
            self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(metadata,resource_id))
        try:
            yield attempt
        finally:
            actual = budget.snapshot()["signature_checks"]-before
            with self.state._transaction():
                row = self.state._one("SELECT * FROM open_repair_bootstrap_work WHERE attempt_id=?",(attempt,))
                if (row is None or row["signature_checks"] is not None
                        or not 0 <= actual <= row["signature_allowance"]):
                    _fail("repair_index_work_corrupt")
                self.db.execute("UPDATE open_repair_bootstrap_work SET signature_checks=? WHERE attempt_id=?",(actual,attempt))
                self.db.execute("UPDATE open_repair_bootstrap_usage SET signatures=signatures+? WHERE resource_id=?",(actual,resource_id))

    @staticmethod
    def _artifact_name(name):
        if type(name) is not str or re.fullmatch(r"[a-z][a-z0-9_.:-]{0,63}",name) is None:
            _fail("repair_invalid_context")

    def saved_artifact(self, resource_id, name):
        self._artifact_name(name)
        with self.state._lock:
            self.state._binding()
            row=self.state._one("SELECT * FROM open_repair_index_artifacts WHERE resource_id=? AND name=?",(resource_id,name))
            if row is not None and ((row["raw"] is None)!=(row["digest"] is None)
                    or row["raw"] is not None and hashlib.sha256(bytes(row["raw"])).hexdigest()!=row["digest"]):
                _fail("repair_storage_corrupt")
            return row

    def reserve_artifact(self, resource_id, name, *, guard, status_revision=False):
        """Reserve stable signing time/optional issuer sequence before signing.

        Signature construction happens outside the writer, then save_artifact
        retains the exact bytes before any send. A restart never reuses a
        reserved revision for another artifact, even when raw is still null.
        """
        self._artifact_name(name)
        if type(status_revision) is not bool:
            _fail("repair_invalid_context")
        self._checkpoint_guard(guard)
        with self.state._transaction() as now:
            code=self._guard(guard)
            if code is None:
                source,_,maximum=self._bounds(resource_id)
                row=self._row(resource_id)
                old=self.state._one("SELECT * FROM open_repair_index_artifacts WHERE resource_id=? AND name=?",(resource_id,name))
                if old is not None:
                    if (old["status_revision"] is not None)!=status_revision:
                        _fail("repair_index_job_conflict")
                else:
                    count=self.db.execute("SELECT count(*) FROM open_repair_index_artifacts WHERE resource_id=?",(resource_id,)).fetchone()[0]
                    if now>=row["deadline"] or count>=16:
                        _fail("repair_index_job_capacity")
                    revision=None
                    extra=ROW_CHARGE
                    if status_revision:
                        setup=json.loads(bytes(source["activation_inputs"]))
                        root=json.loads(setup["root"]["raw"])["payload"]["ack_slot"]["root_key"]
                        root_digest=hashlib.sha256(canonical_bytes(root)).hexdigest()
                        issuer=self.state.identity.key_id
                        sequence=self.state._one("SELECT revision FROM open_repair_index_issuer_sequence WHERE root_digest=? AND issuer=?",(root_digest,issuer))
                        floor=self.db.execute("SELECT coalesce(max(revision),0) FROM open_repair_access_documents WHERE root_digest=? AND issuer=?",(root_digest,issuer)).fetchone()[0]
                        source_status=json.loads(bytes(source["source_status"]))["payload"]["revision"]
                        revision=max(floor,source_status,sequence["revision"] if sequence else 0)
                        legacy=[]
                        # These existing same-DB counters also issue this node's
                        # authority.status. Reserve across them, never restart at 1.
                        for table,prefix in (("open_provider_state","status_revision:"),("open_provider_client_meta","status:")):
                            if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
                                name_key=prefix+root_digest
                                value=self.db.execute("SELECT value FROM "+table+" WHERE name=?",(name_key,)).fetchone()
                                if value is not None:
                                    revision=max(revision,wire.u53(int(value[0])))
                                    legacy.append((table,name_key))
                        revision=wire.u53(revision+1,1)
                        extra+=0 if sequence else ROW_CHARGE
                    if row["used_bytes"]+extra>min(row["maximum_bytes"],maximum):
                        _fail("repair_index_job_capacity")
                    if status_revision:
                        self.db.execute("INSERT INTO open_repair_index_issuer_sequence VALUES(?,?,?) ON CONFLICT(root_digest,issuer) DO UPDATE SET revision=excluded.revision",(root_digest,issuer,revision))
                        for table,name_key in legacy:
                            self.db.execute("UPDATE "+table+" SET value=? WHERE name=?",(str(revision),name_key))
                    self.db.execute("INSERT INTO open_repair_index_artifacts VALUES(?,?,?,?,NULL,NULL)",(resource_id,name,now,revision))
                    self.db.execute("UPDATE open_repair_index_execution SET used_bytes=used_bytes+? WHERE resource_id=?",(extra,resource_id))
        if code is not None:
            _fail(code)
        return self.saved_artifact(resource_id,name)

    def save_artifact(self, resource_id, name, raw, *, guard):
        self._artifact_name(name)
        if type(raw) is not bytes or not 0<len(raw)<=270350:
            _fail("repair_index_job_capacity")
        digest=hashlib.sha256(raw).hexdigest()
        self._checkpoint_guard(guard)
        with self.state._transaction():
            code=self._guard(guard)
            if code is None:
                _,_,maximum=self._bounds(resource_id)
                row=self._row(resource_id)
                old=self.state._one("SELECT * FROM open_repair_index_artifacts WHERE resource_id=? AND name=?",(resource_id,name))
                if old is None:
                    _fail("repair_index_job_missing")
                if old["raw"] is not None:
                    if bytes(old["raw"])!=raw or old["digest"]!=digest:
                        _fail("repair_index_job_conflict")
                else:
                    if row["used_bytes"]+len(raw)>min(row["maximum_bytes"],maximum):
                        _fail("repair_index_job_capacity")
                    self.db.execute("UPDATE open_repair_index_artifacts SET raw=?,digest=? WHERE resource_id=? AND name=?",(raw,digest,resource_id,name))
                    self.db.execute("UPDATE open_repair_index_execution SET used_bytes=used_bytes+? WHERE resource_id=?",(len(raw),resource_id))
        if code is not None:
            _fail(code)
        return self.saved_artifact(resource_id,name)

    def start(self, resource_id, plan_raw, *, deadline, guard):
        if type(plan_raw) is not bytes or not 0 < len(plan_raw) <= MAX_JOURNAL_BYTES:
            _fail("repair_index_job_capacity")
        digest = hashlib.sha256(plan_raw).hexdigest()
        wire.u53(deadline, 1)
        self._checkpoint_guard(guard)
        with self.state._transaction() as now:
            code = self._guard(guard)
            if code is None:
                source, _, maximum = self._bounds(resource_id)
                if not now < deadline <= source["retain_until"]:
                    _fail("repair_access_expired")
                old = self.state._one("SELECT * FROM open_repair_index_execution WHERE resource_id=?", (resource_id,))
                if old is not None:
                    if old["plan_digest"] != digest or bytes(old["plan"]) != plan_raw or old["deadline"] != deadline:
                        _fail("repair_index_job_conflict")
                else:
                    used = len(plan_raw) + ROW_CHARGE
                    if used > maximum:
                        _fail("repair_index_job_capacity")
                    self.db.execute("INSERT INTO open_repair_index_execution VALUES(?,?,?,?,?,?,'prepare',?,0,NULL,NULL)",
                        (resource_id,digest,plan_raw,deadline,maximum,used,now))
        if code is not None:
            _fail(code)
        return self.snapshot(resource_id)

    def snapshot(self, resource_id):
        with self.state._lock:
            self.state._binding()
            row = self._row(resource_id)
            if hashlib.sha256(bytes(row["plan"])).hexdigest() != row["plan_digest"]:
                _fail("repair_storage_corrupt")
            return dict(row)

    def saved_step(self, resource_id, step):
        wire.u53(step)
        if step >= MAX_STEPS:
            _fail("repair_index_job_capacity")
        with self.state._lock:
            self.state._binding()
            row = self.state._one("SELECT * FROM open_repair_index_steps WHERE resource_id=? AND step=?",(resource_id,step))
            if row is not None and hashlib.sha256(bytes(row["request"])).hexdigest() != row["request_digest"]:
                _fail("repair_storage_corrupt")
            return row

    def begin(self, resource_id, step, request, *, signature_allowance, response_allowance, guard):
        """Persist the exact request and charge an attempt before any send/work."""
        wire.u53(step); wire.u53(signature_allowance); wire.u53(response_allowance)
        if (step >= MAX_STEPS or type(request) is not bytes or not 0 < len(request) <= 270350
                or response_allowance > 270350):
            _fail("repair_index_job_capacity")
        digest = hashlib.sha256(request).hexdigest()
        transfer = len(request) + response_allowance
        attempt = None
        self._checkpoint_guard(guard)
        with self.state._transaction() as now:
            code = self._guard(guard)
            if code is None:
                source, capacity, maximum = self._bounds(resource_id)
                row = self._row(resource_id)
                if now >= row["deadline"] or row["state"] == "usable":
                    _fail("repair_access_expired")
                previous = self.state._one("SELECT * FROM open_repair_index_steps WHERE resource_id=? AND step=?",(resource_id,step))
                if previous is not None and (previous["request_digest"] != digest or bytes(previous["request"]) != request):
                    _fail("repair_index_job_conflict")
                usage = self.state._one("SELECT * FROM open_repair_bootstrap_usage WHERE resource_id=?",(resource_id,))
                if usage is None:
                    _fail("repair_receipt_ledger_missing")
                pending = self.db.execute("SELECT coalesce(sum(signature_allowance),0) FROM open_repair_bootstrap_work WHERE resource_id=? AND signature_checks IS NULL",(resource_id,)).fetchone()[0]
                limits = self._limits(source)
                extra = ROW_CHARGE + (len(request)+ROW_CHARGE if previous is None else 0)
                if (row["used_bytes"]+extra > min(row["maximum_bytes"],maximum)
                        or usage["requests"] >= min(limits["max_requests"],capacity["max_requests"])
                        or usage["signatures"]+pending+signature_allowance > limits["max_signature_checks"]
                        or usage["proof_bytes"]+transfer > limits["max_proof_bytes"]
                        or usage["replays"] >= min(limits["max_replay_records"],capacity["max_replay_records"])):
                    _fail("repair_index_job_capacity")
                attempt = row["attempts"]+1
                if previous is None:
                    self.db.execute("INSERT INTO open_repair_index_steps VALUES(?,?,?,?,NULL)",(resource_id,step,digest,request))
                self.db.execute("INSERT INTO open_repair_index_attempts VALUES(?,?,?,?,?,NULL,NULL)",
                    (resource_id,attempt,step,signature_allowance,transfer))
                self.db.execute("UPDATE open_repair_bootstrap_usage SET requests=requests+1,signatures=signatures+?,proof_bytes=proof_bytes+?,replays=replays+1 WHERE resource_id=?",
                    (signature_allowance,transfer,resource_id))
                self.db.execute("UPDATE open_repair_index_execution SET used_bytes=used_bytes+?,attempts=?,last_error=NULL WHERE resource_id=?",(extra,attempt,resource_id))
        if code is not None:
            _fail(code)
        return attempt

    def finish(self, resource_id, attempt, response, *, signature_checks, guard):
        """Publish only an independently verified response; interrupted work stays charged."""
        wire.u53(attempt,1); wire.u53(signature_checks)
        if type(response) is not bytes or not 0 < len(response) <= 270350:
            _fail("repair_index_job_capacity")
        self._checkpoint_guard(guard)
        with self.state._transaction():
            code = self._guard(guard)
            if code is None:
                _, _, maximum = self._bounds(resource_id)
                row = self._row(resource_id)
                work = self.state._one("SELECT * FROM open_repair_index_attempts WHERE resource_id=? AND attempt=?",(resource_id,attempt))
                if work is None:
                    _fail("repair_index_job_missing")
                step = self.state._one("SELECT * FROM open_repair_index_steps WHERE resource_id=? AND step=?",(resource_id,work["step"]))
                actual = len(bytes(step["request"])) + len(response)
                if signature_checks > work["signature_allowance"] or actual > work["wire_allowance"]:
                    _fail("repair_over_budget")
                if step["response"] is not None and bytes(step["response"]) != response:
                    _fail("repair_index_job_conflict")
                if work["signature_checks"] is not None:
                    if work["signature_checks"] != signature_checks or work["wire_bytes"] != actual:
                        _fail("repair_index_job_conflict")
                else:
                    extra = len(response) if step["response"] is None else 0
                    if row["used_bytes"]+extra > min(row["maximum_bytes"],maximum):
                        _fail("repair_index_job_capacity")
                    self.db.execute("UPDATE open_repair_index_steps SET response=? WHERE resource_id=? AND step=?",(response,resource_id,work["step"]))
                    self.db.execute("UPDATE open_repair_index_attempts SET signature_checks=?,wire_bytes=? WHERE resource_id=? AND attempt=?",(signature_checks,actual,resource_id,attempt))
                    self.db.execute("UPDATE open_repair_bootstrap_usage SET signatures=signatures-?,proof_bytes=proof_bytes-? WHERE resource_id=?",
                        (work["signature_allowance"]-signature_checks,work["wire_allowance"]-actual,resource_id))
                    self.db.execute("UPDATE open_repair_index_execution SET used_bytes=used_bytes+? WHERE resource_id=?",(extra,resource_id))
        if code is not None:
            _fail(code)

    def transition(self, resource_id, state, *, evidence, next_due, guard):
        """The caller verifies the actual lease/readback before advancing a predicate."""
        if state not in STATES or type(evidence) is not bytes or len(evidence)>65536:
            _fail("repair_invalid_context")
        wire.u53(next_due)
        self._checkpoint_guard(guard)
        with self.state._transaction():
            code = self._guard(guard)
            if code is None:
                _, _, maximum = self._bounds(resource_id)
                row = self._row(resource_id)
                if STATES.index(state) not in (STATES.index(row["state"]),STATES.index(row["state"])+1):
                    _fail("repair_index_job_conflict")
                previous = bytes(row["result"]) if row["result"] is not None else b""
                if row["state"] == state and previous != evidence:
                    _fail("repair_index_job_conflict")
                used = row["used_bytes"]-len(previous)+len(evidence)
                if used > min(row["maximum_bytes"],maximum) or next_due > row["deadline"]:
                    _fail("repair_index_job_capacity")
                self.db.execute("UPDATE open_repair_index_execution SET state=?,result=?,used_bytes=?,next_due=?,last_error=NULL WHERE resource_id=?",
                    (state,evidence,used,next_due,resource_id))
        if code is not None:
            _fail(code)

    def defer(self, resource_id, code, *, next_due):
        if type(code) is not str or not code.startswith("repair_") or len(code)>96:
            _fail("repair_invalid_context")
        wire.u53(next_due)
        with self.state._transaction():
            row = self._row(resource_id)
            self.db.execute("UPDATE open_repair_index_execution SET last_error=?,next_due=? WHERE resource_id=?",
                (code,min(next_due,row["deadline"]),resource_id))
