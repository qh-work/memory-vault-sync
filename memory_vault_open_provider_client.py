"""Routed provider discovery and owner-authorized directory publication.

Only existing participant routing, transport, keys and protected network state
are used. Directory observations never confer object-read or Vault authority.
"""
from __future__ import annotations

import asyncio
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, document_sha256, integer, opaque
from memory_vault_open_control import coordinate, verify_node
from memory_vault_open_provider import (
    MAX_CONTROL_BYTES, PUBLISH, ProviderError, as_dual, authority_scope, bounded,
    dual_id, fields, issue_status, make_target_challenge, opaque_ref, root_key as check_root,
    route_target, sign_document, sign_rpc, verify_document, verify_index_lease,
    verify_resource_lease, verify_response, verify_rpc, verify_status, verify_target_answer,
)
from memory_vault_open_routing import LookupBudget

LOCAL_MAX_RECORDS = 128
LOCAL_MAX_BYTES = 131072
DEFAULT_RESOURCE_BUDGET = {
    "max_live_bytes": 0, "max_meta_bytes": 98304, "max_items": 1,
    "max_requests": 8, "max_pending": 1, "max_replay_records": 8,
    "max_jobs": 0, "max_job_bytes": 0,
}


class OpenProviderClient:
    """A running participant's provider API; constructing it performs no IO on the network.

    B uses authorize_publication when B and P are different principals. P then
    publishes the exact authorization with its own identity. No method can sign
    for an absent owner, replace a lease, or claim that advertised bytes exist.
    """

    def __init__(self, participant, encryption):
        self.participant, self.encryption = participant, encryption
        self.identity = participant.identity
        self._proven_targets = {}
        self.subject = {"signing_key": self.identity.public_descriptor(), "encryption_key": encryption.public_descriptor()}
        as_dual(self.subject)
        with participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("CREATE TABLE IF NOT EXISTS open_provider_client_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL)")
                db.execute("""CREATE TABLE IF NOT EXISTS open_provider_local(
                    category TEXT NOT NULL,reference TEXT NOT NULL,body BLOB NOT NULL,retain_until INTEGER NOT NULL,
                    PRIMARY KEY(category,reference))""")
                db.execute("CREATE INDEX IF NOT EXISTS open_provider_local_expiry ON open_provider_local(retain_until)")
                db.execute("""CREATE TABLE IF NOT EXISTS open_provider_local_floors(
                    fact_key TEXT PRIMARY KEY,revision INTEGER NOT NULL,digest TEXT NOT NULL,
                    record BLOB NOT NULL,second_record BLOB,status TEXT NOT NULL,retain_until INTEGER NOT NULL)""")
                db.execute("CREATE INDEX IF NOT EXISTS open_provider_local_floor_expiry ON open_provider_local_floors(retain_until)")
                binding = self.identity.key_id + ":" + encryption.key_id
                old = db.execute("SELECT value FROM open_provider_client_meta WHERE name='binding'").fetchone()
                if old is not None and old[0] != binding:
                    raise ProviderError("provider_client_identity_mismatch")
                if old is None:
                    if db.execute("SELECT 1 FROM open_provider_local LIMIT 1").fetchone() or db.execute("SELECT 1 FROM open_provider_local_floors LIMIT 1").fetchone():
                        raise ProviderError("provider_client_binding_missing")
                    db.execute("INSERT INTO open_provider_client_meta VALUES('binding',?)", (binding,))
                db.commit()
            except BaseException:
                db.rollback(); raise

    @staticmethod
    def _budget(budget):
        result = budget if budget is not None else LookupBudget()
        if not isinstance(result, LookupBudget):
            raise ProviderError("provider_invalid_budget")
        result.check()
        return result

    @staticmethod
    def _metrics(budget):
        return {"requests": budget.requests, "request_bytes": budget.request_bytes,
                "response_bytes": budget.response_bytes,
                "response_bytes_are_upper_bound": bool(getattr(budget, "provider_unmeasured_failures", 0))}

    @staticmethod
    def _error(node, error):
        return {"node_key_id": node["payload"]["signing_key"]["key_id"], "code": getattr(error, "code", "provider_unreachable")}

    @staticmethod
    def _fact_key(raw):
        return document_sha256({"ref": raw["ref"], "provider_key_id": raw["signing_key"]["key_id"],
                                "storage_epoch": raw["storage_epoch"], "custody_id": raw["custody_id"]})

    def _session(self, category, reference, semantic, initial=None, retain_until=None):
        """Reserve the bounded local phase before acquiring a remote obligation."""
        now = int(time.time())
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM open_provider_local WHERE rowid IN (SELECT rowid FROM open_provider_local WHERE retain_until<=? ORDER BY retain_until LIMIT 32)", (now,))
                old = db.execute("SELECT body FROM open_provider_local WHERE category=? AND reference=?", (category, reference)).fetchone()
                if old is not None:
                    result = document(bytes(old[0]), maximum=LOCAL_MAX_BYTES)
                    if result["semantic"] != semantic:
                        raise ProviderError("provider_local_conflict")
                else:
                    if initial is None or retain_until is None:
                        raise ProviderError("provider_local_missing")
                    if db.execute("SELECT count(*) FROM open_provider_local").fetchone()[0] >= LOCAL_MAX_RECORDS:
                        raise ProviderError("provider_local_capacity", retryable=True)
                    result = document({"semantic": semantic, **initial}, maximum=LOCAL_MAX_BYTES)
                    db.execute("INSERT INTO open_provider_local VALUES(?,?,?,?)", (category, reference, canonical_bytes(result), integer(retain_until)))
                db.commit()
                return result
            except BaseException:
                db.rollback(); raise

    def _append(self, category, reference, additions):
        # Each stored field is immutable. Concurrent identical retries converge;
        # differing remote outcomes are retained as an explicit refusal.
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT body FROM open_provider_local WHERE category=? AND reference=?", (category, reference)).fetchone()
                if row is None:
                    raise ProviderError("provider_local_missing")
                result = document(bytes(row[0]), maximum=LOCAL_MAX_BYTES)
                for key, value in additions.items():
                    if key in result and result[key] != value:
                        raise ProviderError("provider_local_conflict")
                    result[key] = value
                result = document(result, maximum=LOCAL_MAX_BYTES)
                db.execute("UPDATE open_provider_local SET body=? WHERE category=? AND reference=?", (canonical_bytes(result), category, reference))
                db.commit()
                return result
            except BaseException:
                db.rollback(); raise

    def _observe_fact(self, fact):
        raw = verify_document(fact, "provider.fact"); key = self._fact_key(raw)
        digest = document_sha256(fact); refusal = None
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM open_provider_local_floors WHERE rowid IN (SELECT rowid FROM open_provider_local_floors WHERE retain_until<=? ORDER BY retain_until LIMIT 32)", (int(time.time()),))
                old = db.execute("SELECT revision,digest,status,retain_until FROM open_provider_local_floors WHERE fact_key=?", (key,)).fetchone()
                if old and old[2] in {"conflict", "withdrawn"}:
                    raise ProviderError("provider_fact_inactive")
                if old and raw["revision"] < old[0]:
                    raise ProviderError("provider_fact_rollback")
                if old and raw["revision"] == old[0] and digest != old[1]:
                    db.execute("UPDATE open_provider_local_floors SET second_record=?,status='conflict',retain_until=max(retain_until,?) WHERE fact_key=?",
                               (canonical_bytes(fact), raw["expires_at"] + 60, key))
                    refusal = ProviderError("provider_fact_conflict")
                else:
                    if old is None and db.execute("SELECT count(*) FROM open_provider_local_floors").fetchone()[0] >= LOCAL_MAX_RECORDS:
                        raise ProviderError("provider_local_capacity", retryable=True)
                    db.execute("""INSERT INTO open_provider_local_floors VALUES(?,?,?,?,NULL,?,?)
                        ON CONFLICT(fact_key) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,
                        record=excluded.record,status=excluded.status,retain_until=max(retain_until,excluded.retain_until)""",
                        (key, raw["revision"], digest, canonical_bytes(fact), raw["status"], raw["expires_at"] + 60))
                db.commit()
            except BaseException:
                db.rollback(); raise
        if refusal is not None:
            raise refusal
        return key

    def _fact_current(self, fact):
        raw = verify_document(fact, "provider.fact")
        with self.participant.state.db() as db:
            row = db.execute("SELECT digest,status FROM open_provider_local_floors WHERE fact_key=?", (self._fact_key(raw),)).fetchone()
        return bool(row and row[0] == document_sha256(fact) and row[1] == "active")

    async def call(self, node, action, body, budget=None):
        """One signed RPC; the caller must prove_target before private actions."""
        budget = self._budget(budget)
        self.participant._accept(node)
        if action in {"resource.allocate", "resource.revoke", "provider.put", "provider.status", "provider.result"}:
            binding = (node["payload"]["signing_key"]["key_id"], node["payload"]["storage_epoch"])
            proof = self._proven_targets.get(binding)
            if proof is None or proof["expires_at"] <= int(time.time()):
                raise ProviderError("provider_target_proof_required")
            verify_document(proof["target"], "provider.target")
            if action == "provider.put":
                verify_resource_lease(body["resource_lease"], node=node, target=proof["target"])
        request = sign_rpc(self.identity, node=node, action=action, body=body)
        verify_rpc(request, node=node)
        # A failed transport does not expose its partial-read byte count. Keep
        # the entire reserved bound charged in that case, and label the metric.
        if budget.remaining_bytes < MAX_CONTROL_BYTES:
            raise ProviderError("provider_budget_exhausted", retryable=True)
        budget.charge_request(); budget.charge_request_bytes(len(canonical_bytes(request)))
        budget.charge_bytes(MAX_CONTROL_BYTES)
        try:
            reply = await asyncio.to_thread(self.participant.transport.request, node["payload"]["base_url"], request, deadline=budget.deadline)
        except BaseException:
            budget.provider_unmeasured_failures = getattr(budget, "provider_unmeasured_failures", 0) + 1
            raise
        budget.bytes -= MAX_CONTROL_BYTES
        budget.charge_bytes(reply.wire_bytes)
        if reply.wire_bytes > MAX_CONTROL_BYTES or reply.wire_bytes < len(canonical_bytes(reply.response)):
            raise ProviderError("provider_response_size")
        checked = verify_response(reply.response, request=request, node=node)
        self.participant._accept(node)
        self.participant.table.learn_verified(node, reply.observed_address)
        self.participant._cache(node)
        if "error" in checked["body"]:
            error = checked["body"]["error"]
            raise ProviderError(error["code"], retryable=error["retryable"])
        return checked["body"]

    async def prove_target(self, node, budget=None):
        """Prove both current target keys before sending RootKey or authority."""
        budget = self._budget(budget)
        target = (await self.call(node, "target.get", {}, budget))["target"]
        challenge, nonce = make_target_challenge(self.identity, target=target, node=node)
        answer = (await self.call(node, "target.answer", {"target": target, "challenge": challenge}, budget))["answer"]
        verify_target_answer(answer, target=target, challenge=challenge, nonce=nonce, node=node)
        budget.check(); self.participant._accept(node)
        current = int(time.time())
        self._proven_targets = {k: v for k, v in self._proven_targets.items() if v["expires_at"] > current}
        if len(self._proven_targets) >= 32:
            self._proven_targets.pop(next(iter(self._proven_targets)))
        binding = (node["payload"]["signing_key"]["key_id"], node["payload"]["storage_epoch"])
        self._proven_targets[binding] = {"target": target, "expires_at": min(answer["payload"]["expires_at"], target["payload"]["expires_at"])}
        return target

    async def _directories(self, ref, budget, maximum):
        route = await self.participant._lookup(route_target(ref), "directory", budget)
        nodes = list(route["candidates"])
        if self.participant.descriptor is not None:
            own = verify_node(self.participant.descriptor)
            if "directory" in own["roles"]:
                nodes.append(self.participant.descriptor)
        unique = {}
        for node in nodes:
            try:
                raw = verify_node(node); self.participant._accept(node)
                if raw["status"] == "active" and "directory" in raw["roles"]:
                    unique[(raw["signing_key"]["key_id"], raw["storage_epoch"])] = node
            except MemoryError:
                continue
        ordered = sorted(unique.values(), key=lambda n: (int(n["payload"]["coordinate"], 16) ^ int(route_target(ref), 16), n["payload"]["signing_key"]["key_id"]))
        return ordered[:maximum], bool(route.get("partial", False) or route.get("exhausted", False))

    async def _resolve_directory(self, old, budget):
        # This is an original signed routing introduction retained in a local
        # plan or in B's returned authorization. Fresh possession is still
        # required before any private RPC. Refresh expired addresses via routing.
        try:
            current = verify_node(old)
            self.participant._accept(old)
            if current["status"] == "active" and "directory" in current["roles"]:
                return old
        except MemoryError:
            pass
        wanted = verify_node(old, now=old["payload"]["issued_at"], allow_expired=True)
        route = await self.participant._lookup(coordinate(wanted["signing_key"]["key_id"]), "directory", budget)
        nodes = list(route["candidates"])
        if self.participant.descriptor is not None:
            nodes.append(self.participant.descriptor)
        for node in nodes:
            raw = verify_node(node)
            if raw["signing_key"] == wanted["signing_key"] and raw["storage_epoch"] == wanted["storage_epoch"] and "directory" in raw["roles"] and raw["status"] == "active":
                self.participant._accept(node)
                return node
        raise ProviderError("provider_directory_unresolved", retryable=True)

    async def find(self, ref, budget=None, *, maximum_candidates=8, maximum_directories=3):
        """Return actual dual-key-responsive candidates and their raw observations."""
        ref = opaque_ref(ref); budget = self._budget(budget)
        bounded(maximum_candidates, 16); bounded(maximum_directories, 3)
        candidates, errors, partial = {}, [], False
        try:
            directories, partial = await self._directories(ref, budget, maximum_directories)
        except (MemoryError, OSError, TimeoutError) as error:
            return {"state": "not_observed", "candidates": [], "errors": [{"code": getattr(error, "code", "provider_unreachable")}], "partial": True, **self._metrics(budget)}
        for directory in directories:
            cursor = None
            for _ in range(8):
                try:
                    page = await self.call(directory, "provider.get", {"ref": ref, "after": cursor, "limit": 4, "maximum_bytes": 49152}, budget)
                    nodes = {(n["payload"]["signing_key"]["key_id"], n["payload"]["storage_epoch"]): n for n in page["nodes"]}
                    for entry in page["entries"]:
                        fact = entry["fact"]; raw = verify_document(fact, "provider.fact")
                        try:
                            self._observe_fact(fact)
                            key = (raw["signing_key"]["key_id"], raw["storage_epoch"])
                            node = nodes[key]
                            if key not in candidates:
                                if len(candidates) >= maximum_candidates:
                                    partial = True; break
                                target = await self.prove_target(node, budget)
                                candidates[key] = {"node": node, "target": target, "facts": []}
                            observation = {"fact": fact, "index_lease": entry["index_lease"], "directory": directory}
                            records = candidates[key]["facts"]
                            if observation not in records and len(records) < 6:
                                records.append(observation)
                        except (MemoryError, OSError, TimeoutError) as error:
                            errors.append(self._error(nodes.get((raw["signing_key"]["key_id"], raw["storage_epoch"]), directory), error)); partial = True
                    next_cursor = page["next_cursor"]
                    if next_cursor is None:
                        break
                    if cursor is not None and next_cursor <= cursor:
                        raise ProviderError("provider_invalid_cursor")
                    cursor = next_cursor
                    if len(candidates) >= maximum_candidates:
                        partial = True; break
                except (MemoryError, OSError, TimeoutError) as error:
                    errors.append(self._error(directory, error)); partial = True; break
            else:
                partial = True
            if len(candidates) >= maximum_candidates:
                break
        result = []
        for candidate in candidates.values():
            try:
                self.participant._accept(candidate["node"])
                verify_document(candidate["target"], "provider.target")
                current = []
                for observation in candidate["facts"]:
                    if self._fact_current(observation["fact"]):
                        verify_index_lease(observation["index_lease"], fact=observation["fact"], node=observation["directory"])
                        current.append(observation)
                if current:
                    candidate["facts"] = current; result.append(candidate)
            except MemoryError as error:
                errors.append(self._error(candidate["node"], error)); partial = True
        return {"state": "observed" if result else "not_observed", "candidates": result,
                "errors": errors[:64], "partial": partial, **self._metrics(budget)}

    async def _authorize_one(self, ref, root, publisher, allocation_id, node, resource_seconds, lease_seconds, budget):
        target = await self.prove_target(node, budget)
        raw_node = verify_node(node)
        semantic = {"ref": ref, "root_key": root, "publisher": publisher, "allocation_id": allocation_id,
                    "node_key_id": raw_node["signing_key"]["key_id"], "storage_epoch": raw_node["storage_epoch"],
                    "resource_seconds": resource_seconds, "lease_seconds": lease_seconds}
        reference = document_sha256({"allocation_id": allocation_id, "node_key_id": semantic["node_key_id"], "storage_epoch": semantic["storage_epoch"]})
        now = int(time.time()); until = now + resource_seconds
        intent = sign_document(self.identity, "root.resource.intent", issued_at=now, expires_at=until,
            allocation_id="resource_" + reference, root_key=root, subject=self.subject,
            node_key_id=semantic["node_key_id"], storage_epoch=semantic["storage_epoch"], purpose="provider_index",
            budget=dict(DEFAULT_RESOURCE_BUDGET), windows={key: until for key in ("admit_until", "read_until", "copy_until", "publish_until", "retain_until")})
        session = self._session("authorize", reference, semantic, {"node": node, "intent": intent}, until + 60)
        intent = session["intent"]
        verify_document(intent, "root.resource.intent")
        if "lease" not in session:
            response = await self.call(node, "resource.allocate", {"intent": intent}, budget)
            if response["current_state"] != "active":
                raise ProviderError("provider_resource_inactive")
            verify_resource_lease(response["lease"], intent=intent, node=node, target=target)
            session = self._append("authorize", reference, {"lease": response["lease"], "resource_status": response["status"]})
        lease = verify_resource_lease(session["lease"], intent=intent, node=node, target=target)
        if "grant" not in session:
            now = int(time.time())
            grant = sign_document(self.identity, "provider.publication.grant", issued_at=now, expires_at=lease["windows"]["publish_until"],
                root_key=root, resource=lease["resource"], resource_lease_sha256=document_sha256(session["lease"]), publisher=publisher,
                ref=ref, grant_id="grant_" + reference, revision=1, operation_mask=PUBLISH, maximum_fact_seconds=lease_seconds)
            # Different directory grants have different scopes. Reserve one
            # monotonically increasing owner revision for this RootKey locally.
            with self.participant.state.db() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    name = "status:" + document_sha256(root)
                    row = db.execute("SELECT value FROM open_provider_client_meta WHERE name=?", (name,)).fetchone()
                    revision = integer(int(row[0]) + 1 if row else 1)
                    db.execute("INSERT INTO open_provider_client_meta VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, str(revision)))
                    db.commit()
                except BaseException:
                    db.rollback(); raise
            status = issue_status(self.identity, root=root, revision=revision, issued_at=now, valid_until=grant["payload"]["expires_at"],
                entries=[{"scope_kind": "authority", "scope_id": authority_scope(root, "provider.publication.grant", document_sha256(grant)),
                          "minimum_document_revision": 1, "status": "active", "operation_mask": PUBLISH}])
            session = self._append("authorize", reference, {"grant": grant, "owner_status": status})
        return {"node": node, "intent": session["intent"], "resource_lease": session["lease"],
                "resource_status": session["resource_status"], "publication_grant": session["grant"], "owner_status": session["owner_status"]}

    async def authorize_publication(self, ref, root_key, publisher, allocation_id, *, budget=None,
                                    lease_seconds=180, resource_seconds=600, directory_count=3):
        """Owner B allocates at real D nodes and signs exact P/ref grants."""
        ref = opaque_ref(ref); root = check_root(root_key); publisher = dual_id(publisher); opaque(allocation_id)
        if root["owner"] != as_dual(self.subject):
            raise ProviderError("provider_wrong_owner")
        bounded(lease_seconds, 600); bounded(resource_seconds, 604800); bounded(directory_count, 3)
        if resource_seconds < lease_seconds:
            raise ProviderError("provider_invalid_window")
        budget = self._budget(budget)
        # Reserve the durable issuer sequence before any remote allocation.
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                name = "status:" + document_sha256(root)
                if db.execute("SELECT 1 FROM open_provider_client_meta WHERE name=?", (name,)).fetchone() is None:
                    if db.execute("SELECT count(*) FROM open_provider_client_meta WHERE name LIKE 'status:%'").fetchone()[0] >= LOCAL_MAX_RECORDS:
                        raise ProviderError("provider_local_capacity", retryable=True)
                    db.execute("INSERT INTO open_provider_client_meta VALUES(?, '0')", (name,))
                db.commit()
            except BaseException:
                db.rollback(); raise
        semantic = {"ref": ref, "root_key": root, "publisher": publisher, "allocation_id": allocation_id,
                    "lease_seconds": lease_seconds, "resource_seconds": resource_seconds, "directory_count": directory_count}
        reference = document_sha256({"allocation_id": allocation_id, "owner": self.identity.key_id})
        try:
            plan = self._session("authorize_plan", reference, semantic)
        except ProviderError as error:
            if error.code != "provider_local_missing":
                raise
            nodes, partial = await self._directories(ref, budget, directory_count)
            if not nodes:
                return {"state": "not_observed", "authorizations": [], "errors": [], "partial": True, **self._metrics(budget)}
            plan = self._session("authorize_plan", reference, semantic, {"nodes": nodes}, int(time.time()) + resource_seconds + 60)
        results, errors = [], []
        for old in plan["nodes"]:
            try:
                node = await self._resolve_directory(old, budget)
                results.append(await self._authorize_one(ref, root, publisher, allocation_id, node, resource_seconds, lease_seconds, budget))
            except (MemoryError, OSError, TimeoutError) as error:
                errors.append(self._error(old, error))
        return {"state": "authorized" if results else "pending", "authorizations": results, "errors": errors,
                "partial": len(results) < directory_count, **self._metrics(budget)}

    async def publish(self, ref, root_key, provider_fact, allocation_id, *, budget=None, lease_seconds=180,
                      resource_seconds=600, directory_count=3, authorizations=None):
        """P publishes its own fact using B's independently signed exact grants.

        With no authorizations this identity must also be the root owner; the
        client first obtains its own finite D resources. B != P requires the
        bundles returned by B's authorize_publication, never an owner-key guess.
        """
        ref = opaque_ref(ref); root = check_root(root_key); opaque(allocation_id)
        fact = verify_document(provider_fact, "provider.fact")
        if fact["signing_key"] != self.identity.public_descriptor() or fact["ref"] != ref or fact["status"] != "active":
            raise ProviderError("provider_wrong_publisher")
        if self.participant.descriptor is None:
            raise ProviderError("provider_node_required")
        node_raw = verify_node(self.participant.descriptor)
        if node_raw["signing_key"] != fact["signing_key"] or node_raw["storage_epoch"] != fact["storage_epoch"]:
            raise ProviderError("provider_wrong_publisher")
        bounded(lease_seconds, 600); bounded(directory_count, 3)
        budget = self._budget(budget); errors = []
        if authorizations is None:
            prepared = await self.authorize_publication(ref, root, as_dual(self.subject), allocation_id,
                budget=budget, lease_seconds=lease_seconds, resource_seconds=resource_seconds, directory_count=directory_count)
            authorizations = prepared["authorizations"]; errors.extend(prepared["errors"])
        if not isinstance(authorizations, list) or len(authorizations) > 3:
            raise ProviderError("provider_invalid_authorizations")
        results, seen = [], set()
        for value in authorizations:
            authorization = fields(value, {"node", "intent", "resource_lease", "resource_status", "publication_grant", "owner_status"})
            old = authorization["node"]
            try:
                node = await self._resolve_directory(old, budget)
                node_raw = verify_node(node); binding = (node_raw["signing_key"]["key_id"], node_raw["storage_epoch"])
                if binding in seen:
                    raise ProviderError("provider_duplicate_directory")
                seen.add(binding)
                # No owner root/grant is transmitted until the real target has
                # answered the challenge for this exact current dual identity.
                target = await self.prove_target(node, budget)
                lease = verify_resource_lease(authorization["resource_lease"], intent=authorization["intent"], node=node, target=target)
                grant = verify_document(authorization["publication_grant"], "provider.publication.grant")
                status = verify_status(authorization["owner_status"])
                expected_scope = authority_scope(root, "provider.publication.grant", document_sha256(authorization["publication_grant"]))
                if (lease["root_key"] != root or lease["purpose"] != "provider_index" or grant["root_key"] != root or grant["ref"] != ref
                        or grant["publisher"] != as_dual(self.subject) or grant["resource"] != lease["resource"]
                        or grant["resource_lease_sha256"] != document_sha256(authorization["resource_lease"])
                        or status["scope_key"] != {"root_key": root, "issuer_key_id": root["owner"]["signing_key_id"]}
                        or not any(e["scope_kind"] == "authority" and e["scope_id"] == expected_scope and e["status"] == "active"
                                   and e["minimum_document_revision"] <= grant["revision"] and e["operation_mask"] & PUBLISH for e in status["entries"])):
                    raise ProviderError("provider_publication_not_authorized")
                if lease_seconds > grant["maximum_fact_seconds"]:
                    raise ProviderError("provider_invalid_limit")
                semantic = {"allocation_id": allocation_id, "ref": ref, "root_key": root, "fact_sha256": document_sha256(provider_fact),
                            "node_key_id": binding[0], "storage_epoch": binding[1], "lease_seconds": lease_seconds,
                            "grant_sha256": document_sha256(authorization["publication_grant"])}
                reference = document_sha256({"allocation_id": allocation_id, "publisher": self.identity.key_id, "node_key_id": binding[0], "storage_epoch": binding[1]})
                put_body = {"fact": provider_fact, "provider_node": self.participant.descriptor,
                            "publication_grant": authorization["publication_grant"], "resource_lease": authorization["resource_lease"],
                            "owner_status": authorization["owner_status"], "allocation_id": "publication_" + reference, "lease_seconds": lease_seconds}
                session = self._session("publish", reference, semantic, {"body": put_body}, lease["expires_at"] + 60)
                # The first exact body is frozen locally before the remote put;
                # retries keep it byte-identical even after local descriptor refresh.
                if "index_lease" in session:
                    response = await self.call(node, "provider.result", {"allocation_id": session["body"]["allocation_id"], "operation": "provider.put"}, budget)
                else:
                    response = await self.call(node, "provider.put", session["body"], budget)
                index = verify_index_lease(response["index_lease"], fact=provider_fact, node=node,
                                           allow_expired=response["current_state"] != "active")
                if "index_lease" in session and session["index_lease"] != response["index_lease"]:
                    raise ProviderError("provider_local_conflict")
                self._append("publish", reference, {"index_lease": response["index_lease"]})
                results.append({"directory": node, "fact": provider_fact, "index_lease": response["index_lease"],
                                "current_state": response["current_state"], "expires_at": index["expires_at"]})
            except (MemoryError, OSError, TimeoutError) as error:
                errors.append(self._error(old, error))
        active = sum(r["current_state"] == "active" for r in results)
        return {"state": "published" if active else "pending", "publications": results, "errors": errors[:64],
                "partial": active < directory_count, **self._metrics(budget)}
