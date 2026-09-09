"""Finite open routing participant and optional, separately running HTTP node.

The participant reuses the existing identity and protected transport database.
It never opens a Vault, changes a trust store, or handles private message bodies.
An introduction is only a pending destination until its endpoint answers a
fresh, signed challenge. Resource service is an explicit local owner policy.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import socket
import sqlite3
import threading
import time
from typing import Any, Mapping

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network import NetworkClient, _read_private
from memory_vault_network_crypto import document, document_sha256, integer, object_fields
from memory_vault_open_control import (
    contact_key, coordinate, issue_node, sign_request, sign_response,
    verify_contact, verify_node, verify_response, verify_request,
    MAX_DESCRIPTOR_BYTES, MAX_DESCRIPTOR_SECONDS,
)
from memory_vault_open_index import OpenIndex
from memory_vault_open_routing import LookupBudget, RoutingTable, RpcReply, lookup, maintenance_target
from memory_vault_open_state import OpenCheckpoints
from memory_vault_open_transport import MAX_RPC_BYTES, RPC_PATH, OpenHTTPTransport, endpoint
from memory_vault_trust import Identity, _absolute_path, _atomic_write_private, _exclusive_store

NODE_CONFIG = "memory-vault-open-node-config/v1"
NODE_PATH = "/open/v1/node"
RENEW_BEFORE_SECONDS = 300


class _TransportState(NetworkClient):
    """Reuse the one protected network.sqlite3 implementation, not a new store."""

    def __init__(self, directory: Path, identity: Identity, storage_epoch: str | None):
        self.directory = Path(directory)
        if not self.directory.is_absolute():
            raise MemoryError("network_separate_state_required")
        self._binding = {"profile": "open-routing-v1", "signing_key": identity.public_descriptor(),
                         "storage_epoch": storage_epoch}


class _NodePublication:
    """One config lock owns renewal; each persisted signed revision is immutable.

    The config is the durable local authority for restart. The public file is
    replaced only after that config and the existing observation floor commit.
    A crash at any intermediate point reuses the saved revision, not a fork.
    """
    def __init__(self, path, config, identity):
        self.path = _absolute_path(path)
        self.introduction_path = self.path.with_name("node-introduction.json")
        self.config, self.identity = document(canonical_bytes(config)), identity
        original = verify_node(config["node"], allow_expired=True)
        if original["signing_key"] != identity.public_descriptor() or original["status"] != "active":
            raise MemoryError("open_wrong_node")
        endpoint(original["base_url"], allow_loopback=config["allow_loopback"])
        self.binding = {name: original[name] for name in ("signing_key", "storage_epoch", "base_url", "roles")}
        self.state = _TransportState(Path(config["state_directory"]), identity, original["storage_epoch"])
        self.current = None

    def _checked(self, descriptor, now):
        raw = verify_node(descriptor, now=now, allow_expired=True)
        if raw["status"] != "active":
            raise MemoryError("open_control_revoked")
        if any(raw[name] != value for name, value in self.binding.items()):
            raise MemoryError("open_node_publication_binding_mismatch")
        return raw

    def refresh(self, accept=None):
        now = int(time.time())
        if self.current is not None and self.current["payload"]["expires_at"] - now > RENEW_BEFORE_SECONDS:
            return self.current
        stored = _read_private(self.path, MAX_RPC_BYTES)
        config = document(stored, maximum=MAX_RPC_BYTES)
        if {key: value for key, value in config.items() if key != "node"} != {
                key: value for key, value in self.config.items() if key != "node"}:
            raise MemoryError("open_node_configuration_changed")
        candidates = [config["node"]]
        introduction_bytes = _read_private(self.introduction_path, MAX_DESCRIPTOR_BYTES)
        introduction = document(introduction_bytes, maximum=MAX_DESCRIPTOR_BYTES) if introduction_bytes is not None else None
        if introduction is not None:
            candidates.append(introduction)
        with self.state.db() as db:
            checkpoints = OpenCheckpoints(db)
            checkpoints.initialize()
            row = db.execute("SELECT revision,digest,record,status,second_record FROM open_control_floors WHERE kind='node' AND key_id=?",
                             (self.identity.key_id,)).fetchone()
            if row is not None:
                if row["status"] == "conflict" or row["second_record"] is not None:
                    raise MemoryError("open_control_conflict")
                if row["status"] != "active":
                    raise MemoryError("open_control_revoked")
                record = document(bytes(row["record"]), maximum=MAX_DESCRIPTOR_BYTES)
                recorded = self._checked(record, now)
                if recorded["revision"] != row["revision"] or document_sha256(record) != row["digest"]:
                    raise MemoryError("open_node_publication_corrupt")
                candidates.append(record)
        revisions = {}
        for descriptor in candidates:
            raw = self._checked(descriptor, now)
            digest = document_sha256(descriptor)
            previous = revisions.get(raw["revision"])
            if previous is not None and previous != digest:
                raise MemoryError("open_control_conflict")
            revisions[raw["revision"]] = digest
        latest = max(candidates, key=lambda item: item["payload"]["revision"])
        raw = latest["payload"]
        if raw["expires_at"] - now <= RENEW_BEFORE_SECONDS:
            latest = issue_node(self.identity, base_url=raw["base_url"], storage_epoch=raw["storage_epoch"],
                                roles=raw["roles"], revision=integer(raw["revision"] + 1, minimum=1),
                                issued_at=now, expires_at=integer(now + MAX_DESCRIPTOR_SECONDS))
        updated = {**config, "node": latest}
        if canonical_bytes(config) != canonical_bytes(updated):
            _atomic_write_private(self.path, canonical_bytes(updated) + b"\n")
        if accept is not None:
            accept(latest)
        else:
            with self.state.db() as db:
                OpenCheckpoints(db).accept(latest, now=now)
        if introduction is None or canonical_bytes(introduction) != canonical_bytes(latest):
            _atomic_write_private(self.introduction_path, canonical_bytes(latest))
        self.config, self.current = updated, document(canonical_bytes(latest), maximum=MAX_DESCRIPTOR_BYTES)
        return self.current


class OpenParticipant:
    def __init__(self, identity: Identity, state_directory: Path, *, seeds: list,
                 descriptor: Mapping[str, Any] | None = None, allow_loopback: bool = False,
                  index_policy: Mapping[str, Any] | None = None, contact_policy: Mapping[str, Any] | None = None,
                  delivery_policy: Mapping[str, Any] | None = None, provider_policy: Mapping[str, Any] | None = None,
                  encryption_identity=None):
        if not isinstance(seeds, list) or len(seeds) > 2:
            raise MemoryError("open_two_initial_introductions_maximum")
        self.identity = identity
        self.descriptor = document(descriptor) if descriptor is not None else None
        own = verify_node(self.descriptor) if self.descriptor else None
        if own is not None and (own["signing_key"] != identity.public_descriptor() or own["status"] != "active"):
            raise MemoryError("open_wrong_node")
        self.transport = OpenHTTPTransport(allow_loopback=allow_loopback)
        self.state = _TransportState(state_directory, identity, own["storage_epoch"] if own else None)
        self.table = RoutingTable(identity.key_id, directory=bool(own and "directory" in own["roles"]))
        self.seeds = [document(canonical_bytes(document(seed, maximum=4096)), maximum=4096) for seed in seeds]
        for seed in self.seeds:
            # An expired original is only a fixed-key endpoint introduction.
            # It cannot enter routing or authorize an RPC until refreshed.
            checked = verify_node(seed, allow_expired=True)
            if checked["status"] != "active":
                raise MemoryError("open_seed_inactive")
            endpoint(seed["payload"]["base_url"], allow_loopback=allow_loopback)
        if len({seed["payload"]["signing_key"]["key_id"] for seed in self.seeds}) != len(self.seeds):
            raise MemoryError("open_duplicate_seed")
        self.index_policy = dict(index_policy or {})
        self.contact_policy = dict(contact_policy or {})
        self.delivery_policy = dict(delivery_policy or {})
        self.provider_policy = dict(provider_policy or {})
        self.encryption_identity = encryption_identity
        if self.provider_policy and encryption_identity is None:
            raise MemoryError("open_provider_encryption_identity_required")
        from memory_vault_open_contact_state import ContactState
        if set(self.index_policy) - {"enabled", "maximum_records", "maximum_bytes", "maximum_replays", "maximum_lease_seconds"}:
            raise MemoryError("open_invalid_index_policy")
        self._pending: OrderedDict[str, dict] = OrderedDict()
        self._pending_lock = threading.Lock()
        self._operation = threading.Lock()
        self._descriptor_lock = threading.RLock()
        self._publication = None
        self._maintenance_cycle = 0
        self._seed_refresh_after = 0.0
        with self.state.db() as db:
            OpenCheckpoints(db).initialize()
            db.execute("CREATE TABLE IF NOT EXISTS open_peer_cache (key_id TEXT PRIMARY KEY,node BLOB NOT NULL,seen_at INTEGER NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS open_peer_seen ON open_peer_cache(seen_at)")
            db.commit()
            if self.descriptor:
                OpenCheckpoints(db).accept(self.descriptor)
                OpenIndex(db, identity, self.descriptor, **self.index_policy).initialize()
                ContactState(db, identity, self.descriptor, **self.contact_policy).initialize()
                if self.delivery_policy:
                    from memory_vault_open_delivery_state import DeliveryState
                    DeliveryState(db, identity, self.descriptor, **self.delivery_policy).initialize()
                if self.provider_policy:
                    from memory_vault_open_provider_state import ProviderState
                    ProviderState(db, identity, self.descriptor, encryption_identity=encryption_identity,
                                  **self.provider_policy).initialize()

    def close(self):
        self.transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _accept(self, descriptor):
        with self.state.db() as db:
            return OpenCheckpoints(db).accept(descriptor)

    def refresh_descriptor(self):
        if self._publication is None:
            return
        with self._descriptor_lock:
            self.descriptor = self._publication.refresh(self._accept)

    def current_introduction(self):
        """Read-only public snapshot; never include config or either private key."""
        with self._descriptor_lock:
            if self.descriptor is None:
                raise MemoryError("open_node_not_configured")
            descriptor = document(canonical_bytes(self.descriptor), maximum=MAX_DESCRIPTOR_BYTES)
            verify_node(descriptor)
            return descriptor

    async def _refresh_seed_introductions(self, budget, *, force=False):
        """At most the two configured origins, inside the existing lookup budget.

        A fetched signature is still an introduction; normal hello/challenge
        must prove the endpoint before it enters the routing table.
        """
        errors = []
        if not force and time.monotonic() < self._seed_refresh_after:
            return errors
        self._seed_refresh_after = time.monotonic() + 30
        for index, original in enumerate(self.seeds):
            before = verify_node(original, allow_expired=True)
            if before["expires_at"] > int(time.time()) + 60:
                continue
            try:
                budget.check()
                budget.charge_request()
                reply = await asyncio.to_thread(self.transport.request_node, before["base_url"], deadline=budget.deadline)
                budget.charge_bytes(reply.wire_bytes)
                after = verify_node(reply.response)
                if (after["status"] != "active" or after["revision"] <= before["revision"]
                        or any(after[name] != before[name] for name in ("signing_key", "storage_epoch", "base_url", "roles"))):
                    raise MemoryError("open_seed_refresh_mismatch")
                self._accept(reply.response)
                self._cache(reply.response)
                self.seeds[index] = document(canonical_bytes(reply.response), maximum=MAX_DESCRIPTOR_BYTES)
            except MemoryError as exc:
                errors.append(exc.code)
        return errors

    def _cache(self, node):
        """Small restart introductions; a cache hit is not a fresh endpoint proof."""
        now = int(time.time())
        with self.state.db() as db:
            db.execute("INSERT OR REPLACE INTO open_peer_cache VALUES(?,?,?)",
                       (node["payload"]["signing_key"]["key_id"], canonical_bytes(node), now))
            db.execute("DELETE FROM open_peer_cache WHERE key_id NOT IN (SELECT key_id FROM open_peer_cache ORDER BY seen_at DESC,key_id LIMIT 32)")

    def _initial(self, target: str, view: str):
        candidates = self.table.closest(target, view, limit=16)
        if view == "directory":
            candidates += self.table.closest(target, "general", limit=8)
        # Explicit initial introductions retain a probe opportunity even when
        # their bucket is full. No administrator-provided global routing pool.
        candidates = self.seeds + candidates
        with self.state.db() as db:
            candidates += [document(bytes(row[0])) for row in db.execute(
                "SELECT node FROM open_peer_cache ORDER BY seen_at DESC,key_id LIMIT 32")]
        unique = {}
        for node in candidates:
            try:
                raw = verify_node(node)
                if raw["status"] == "active" and raw["signing_key"]["key_id"] != self.identity.key_id:
                    key = raw["signing_key"]["key_id"]
                    previous = unique.get(key)
                    # Keep a seed's probe position, but prefer a newer signed
                    # incarnation already present in the table/restart cache.
                    # Selection remains an introduction; _rpc still checks the
                    # durable floor and challenges its exact descriptor.
                    if previous is None or raw["revision"] > previous["payload"]["revision"]:
                        unique[key] = node
            except MemoryError:
                continue
        # Scan all bounded inputs before truncation, since a newer incarnation
        # of an early seed may be the last cache entry.
        nodes = list(unique.values())[:32]
        return [nodes[::2], nodes[1::2]]

    def _request(self, node, action, body):
        now = int(time.time())
        return sign_request(self.identity, node=node, action=action, body=body,
                            request_id="open_" + secrets.token_hex(16), issued_at=now, expires_at=now + 60)

    async def _rpc(self, node, request, deadline):
        self._accept(node)
        reply = await asyncio.to_thread(self.transport.request, node["payload"]["base_url"], request, deadline=deadline)
        checked = verify_response(reply.response, request=request, node=node)
        self._accept(node)
        if request["payload"]["action"] == "hello" and "node" in checked["body"]:
            actual = checked["body"]["node"]
            self._accept(actual)
        else:
            actual = node
        if "error" not in checked["body"]:
            self._cache(actual)
        return RpcReply(reply.response, reply.observed_address, reply.wire_bytes)

    async def _call(self, node, action, body, budget, *, endpoint_result=None):
        budget.check()
        request = self._request(node, action, body)
        budget.charge_request_bytes(len(canonical_bytes(request)))
        budget.charge_request()
        reply = await self._rpc(node, request, budget.deadline)
        budget.charge_bytes(reply.wire_bytes)
        payload = verify_response(reply.response, request=request, node=node)
        # A signed hello rejection still proves the challenged seed's endpoint.
        # Preserve that route so queue backpressure cannot strand a new node;
        # the operation error below still reports that admission did not occur.
        actual = payload["body"].get("node", node) if action == "hello" else node
        if action == "hello" or "error" not in payload["body"]:
            self.table.learn_verified(actual, reply.observed_address)
        if "error" in payload["body"]:
            error = payload["body"]["error"]
            raise MemoryError(error["code"], retryable=error["retryable"])
        if endpoint_result is not None:
            endpoint_result["socket"] = (reply.observed_address, endpoint(node["payload"]["base_url"],
                                          allow_loopback=self.transport.allow_loopback)[2])
        return payload["body"]

    async def _lookup(self, target, view, budget):
        # Discovery/send can be the first online operation of an existing
        # client; seed renewal must not depend on an earlier explicit join.
        refresh_errors = await self._refresh_seed_introductions(budget)
        result = await lookup(self.table, target, view=view, rpc=self._rpc,
                              sign_request=self._request, initial_lanes=self._initial(target, view), budget=budget)
        result["partial"] = result["partial"] or bool(refresh_errors)
        return result

    @staticmethod
    def _metrics(budget):
        return {"requests": budget.requests, "request_bytes": budget.request_bytes,
                "response_bytes": budget.response_bytes}

    async def join(self):
        budget = LookupBudget()
        errors = await self._refresh_seed_introductions(budget, force=True)
        # Rejoining may already have a newer verified incarnation in the
        # restart cache. Keep the same explicit seed keys, resolving their
        # current signed bytes through the bounded merge used by lookup.
        initial = self._initial(coordinate(self.identity.key_id), "general")
        known = {node["payload"]["signing_key"]["key_id"]: node for lane in initial for node in lane}
        for configured in self.seeds:
            seed = known.get(configured["payload"]["signing_key"]["key_id"], configured)
            try:
                await self._call(seed, "hello", {"node": self.descriptor}, budget)
            except MemoryError as exc:
                errors.append(exc.code)
        result = await self._lookup(coordinate(self.identity.key_id), "general", budget)
        # Notify only a bounded number of actually proven peers. The receiver
        # queues this self-advertisement; it does not trust the claimed URL yet.
        if self.descriptor:
            for peer in result["candidates"][:2]:
                try:
                    await self._call(peer, "hello", {"node": self.descriptor}, budget)
                except MemoryError as exc:
                    errors.append(exc.code)
        return {"state": result["state"], "routing": self.table.stats(), "metrics": self._metrics(budget),
                "partial": bool(errors) or result["partial"], "errors": errors,
                "authority_required": False, "discovery_grants_access": False}

    async def maintain(self):
        """One node-local turn, not an agent scheduler or a global refresh."""
        self.refresh_descriptor()
        cleanup_errors = []
        if self.descriptor is not None:
            try:
                if self.delivery_policy.get("enabled") is True:
                    from memory_vault_open_delivery_state import DeliveryState
                    with self.state.db() as db:
                        DeliveryState(db, self.identity, self.descriptor, **self.delivery_policy).collect_expired(limit=16)
                if self.provider_policy.get("enabled") is True:
                    from memory_vault_open_provider_state import ProviderState
                    with self.state.db() as db:
                        ProviderState(db, self.identity, self.descriptor, encryption_identity=self.encryption_identity,
                                      **self.provider_policy).collect_expired(limit=16)
            except (MemoryError, sqlite3.Error) as exc:
                cleanup_errors.append(getattr(exc, "code", "open_storage_unavailable"))
        budget = LookupBudget(maximum_requests=16, maximum_bytes=1024 * 1024, maximum_seconds=5)
        pending = []
        with self._pending_lock:
            for _ in range(min(2, len(self._pending))):
                pending.append(self._pending.popitem(last=False)[1])
        errors = cleanup_errors + await self._refresh_seed_introductions(budget)
        for peer in pending:
            try:
                await self._call(peer, "hello", {"node": None}, budget)
            except MemoryError as exc:
                errors.append(exc.code)
        cycle = self._maintenance_cycle
        target = maintenance_target(self.identity.key_id, cycle)
        self._maintenance_cycle += 1
        # A full remote introduction queue may reject a first announcement.
        # Retry our own announcement within this same maintenance allowance,
        # rotating over the nearest proven peers to OUR coordinate. Random
        # refresh targets discover routes, but announcing only in those regions
        # can leave our own neighbourhood unable to introduce us to a lookup.
        # No fresh third-party URL is promoted by this selection step.
        if self.descriptor is not None:
            peers = self.table.closest(coordinate(self.identity.key_id), "general", limit=8)
            for offset in range(min(2, len(peers))):
                peer = peers[(cycle * 2 + offset) % len(peers)]
                try:
                    await self._call(peer, "hello", {"node": self.descriptor}, budget)
                except MemoryError as exc:
                    errors.append(exc.code)
        result = await self._lookup(target, "general", budget)
        return {"state": result["state"], "metrics": self._metrics(budget), "errors": errors}

    async def find_contact(self, owner_key_id: str, *, budget=None):
        key = contact_key(owner_key_id)
        budget = budget or LookupBudget()
        route = await self._lookup(key, "directory", budget)
        found, errors, states = [], [], []
        # A directory may be queried locally under the exact same signed API.
        peers = list(route["candidates"])
        if self.descriptor and "directory" in self.descriptor["payload"]["roles"]:
            peers.append(self.descriptor)
        for node in peers[:8]:
            try:
                body = await self._call(node, "get", {"key": key}, budget)
                states.append(body["state"])
                if body["state"] == "found":
                    self._accept(body["contact"])
                    found.append(body)
            except MemoryError as exc:
                errors.append(exc.code)
        # Finish observing all selected shards before selecting any result: a
        # later response may reveal a newer revision or a conflicting signature.
        eligible = []
        for body in found:
            try:
                self._accept(body["contact"])
                eligible.append(body)
            except MemoryError as exc:
                errors.append(exc.code)
        best = max(eligible, key=lambda x: x["contact"]["payload"]["revision"], default=None)
        # Unsigned owner state is never inferred from a directory's assertion.
        # Any reported conflict/revocation is inconclusive but stops this read.
        if set(states) & {"conflict", "revoked"}:
            best = None
        return {"state": "found" if best else "inconclusive", "contact": best["contact"] if best else None,
                "lease": best["lease"] if best else None, "metrics": self._metrics(budget),
                "route": route, "errors": errors, "discovery_grants_access": False,
                "encryption_key_possession_proven": False}

    async def publish_contact(self, contact, *, lease_seconds=300):
        owner = verify_contact(contact)
        if owner["signing_key"] != self.identity.public_descriptor():
            raise MemoryError("open_contact_owner_required")
        try:
            self._accept(contact)
        except MemoryError as exc:
            # accept persists a valid revocation before refusing its use as an
            # active contact. The verified owner may still propagate those
            # exact withdrawal bytes to directories. Rollback/conflict/storage
            # failures remain terminal; no general checkpoint rule is relaxed.
            if owner["status"] != "revoked" or exc.code != "open_control_revoked":
                raise
        budget = LookupBudget()
        route = await self._lookup(contact_key(self.identity.key_id), "directory", budget)
        receipts, errors, keys, addresses = [], [], set(), set()
        for node in route["candidates"]:
            raw = node["payload"]
            if raw["signing_key"]["key_id"] in keys or raw["base_url"] in addresses:
                continue
            try:
                observed = {}
                body = await self._call(node, "put", {"contact": contact, "lease_seconds": lease_seconds}, budget,
                                        endpoint_result=observed)
                if observed["socket"] in addresses:
                    continue
                receipts.append(body["lease"])
                keys.add(raw["signing_key"]["key_id"])
                addresses.add(observed["socket"])
            except MemoryError as exc:
                errors.append(exc.code)
            if len(receipts) == 3:
                break
        return {"state": "leased" if len(receipts) == 3 else "degraded", "confirmed_leases": len(receipts),
                "desired_leases": 3, "leases": receipts, "metrics": self._metrics(budget), "errors": errors,
                "physical_failure_domains_verified": False}

    def handle(self, request):
        if self.descriptor is None:
            raise MemoryError("open_node_not_configured")
        from memory_vault_open_contact import PROFILE, verify_rpc, sign_response as contact_response
        payload = request.get("payload") if isinstance(request, Mapping) else None
        if isinstance(payload, Mapping) and payload.get("schema_version") == "memory-vault-open-delivery-control/v1":
            from memory_vault_open_delivery import verify_rpc as delivery_verify, sign_response as delivery_response
            from memory_vault_open_delivery_state import DeliveryState
            delivery_verify(request, node=self.descriptor)
            try:
                if not self.delivery_policy:
                    raise MemoryError("open_delivery_closed")
                with self.state.db() as db:
                    result = DeliveryState(db, self.identity, self.descriptor, **self.delivery_policy).handle(request)
            except MemoryError as exc:
                result = {"error": {"code": exc.code, "retryable": bool(exc.retryable)}}
            return delivery_response(self.identity, request=request, node=self.descriptor, body=result)
        if isinstance(payload, Mapping) and payload.get("schema_version") == "memory-vault-open-provider/v1":
            from memory_vault_open_provider import verify_rpc as provider_verify, sign_response as provider_response
            from memory_vault_open_provider_state import ProviderState
            provider_verify(request, node=self.descriptor)
            try:
                if not self.provider_policy:
                    raise MemoryError("open_provider_closed")
                with self.state.db() as db:
                    result = ProviderState(db, self.identity, self.descriptor,
                        encryption_identity=self.encryption_identity, **self.provider_policy).handle(request)
            except MemoryError as exc:
                result = {"error": {"code": exc.code, "retryable": bool(exc.retryable)}}
            return provider_response(self.identity, request=request, node=self.descriptor, body=result)
        if isinstance(payload, Mapping) and payload.get("schema_version") == PROFILE:
            from memory_vault_open_contact_state import ContactState
            verify_rpc(request, node=self.descriptor)
            try:
                with self.state.db() as db:
                    result = ContactState(db, self.identity, self.descriptor, **self.contact_policy).handle(request)
            except MemoryError as exc:
                result = {"error": {"code": exc.code, "retryable": bool(exc.retryable)}}
            return contact_response(self.identity, request=request, node=self.descriptor, body=result)
        now = int(time.time())
        original = verify_request(request, node=self.descriptor, now=now)
        try:
            action, body = original["action"], original["body"]
            if action == "hello":
                if body["node"] is not None:
                    self._accept(body["node"])
                    key = body["node"]["payload"]["signing_key"]["key_id"]
                    with self._pending_lock:
                        if self.table.has_verified(body["node"]):
                            # Already-proven unchanged neighbours must not keep
                            # refilling the queue ahead of new endpoint probes.
                            # This does not learn the inbound claim, renew its
                            # expiry, or reset any failed-probe counter.
                            self._pending.pop(key, None)
                        elif len(self._pending) >= 32 and key not in self._pending:
                            raise MemoryError("open_pending_capacity", retryable=True)
                        else:
                            self._pending[key] = body["node"]
                result = {"node": self.descriptor}
            elif action == "find":
                result = {"nodes": self.table.reply_candidates(body["target"], body["view"])}
            else:
                with self.state.db() as db:
                    index = OpenIndex(db, self.identity, self.descriptor, **self.index_policy)
                    result = index.handle(request, now=now)
        except MemoryError as exc:
            result = {"error": {"code": exc.code, "retryable": bool(exc.retryable)}}
        return sign_response(self.identity, request=request, node=self.descriptor, body=result,
                             issued_at=now, expires_at=min(now + 60, original["expires_at"]))

    def handle_blob(self, request, chunk):
        if self.descriptor is None:
            raise MemoryError("open_node_not_configured")
        from memory_vault_open_blob import verify_blob_request, sign_blob_response
        from memory_vault_open_delivery_state import DeliveryState
        verify_blob_request(request, node=self.descriptor)
        try:
            if not self.delivery_policy:
                raise MemoryError("open_delivery_closed")
            with self.state.db() as db:
                body, output = DeliveryState(db, self.identity, self.descriptor, **self.delivery_policy).handle_blob(request, chunk)
        except MemoryError as exc:
            body, output = {"error": {"code": exc.code, "retryable": bool(exc.retryable)}}, b""
        return sign_blob_response(self.identity, request=request, node=self.descriptor, body=body), output


class OpenHTTPServer(ThreadingHTTPServer):
    """Bounded HTTP admission. No plaintext, HTTP redirects or secret logging."""
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, participant):
        self.participant = participant
        self._slots = threading.BoundedSemaphore(8)
        self._rate_lock = threading.Lock()
        self._rate = OrderedDict()
        self._global_rate = (0, 0)
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def admitted(self, address):
        now = int(time.monotonic())
        with self._rate_lock:
            start, count = self._global_rate
            count = count + 1 if start == now else 1
            self._global_rate = (now, count)
            previous = self._rate.get(address, (-1, 0))
            per_source = previous[1] + 1 if previous[0] == now else 1
            self._rate[address] = (now, per_source)
            self._rate.move_to_end(address)
            while len(self._rate) > 256:
                self._rate.popitem(last=False)
            return count <= 128 and per_source <= 64

    def handle_error(self, request, client_address):
        # Exceptions can contain headers, request content or local paths.
        pass


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        self.request.settimeout(3)
        super().setup()
        self.rfile = _HeaderBudget(self.rfile)
        # Limit the whole incoming exchange, including a drip-fed header/body.
        self._deadline = threading.Timer(3, self._abort)
        self._deadline.daemon = True
        self._deadline.start()

    def _abort(self):
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        try:
            super().finish()
        finally:
            self._deadline.cancel()

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.close_connection = True
        if not self.server.admitted(self.client_address[0]):
            self.send_error(429)
            return
        if self.path != NODE_PATH:
            self.send_error(404)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if ((lengths and lengths != ["0"]) or self.headers.get_all("Transfer-Encoding")
                or self.headers.get_all("Content-Encoding")):
            self.send_error(400)
            return
        try:
            encoded = canonical_bytes(self.server.participant.current_introduction())
            if len(encoded) > MAX_DESCRIPTOR_BYTES:
                raise MemoryError("open_response_too_large")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)
        except MemoryError:
            self.send_error(503)

    def do_POST(self):
        self.close_connection = True
        if not self.server.admitted(self.client_address[0]):
            self.send_error(429)
            return
        try:
            is_blob = self.path == "/open/v1/blob"
            maximum = 270350 if is_blob else MAX_RPC_BYTES
            lengths = self.headers.get_all("Content-Length", [])
            if (self.path not in {RPC_PATH, "/open/v1/blob"} or len(lengths) != 1 or not lengths[0].isascii()
                    or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= maximum
                    or self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding")):
                raise MemoryError("open_invalid_http_request")
            if is_blob and (lengths[0] != str(int(lengths[0])) or self.headers.get_all("Content-Type", []) != ["application/octet-stream"]):
                raise MemoryError("open_invalid_http_request")
            size = int(lengths[0])
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise MemoryError("open_invalid_http_request")
            if is_blob:
                from memory_vault_open_blob import decode_blob_frame, encode_blob_frame
                frame = decode_blob_frame(raw)
                response, chunk = self.server.participant.handle_blob(frame.header, frame.chunk)
                encoded = encode_blob_frame(response, chunk)
            else:
                response = self.server.participant.handle(document(raw, maximum=MAX_RPC_BYTES))
                encoded = canonical_bytes(response)
            if len(encoded) > maximum:
                raise MemoryError("open_response_too_large")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream" if is_blob else "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)
        except (MemoryError, ValueError):
            self.send_error(400)
        except sqlite3.Error:
            self.send_error(503)


class _HeaderBudget:
    def __init__(self, stream):
        self.stream, self.used = stream, 0

    def readline(self, limit=-1):
        remaining = 16384 - self.used
        result = self.stream.readline(min(limit if limit >= 0 else 16385, remaining + 1))
        self.used += len(result)
        if self.used > 16384:
            raise MemoryError("open_headers_too_large")
        return result

    def __getattr__(self, name):
        return getattr(self.stream, name)


def _run_node(config_path):
    raw = _read_private(config_path, MAX_RPC_BYTES)
    parsed = document(raw, maximum=MAX_RPC_BYTES)
    optional = {"contact_policy", "delivery_policy", "provider_policy", "encryption_key_path"}
    config = object_fields(parsed,
                           {"schema_version", "identity_path", "state_directory", "node", "seeds", "allow_loopback", "index_policy", "listen_host", "listen_port"} | (optional & set(parsed)))
    if config["schema_version"] != NODE_CONFIG:
        raise MemoryError("open_invalid_node_config")
    if (config["listen_host"] != "127.0.0.1" or type(config["listen_port"]) is not int
            or not 1024 <= config["listen_port"] <= 65535):
        raise MemoryError("open_invalid_listener")
    # Public HTTPS termination is owner-operated. This process never opens a
    # public listener, installs a service, obtains certificates or buys resources.
    from memory_vault_network_crypto import EncryptionIdentity
    encryption_identity = EncryptionIdentity.load(Path(config["encryption_key_path"])) if "encryption_key_path" in config else None
    identity = Identity.load(Path(config["identity_path"]))
    publication = _NodePublication(config_path, config, identity)
    config = {**config, "node": publication.refresh()}
    with OpenParticipant(identity, Path(config["state_directory"]),
                         seeds=config["seeds"], descriptor=config["node"],
                         allow_loopback=config["allow_loopback"], index_policy=config["index_policy"],
                         contact_policy=config.get("contact_policy"), delivery_policy=config.get("delivery_policy"),
                         provider_policy=config.get("provider_policy"), encryption_identity=encryption_identity) as participant:
        participant._publication = publication
        server = OpenHTTPServer((config["listen_host"], config["listen_port"]), participant)
        stop = threading.Event()
        def maintenance():
            try:
                asyncio.run(participant.join())
            except (MemoryError, OSError, sqlite3.Error):
                pass
            while not stop.wait(2):
                try:
                    asyncio.run(participant.maintain())
                except (MemoryError, OSError, sqlite3.Error):
                    pass
        worker = threading.Thread(target=maintenance, daemon=True)
        worker.start()
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            stop.set()
            server.server_close()
            # Keep the publication lock until this process's last maintenance
            # turn has ended, including any durable descriptor write.
            worker.join()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run an owner-configured finite open routing node")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    # A second process must not sign a different successor to the same saved
    # revision. The existing cross-platform protected file lock is held for
    # this node's lifetime; a crashed process releases the OS lock naturally.
    with _exclusive_store(_absolute_path(args.config)):
        _run_node(args.config)


if __name__ == "__main__":
    main()
