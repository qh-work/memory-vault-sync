"""Bounded native open routing. A reachable peer never grants Memory authority.

RPC adapters must enforce their absolute deadline and return the actual socket
address and response byte count. Introductions are not successful probes. The
security store, outside this disposable routing cache, owns persistent high water.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import digest
from memory_vault_open_control import (
    MAX_CONTROL_BYTES, MAX_DESCRIPTOR_BYTES, coordinate, verify_node, verify_response,
)

BUCKET_SIZE = 8
REPLACEMENTS = 2
SOURCE_CAP = 2
MAX_CANDIDATES = 32
MAX_LANE_CANDIDATES = 16
MAX_LANE_REQUESTS = 32
MAX_CONCURRENT = 3


class OpenRoutingError(MemoryError):
    pass


def source_group(address: str) -> str:
    if not isinstance(address, str) or "%" in address:
        raise OpenRoutingError("open_invalid_observed_address")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise OpenRoutingError("open_invalid_observed_address") from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    prefix = 24 if ip.version == 4 else 48
    return str(ip.version) + ":" + str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def distance(first: str, second: str) -> int:
    return int(digest(first), 16) ^ int(digest(second), 16)


def maintenance_target(key_id: str, cycle: int) -> str:
    coordinate(key_id)
    if type(cycle) is not int or not 0 <= cycle <= (1 << 53) - 1:
        raise OpenRoutingError("open_invalid_routing_budget")
    return hashlib.sha256(b"memory-vault-open-maintenance/v1\x00" + key_id.encode("ascii")
                          + b"\x00" + str(cycle).encode("ascii")).hexdigest()


def _view(value: str) -> str:
    if not isinstance(value, str) or value not in {"general", "directory"}:
        raise OpenRoutingError("open_invalid_view")
    return value


@dataclass
class _Entry:
    node: dict[str, Any]
    group: str
    failures: int = 0

    @property
    def key(self) -> str:
        return self.node["payload"]["signing_key"]["key_id"]


class RoutingTable:
    """Two fixed views; active entries require a verified challenge response.

    Callers must not pass an introduced peer to learn_verified. Lookup does this
    only after verifying the complete response binding. RLock protects HTTP and
    maintenance workers; no network operation occurs while this lock is held.
    """

    def __init__(self, key_id: str, directory: bool = False, now: Callable = time.time):
        if type(directory) is not bool:
            raise OpenRoutingError("open_invalid_view")
        self.key_id, self.coordinate, self.directory, self.now = key_id, coordinate(key_id), directory, now
        self._active: dict[str, dict[int, list[_Entry]]] = {"general": {}, "directory": {}}
        self._replacement: dict[str, dict[int, list[_Entry]]] = {"general": {}, "directory": {}}
        self._introductions: list[_Entry] = []
        self._lock = threading.RLock()

    def _bucket(self, node: Mapping[str, Any]) -> int:
        return distance(self.coordinate, node["payload"]["coordinate"]).bit_length() - 1

    def _prune(self) -> None:
        now = int(self.now())
        for mapping in (self._active, self._replacement):
            for buckets in mapping.values():
                for bucket, entries in list(buckets.items()):
                    kept = [e for e in entries if e.node["payload"]["expires_at"] > now]
                    if kept:
                        buckets[bucket] = kept
                    else:
                        del buckets[bucket]
        self._introductions = [e for e in self._introductions if e.node["payload"]["expires_at"] > now]
        for view, buckets in self._replacement.items():
            for bucket, spare in list(buckets.items()):
                active = self._active[view].setdefault(bucket, [])
                for entry in list(reversed(spare)):
                    if len(active) < BUCKET_SIZE and sum(e.group == entry.group for e in active) < SOURCE_CAP:
                        active.append(entry)
                        spare.remove(entry)
                if not active:
                    self._active[view].pop(bucket, None)
                if not spare:
                    del buckets[bucket]

    def _known(self, key: str) -> list[_Entry]:
        return [e for mapping in (self._active, self._replacement) for buckets in mapping.values()
                for entries in buckets.values() for e in entries if e.key == key] + [
                    e for e in self._introductions if e.key == key]

    def _remove(self, key: str) -> None:
        for mapping in (self._active, self._replacement):
            for buckets in mapping.values():
                for bucket, entries in list(buckets.items()):
                    kept = [e for e in entries if e.key != key]
                    if kept:
                        buckets[bucket] = kept
                    else:
                        del buckets[bucket]
        self._introductions = [e for e in self._introductions if e.key != key]

    def learn_verified(self, signednode: Mapping[str, Any], observed_address: str, *,
                       allow_replacement_eviction: bool = True) -> bool:
        # Bound and copy before storing; external mutation cannot change a peer.
        raw = canonical_bytes(signednode)
        if len(raw) > MAX_DESCRIPTOR_BYTES:
            raise OpenRoutingError("network_document_too_large")
        if type(allow_replacement_eviction) is not bool:
            raise OpenRoutingError("open_invalid_routing_budget")
        payload = verify_node(signednode, now=int(self.now()))
        node, group = copy.deepcopy(dict(signednode)), source_group(observed_address)
        key = payload["signing_key"]["key_id"]
        if key == self.key_id:
            return False
        with self._lock:
            self._prune()
            known = self._known(key)
            if known:
                previous = known[0].node["payload"]
                if payload["revision"] < previous["revision"]:
                    raise OpenRoutingError("open_node_rollback")
                if payload["revision"] == previous["revision"] and raw != canonical_bytes(known[0].node):
                    raise OpenRoutingError("open_node_revision_conflict")
            if payload["status"] != "active":
                self._remove(key)
                return False
            # Refresh in place, retaining stable peers. A changed observed source
            # still has to fit the source limit; move it to replacement otherwise.
            entry = _Entry(node, group)
            bucket = self._bucket(node)
            active_any = False
            for view in ("general", "directory"):
                participates = "router" in payload["roles"] if view == "general" else (
                    self.directory and "directory" in payload["roles"])
                active = self._active[view].setdefault(bucket, [])
                spare = self._replacement[view].setdefault(bucket, [])
                position = next((i for i, e in enumerate(active) if e.key == key), None)
                prior_spare = next((i for i, e in enumerate(spare) if e.key == key), None)
                others = [e for e in active if e.key != key]
                spare[:] = [e for e in spare if e.key != key]
                if participates and len(others) < BUCKET_SIZE and sum(e.group == group for e in others) < SOURCE_CAP:
                    if position is None:
                        active.append(copy.deepcopy(entry))
                    else:
                        active[position] = copy.deepcopy(entry)
                    active_any = True
                else:
                    active[:] = others
                    if participates:
                        if prior_spare is not None:
                            spare.insert(prior_spare, copy.deepcopy(entry))
                        elif len(spare) < REPLACEMENTS or allow_replacement_eviction:
                            spare.append(copy.deepcopy(entry))
                            del spare[:-REPLACEMENTS]
                if not active:
                    self._active[view].pop(bucket, None)
                if not spare:
                    self._replacement[view].pop(bucket, None)
            if not self.directory and "directory" in payload["roles"]:
                position = next((i for i, e in enumerate(self._introductions) if e.key == key), None)
                others = [e for e in self._introductions if e.key != key]
                if sum(e.group == group for e in others) < SOURCE_CAP:
                    if position is not None:
                        self._introductions[position] = copy.deepcopy(entry)
                    elif len(self._introductions) < 4:
                        self._introductions.append(copy.deepcopy(entry))
                else:
                    self._introductions = others
            elif "directory" not in payload["roles"]:
                self._introductions = [e for e in self._introductions if e.key != key]
            return active_any

    def closest(self, target: str, view: str = "general", limit: int = 8) -> list[dict[str, Any]]:
        digest(target)
        _view(view)
        if type(limit) is not int or not 0 <= limit <= MAX_CANDIDATES:
            raise OpenRoutingError("open_invalid_routing_budget")
        with self._lock:
            self._prune()
            entries = (self._introductions if view == "directory" and not self.directory else
                       [e for group in self._active[view].values() for e in group])
            return copy.deepcopy([e.node for e in sorted(entries,
                key=lambda e: (distance(target, e.node["payload"]["coordinate"]), e.key))[:limit]])

    def reply_candidates(self, target: str, view: str = "general") -> list[dict[str, Any]]:
        """Introduce proven replacements without evicting stable active peers.

        A replacement has answered its own signed challenge. Recipients must
        still probe it themselves; an introduction never transfers that proof.
        The response retains the eight-node and per-bucket source bounds.
        """
        digest(target)
        _view(view)
        with self._lock:
            self._prune()
            entries = (self._introductions if view == "directory" and not self.directory else
                       [e for mapping in (self._active, self._replacement)
                        for bucket in mapping[view].values() for e in bucket])
            result, sources = [], {}
            for entry in sorted(entries, key=lambda e: (distance(target, e.node["payload"]["coordinate"]), e.key)):
                source = (self._bucket(entry.node), entry.group)
                if sources.get(source, 0) >= SOURCE_CAP:
                    continue
                result.append(entry.node)
                sources[source] = sources.get(source, 0) + 1
                if len(result) == BUCKET_SIZE:
                    break
            if not result and view == "directory":
                return self.reply_candidates(target, "general")
            return copy.deepcopy(result)

    def mark_failed(self, key_id: str) -> bool:
        with self._lock:
            self._prune()
            removed = False
            for buckets in self._replacement.values():
                for bucket, entries in list(buckets.items()):
                    for entry in list(entries):
                        if entry.key == key_id:
                            entry.failures += 1
                            if entry.failures >= 2:
                                entries.remove(entry)
                                removed = True
                    if not entries:
                        del buckets[bucket]
            for view, buckets in self._active.items():
                for bucket, entries in list(buckets.items()):
                    for entry in list(entries):
                        if entry.key != key_id:
                            continue
                        entry.failures += 1
                        if entry.failures < 2:
                            continue
                        entries.remove(entry)
                        removed = True
                        spare = self._replacement[view].get(bucket, [])
                        for replacement in reversed(spare):
                            if sum(e.group == replacement.group for e in entries) < SOURCE_CAP:
                                entries.append(replacement)
                                spare.remove(replacement)
                                break
                    if not entries:
                        del buckets[bucket]
            for entry in list(self._introductions):
                if entry.key == key_id:
                    entry.failures += 1
                    if entry.failures >= 2:
                        self._introductions.remove(entry)
                        removed = True
            return removed

    def stats(self) -> dict[str, int]:
        with self._lock:
            self._prune()
            return {"general_active": sum(map(len, self._active["general"].values())),
                    "general_replacements": sum(map(len, self._replacement["general"].values())),
                    "directory_active": sum(map(len, self._active["directory"].values())),
                    "directory_replacements": sum(map(len, self._replacement["directory"].values())),
                    "directory_introductions": len(self._introductions)}


@dataclass(frozen=True)
class RpcReply:
    response: Mapping[str, Any]
    observed_address: str
    wire_bytes: int


class LookupBudget:
    """One cooperative budget shared by hello, find and contact RPC stages."""

    def __init__(self, maximum_requests: int = 64, maximum_bytes: int = 4 * 1024 * 1024,
                 maximum_seconds: float = 10, clock: Callable = time.monotonic):
        if (type(maximum_requests) is not int or not 1 <= maximum_requests <= 64
                or type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 4 * 1024 * 1024
                or type(maximum_seconds) not in (int, float) or not math.isfinite(maximum_seconds)
                or not 0 < maximum_seconds <= 10):
            raise OpenRoutingError("open_invalid_routing_budget")
        self.maximum_requests, self.maximum_bytes = maximum_requests, maximum_bytes
        self.clock, self.deadline = clock, clock() + maximum_seconds
        self.requests = self.bytes = self.request_bytes = 0

    @property
    def response_bytes(self) -> int:
        return self.bytes

    @property
    def remaining_requests(self) -> int:
        return max(0, self.maximum_requests - self.requests)

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.maximum_bytes - self.bytes)

    def check(self) -> None:
        if self.clock() >= self.deadline or self.requests > self.maximum_requests or self.bytes > self.maximum_bytes or self.request_bytes > self.maximum_requests * MAX_CONTROL_BYTES:
            raise OpenRoutingError("open_lookup_budget_exhausted")

    def charge_request(self) -> None:
        self.check()
        if not self.remaining_requests:
            raise OpenRoutingError("open_lookup_budget_exhausted")
        self.requests += 1

    def charge_bytes(self, count: int) -> None:
        if type(count) is not int or count < 0:
            raise OpenRoutingError("open_invalid_routing_budget")
        self.bytes += count
        self.check()

    def charge_request_bytes(self, count: int) -> None:
        if type(count) is not int or not 0 <= count <= MAX_CONTROL_BYTES:
            raise OpenRoutingError("open_invalid_routing_budget")
        self.request_bytes += count
        self.check()


async def lookup(table: RoutingTable, target: str, *, view: str = "general", rpc: Callable,
                 sign_request: Callable, initial_lanes=None, budget: LookupBudget | None = None) -> dict[str, Any]:
    """Iterative, non-recursive lookup. Only challenge-verified replies count.

    Each live lane has a scheduling slot. Source bits and a single actual result
    are shared when both introductions name one peer; first sight is not ownership.
    Shortlists retain at most 16 memberships per lane and 32 descriptors overall.
    """
    digest(target)
    _view(view)
    budget = budget or LookupBudget()
    candidates: dict[str, dict[str, Any]] = {}
    visited: dict[str, dict[str, Any]] = {}  # <=64 compact outcomes/edges; no descriptor archive
    results: list[dict[str, dict[str, Any]]] = [{}, {}]  # <=8 descriptors per lane
    tasks: dict[asyncio.Task, tuple[str, int, dict[str, Any]]] = {}
    paths, errors, lane_requests = [], [], [0, 0]
    candidate_peak = concurrency_peak = 0
    exhausted = False
    next_lane = 0
    directory_ready = [False, False]

    def order(node):
        return (distance(target, node["payload"]["coordinate"]), node["payload"]["signing_key"]["key_id"])

    def remember_result(node, bits):
        if view == "directory" and "directory" not in node["payload"]["roles"]:
            return
        if view == "general" and "router" not in node["payload"]["roles"]:
            return
        key = node["payload"]["signing_key"]["key_id"]
        for lane in range(2):
            if bits & (1 << lane):
                if view == "directory":
                    directory_ready[lane] = True
                results[lane][key] = node
                if len(results[lane]) > 8:
                    del results[lane][max(results[lane], key=lambda k: order(results[lane][k]))]

    def introduce(node, lane, parent=None, depth=0):
        nonlocal candidate_peak
        try:
            payload = verify_node(node, now=int(table.now()))
        except MemoryError:
            return
        key = payload["signing_key"]["key_id"]
        if key == table.key_id or payload["status"] != "active":
            return
        bit = 1 << lane
        existing = candidates.get(key)
        if key in visited and hashlib.sha256(canonical_bytes(node)).hexdigest() != visited[key]["node_sha256"]:
            return
        if existing is not None and payload["revision"] != existing["node"]["payload"]["revision"]:
            # A lookup freezes its challenge target; a later lookup can use an
            # authenticated newer revision. Never mix request incarnations.
            return
        members = [c for c in candidates.values() if c["bits"] & bit]
        if existing is None or not existing["bits"] & bit:
            if len(members) >= MAX_LANE_CANDIDATES:
                removable = [c for c in members if c["state"] != "running"]
                if not removable:
                    return
                worst = max(removable, key=lambda c: order(c["node"]))
                if order(node) >= order(worst["node"]):
                    return
                worst["bits"] &= ~bit
                if not worst["bits"]:
                    candidates.pop(worst["node"]["payload"]["signing_key"]["key_id"])
        if existing is None:
            if len(candidates) >= MAX_CANDIDATES:
                return
            existing = {"node": copy.deepcopy(node), "bits": 0, "state": "pending", "parents": {}}
            candidates[key] = existing
        new_bit = not existing["bits"] & bit
        existing["bits"] |= bit
        existing["parents"][lane] = (parent, depth)
        candidate_peak = max(candidate_peak, len(candidates))
        if key in visited:
            outcome = visited[key]
            existing["state"] = outcome["state"]
            outcome["bits"] |= bit
            if outcome["state"] == "verified":
                remember_result(existing["node"], bit)
            if new_bit:
                # Retained children inherit a late introduction lane, without
                # duplicate RPCs or an unbounded saved-response descriptor graph.
                for child in tuple(outcome["children"]):
                    if child in candidates and child != key and not candidates[child]["bits"] & bit:
                        introduce(candidates[child]["node"], lane, key, depth + 1)

    if initial_lanes is None:
        seeds = table.closest(target, view, limit=16)
        if not seeds and view == "directory":
            seeds = table.closest(target, "general", limit=16)
        initial_lanes = [seeds[::2], seeds[1::2]]
    if (not isinstance(initial_lanes, (list, tuple)) or len(initial_lanes) > 2
            or any(not isinstance(lane, (list, tuple)) or len(lane) > 16 for lane in initial_lanes)):
        raise OpenRoutingError("open_invalid_routing_budget")
    for lane, nodes in enumerate(initial_lanes):
        for node in nodes:
            introduce(node, lane)

    def pending(lane, ignore_cap=False):
        if not ignore_cap and lane_requests[lane] >= MAX_LANE_REQUESTS:
            return []
        found = results[lane]
        threshold = max((order(n) for n in found.values()), default=None) if len(found) >= 8 else None
        return sorted((c for c in candidates.values() if c["bits"] & (1 << lane)
                       and c["state"] == "pending"
                       and (view != "directory" or not directory_ready[lane]
                            or "directory" in c["node"]["payload"]["roles"])
                       and (threshold is None or order(c["node"]) < threshold)),
                      key=lambda c: order(c["node"]))

    async def query(node, request):
        return await rpc(node, request, budget.deadline)

    try:
        while True:
            budget.check()
            while len(tasks) < MAX_CONCURRENT:
                ready = [pending(0), pending(1)]
                live = [i for i in range(2) if ready[i]]
                if not live:
                    break
                if not budget.remaining_requests or budget.remaining_bytes < MAX_CONTROL_BYTES * (len(tasks) + 1):
                    exhausted = True
                    break
                covered = {i for _, _, item in tasks.values() for i in range(2) if item["bits"] & (1 << i)}
                unserved = [i for i in live if i not in covered]
                lane = next((i for i in (next_lane, 1 - next_lane) if i in (unserved or live)), live[0])
                next_lane = 1 - lane
                candidate = ready[lane][0]
                node = candidate["node"]
                key = node["payload"]["signing_key"]["key_id"]
                request = sign_request(node, "find", {"target": target, "view": view})
                request_length = len(canonical_bytes(request))
                if request_length > MAX_CONTROL_BYTES:
                    raise OpenRoutingError("network_document_too_large")
                budget.charge_request_bytes(request_length)
                budget.charge_request()
                lane_requests[lane] += 1
                candidate["state"] = "running"
                task = asyncio.create_task(query(node, request))
                tasks[task] = (key, lane, candidate)
                candidate["request"] = request
                concurrency_peak = max(concurrency_peak, len(tasks))
            if not tasks:
                break
            timeout = max(0, budget.deadline - budget.clock())
            done, _ = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            if not done:
                exhausted = True
                break
            for task in sorted(done, key=lambda t: tasks[t][0]):
                key, lane, candidate = tasks.pop(task)
                parent, depth = candidate["parents"][lane]
                path = {"key_id": key, "lane": lane, "source_bits": candidate["bits"], "depth": depth,
                        "parent_key_id": parent, "view": view, "state": "failed"}
                children = []
                try:
                    reply = task.result()
                    if not isinstance(reply, RpcReply):
                        raise OpenRoutingError("open_invalid_response")
                    budget.charge_bytes(reply.wire_bytes)
                    if reply.wire_bytes > MAX_CONTROL_BYTES or reply.wire_bytes < len(canonical_bytes(reply.response)):
                        raise OpenRoutingError("open_invalid_response_size")
                    payload = verify_response(reply.response, request=candidate.pop("request"),
                                              node=candidate["node"], now=int(table.now()))
                    budget.check()
                    if "error" in payload["body"]:
                        raise OpenRoutingError(payload["body"]["error"]["code"])
                    # Exploratory lookups may refresh/fill replacements, but
                    # must not churn away proven join introductions. Direct
                    # hello probes can rotate a full replacement list.
                    table.learn_verified(candidate["node"], reply.observed_address,
                                         allow_replacement_eviction=False)
                    candidate["state"] = path["state"] = "verified"
                    remember_result(candidate["node"], candidate["bits"])
                    # Each response is bounded by the signed control codec (8).
                    for node in payload["body"]["nodes"]:
                        child = node["payload"]["signing_key"]["key_id"]
                        children.append(child)
                        for introduced_lane in range(2):
                            if candidate["bits"] & (1 << introduced_lane):
                                origin_depth = candidate["parents"].get(introduced_lane, (None, depth))[1]
                                introduce(node, introduced_lane, key, origin_depth + 1)
                except (MemoryError, OSError, TimeoutError, ValueError) as exc:
                    code = getattr(exc, "code", "open_rpc_unreachable")
                    if code == "open_lookup_budget_exhausted":
                        exhausted = True
                    candidate["state"] = "failed"
                    table.mark_failed(key)
                    errors.append({"key_id": key, "code": code})
                visited[key] = {"state": candidate["state"], "bits": candidate["bits"], "children": children,
                                "node_sha256": hashlib.sha256(canonical_bytes(candidate["node"])).hexdigest()}
                paths.append(path)
            if exhausted and (not tasks or budget.clock() >= budget.deadline or budget.bytes > budget.maximum_bytes):
                break
    except OpenRoutingError as exc:
        if exc.code != "open_lookup_budget_exhausted":
            raise
        exhausted = True
    finally:
        # Adapters must cooperate with cancellation/deadline; no hidden fanout.
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    exhausted = exhausted or any(lane_requests[lane] >= MAX_LANE_REQUESTS and pending(lane, True)
                                 for lane in range(2))
    all_results = {key: node for lane in results for key, node in lane.items()}
    selected = sorted(all_results.values(), key=order)[:8]
    return {"state": "budget_exhausted" if exhausted else ("closest_known" if selected else "unreachable"),
            "candidates": copy.deepcopy(selected), "partial": exhausted or bool(errors) or not bool(selected),
            "metrics": {"requests": budget.requests, "bytes": budget.bytes, "request_bytes": budget.request_bytes,
                        "response_bytes": budget.bytes, "candidate_peak": candidate_peak,
                        "concurrency_peak": concurrency_peak, "lane_requests": lane_requests,
                        "paths": paths, "errors": errors}}
