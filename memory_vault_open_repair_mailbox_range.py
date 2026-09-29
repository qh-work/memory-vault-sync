"""Bounded, slot-bound prefix commitments for the mailbox's 65536 entries.

These hashes are not authorization. A consumer must authenticate its checkpoint
and exact slot before using the commitment to verify stored message metadata.
"""
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_wire as wire

DEPTH = 16
CAPACITY = 1 << DEPTH
_SLOT = b"memory-vault-mailbox-slot/v1\x00"
_EMPTY = b"memory-vault-mailbox-empty/v1\x00"
_LEAF = b"memory-vault-mailbox-leaf/v1\x00"
_NODE = b"memory-vault-mailbox-node/v1\x00"


def _fail():
    wire._fail("repair_mailbox_range_mismatch")


def _binding(slot, policy, budget):
    slot = wire.build_new_wire(slot, policy, budget).value
    wire.object_fields(slot, {"root_key", "slot_id", "writer", "writer_storage_epoch"})
    history._slot(slot, slot["root_key"])
    return budget._hash(_SLOT + wire._canonical(slot, budget))


def _node(binding, height, left, right, budget):
    return budget._hash(_NODE + bytes.fromhex(binding) + bytes([height])
                        + bytes.fromhex(left) + bytes.fromhex(right))


def _empty(binding, budget):
    levels = [budget._hash(_EMPTY + bytes.fromhex(binding))]
    for height in range(1, DEPTH + 1):
        levels.append(_node(binding, height, levels[-1], levels[-1], budget))
    return levels


def _leaf(binding, sequence, sealed_core_sha256, budget):
    original._digest(sealed_core_sha256)
    return budget._hash(_LEAF + bytes.fromhex(binding) + sequence.to_bytes(4, "big")
                        + bytes.fromhex(sealed_core_sha256))


def _root(binding, count, frontier, empty, budget):
    if count == CAPACITY:
        return frontier[DEPTH]
    root = empty[0]
    for height in range(DEPTH):
        root = (_node(binding, height + 1, frontier[height], root, budget)
                if count & (1 << height) else _node(binding, height + 1, root, empty[height], budget))
    return root


def _state(value, slot, policy, budget):
    held = wire.build_new_wire(value, policy, budget).value
    wire.object_fields(held, {"slot_binding", "count", "leaf_root", "frontier"})
    count = wire.u53(held["count"])
    if count > CAPACITY or held["slot_binding"] != _binding(slot, policy, budget):
        _fail()
    if type(held["frontier"]) is not wire._DraftList or len(held["frontier"]) != DEPTH + 1:
        _fail()
    for height, value in enumerate(held["frontier"]):
        if count & (1 << height):
            original._digest(value)
        elif value is not None:
            _fail()
    empty = _empty(held["slot_binding"], budget)
    if held["leaf_root"] != _root(held["slot_binding"], count, held["frontier"], empty, budget):
        _fail()
    return held, empty


def empty_state(slot, *, policy, budget):
    wire._context(policy, budget)
    with budget._lock:
        binding = _binding(slot, policy, budget)
        return wire.build_new_wire(dict(slot_binding=binding, count=0,
            leaf_root=_empty(binding, budget)[DEPTH], frontier=[None]*(DEPTH+1)), policy, budget).value


def append(state, sealed_core_sha256, *, expected_slot, policy, budget):
    """Extend one accepted prefix, carrying at most sixteen frontier nodes."""
    wire._context(policy, budget)
    with budget._lock:
        held, empty = _state(state, expected_slot, policy, budget)
        count, binding = held["count"], held["slot_binding"]
        if count == CAPACITY:
            wire._fail("repair_mailbox_full")
        frontier = list(held["frontier"])
        node = _leaf(binding, count, sealed_core_sha256, budget)
        height = 0
        while count & (1 << height):
            node = _node(binding, height + 1, frontier[height], node, budget)
            frontier[height] = None
            height += 1
        frontier[height] = node
        count += 1
        return wire.build_new_wire(dict(slot_binding=binding, count=count,
            leaf_root=_root(binding, count, frontier, empty, budget), frontier=frontier), policy, budget).value


def verify_inclusion(state, sequence, sealed_core_sha256, siblings, *, expected_slot, policy, budget):
    """Check one complete depth-16 path against an authenticated caller state."""
    wire._context(policy, budget)
    with budget._lock:
        held, _ = _state(state, expected_slot, policy, budget)
        path = wire.build_new_wire(siblings, policy, budget).value
        sequence = wire.u53(sequence)
        if sequence >= held["count"] or type(path) is not wire._DraftList or len(path) != DEPTH:
            _fail()
        node = _leaf(held["slot_binding"], sequence, sealed_core_sha256, budget)
        for height, sibling in enumerate(path):
            original._digest(sibling)
            node = (_node(held["slot_binding"], height+1, sibling, node, budget)
                    if sequence & (1 << height) else _node(held["slot_binding"], height+1, node, sibling, budget))
        if node != held["leaf_root"]:
            _fail()
        return True
