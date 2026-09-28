"""Select a fixed owner recovery phase using existing protected source state.

Selection is only bounded routing. The selected service authenticates the
caller, verifies the complete phase closure and rechecks current permission
using the same durable work/replay ledger before returning any evidence.
"""
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_resource as resource
from memory_vault_open_repair_service import RepairBootstrapService, _fail


class RepairEmptyBootstrapService(RepairBootstrapService):
    resource_state = "empty"
    # The registry has one owner profile across phases. Its independently
    # expected phase determines the exact permitted child closure.

    def __init__(self, state):
        from memory_vault_open_repair_empty_access import RepairAckEmptyAccess
        super().__init__(state)
        self.access = RepairAckEmptyAccess(state)


class RepairOccupiedBootstrapService(RepairBootstrapService):
    resource_state = "occupied"

    def __init__(self, state):
        from memory_vault_open_repair_occupied_access import RepairAckOccupiedAccess
        super().__init__(state)
        self.access = RepairAckOccupiedAccess(state)


def service_for_packet(state, payload):
    """Resolve a phase; malformed, missing and ambiguous hints grant nothing."""
    if payload.get("consumer") == "ack_offer":
        from memory_vault_open_repair_offer_service import RepairOfferBootstrapService
        return RepairOfferBootstrapService(state)
    if payload.get("consumer") != "ack_owner":
        _fail("repair_service_unavailable")
    kind = payload.get("kind")
    if kind == "bootstrap.probe":
        closed = probe._fields(payload, probe._FIELDS["probe"])
        digest = closed["bootstrap_grant_sha256"]
        probe._shape(probe.original._digest, digest)
        subject = resource._dual_key_shape(closed["subject"])
        rows = state.db.execute("""SELECT status FROM open_repair_ack_resources WHERE owner=?
            AND json_extract(activation_inputs,'$.bootstrap.ref.raw_sha256')=? LIMIT 2""",
            (subject["signing_key"]["key_id"], digest)).fetchall()
    elif kind == "bootstrap.answer":
        closed = probe._fields(payload, probe._FIELDS["answer"])
        parent = probe._ref(closed["challenge_ref"])
        rows = state.db.execute("""SELECT r.status FROM open_repair_bootstrap_challenges c
            JOIN open_repair_ack_resources r ON c.resource_id=r.resource_id
            WHERE c.challenge_digest=? LIMIT 2""", (parent.raw_sha256,)).fetchall()
    elif kind == "bootstrap.proof_child_request":
        closed = proof._fields(payload, proof.CHILD_FIELDS - {"bootstrap_grant_sha256"})
        parent = probe._ref(closed["handle_ref"])
        rows = state.db.execute("""SELECT r.status FROM open_repair_bootstrap_handles h
            JOIN open_repair_ack_resources r ON h.resource_id=r.resource_id
            WHERE h.digest=? LIMIT 2""", (parent.raw_sha256,)).fetchall()
    else:
        _fail("repair_invalid_probe")
    if len(rows) != 1:
        _fail("repair_service_unavailable")
    if rows[0][0] == "unbound":
        return RepairBootstrapService(state)
    if rows[0][0] == "empty":
        return RepairEmptyBootstrapService(state)
    if rows[0][0] == "occupied":
        return RepairOccupiedBootstrapService(state)
    _fail("repair_service_unavailable")
