"""Receipt-writer service proof under its own original ACK offer grant."""
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_offer_access import RepairAckOfferAccess
from memory_vault_open_repair_service import RepairBootstrapService, _fail


class RepairOfferBootstrapService(RepairBootstrapService):
    resource_state = "empty"
    resource_states = ("empty",)
    consumer = "ack_offer"
    response_profile = "ack_offer_service_v1"

    def __init__(self, state):
        super().__init__(state)
        self.access = RepairAckOfferAccess(state)

    def _grant_entry(self, resource_id):
        rows = self.db.execute("""SELECT o.namespace,o.opaque_key,o.raw_sha256,o.size,o.raw
            FROM open_repair_ack_pins p JOIN open_repair_ack_objects o
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key
            WHERE p.resource_id=? AND p.role='empty:bootstrap.ack_offer' LIMIT 2""", (resource_id,)).fetchall()
        if len(rows) != 1:
            _fail("repair_service_unavailable")
        namespace, key, digest, size, raw = rows[0]
        return dict(raw=bytes(raw), ref=dict(namespace=namespace, key=key, raw_sha256=digest, size=size))

    def _context(self, resource_id, budget):
        row = self.state._row(resource_id)
        if row["status"] not in self.resource_states:
            _fail("repair_service_unavailable")
        binding = self.state._one("SELECT writer_keys FROM open_repair_ack_bindings WHERE resource_id=?", (resource_id,))
        if binding is None or type(binding["writer_keys"]) is not bytes:
            _fail("repair_service_unavailable")
        writer = wire.parse_new_wire(binding["writer_keys"], budget.policy, budget).value
        entry = self._grant_entry(resource_id)
        grant = wire.parse_new_wire(entry["raw"], budget.policy, budget).value["payload"]
        return row, grant, dict(expected_subject=writer, expected_target=self.state.target,
            target_storage_epoch=self.state.node["payload"]["storage_epoch"],
            bootstrap_grant_sha256=entry["ref"]["raw_sha256"], selector=grant["selector"],
            at=self.state._now(), policy=budget.policy, budget=budget, consumer=self.consumer)

    def _lookup_probe(self, payload):
        closed = probe._fields(payload, probe._FIELDS["probe"])
        digest = closed["bootstrap_grant_sha256"]
        probe._shape(probe.original._digest, digest)
        subject = resource._dual_key_shape(closed["subject"])
        rows = self.db.execute("""SELECT r.resource_id FROM open_repair_ack_resources r
            JOIN open_repair_ack_bindings b ON b.resource_id=r.resource_id
            JOIN open_repair_ack_pins p ON p.resource_id=r.resource_id AND p.role='empty:bootstrap.ack_offer'
            JOIN open_repair_ack_objects o ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key
            WHERE r.status='empty' AND o.raw_sha256=?
            AND json_extract(b.writer_keys,'$.signing_key.key_id')=? LIMIT 2""",
            (digest, subject["signing_key"]["key_id"])).fetchall()
        if len(rows) != 1:
            _fail("repair_service_unavailable")
        return rows[0][0]
