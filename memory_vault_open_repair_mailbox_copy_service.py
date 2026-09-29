"""Original-grant owner possession and protected discovery-root replica reads."""
from memory_vault_open_repair_copy_service import ReplicaReadService, ReplicaReadAccess
from memory_vault_open_repair_mailbox_copy_state import MailboxCopyState
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire


class MailboxRootReplicaReadService(ReplicaReadService):
    resource_state = 'replica_root'
    consumer = 'mailbox_root'
    response_profile = 'mailbox_root_service_v1'
    context_root = 'expected_root'

    def __init__(self, state):
        self.state, self.db = state, state.db
        self.store = MailboxCopyState(state)
        self.access = ReplicaReadAccess(self)

    def _prepare_read(self, *args, **options):
        return self.store.prepare_root_read(*args, **options)

    # Match the original mailbox service's transport return convention.
    def challenge(self, packet):
        return dict(raw=super().challenge(packet).raw)

    def answer(self, packet):
        return super().answer(packet).raw

    def child(self, packet, *, body=False):
        if body: wire._fail('repair_copy_scope')
        return super().child(packet)


def root_replica_service_for_packet(state, payload):
    """Select only an existing typed configuration; the service verifies access."""
    db = state.db
    if payload.get('consumer') != 'mailbox_root': return None
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='open_repair_copy_read_config'").fetchone(): return None
    kind = payload.get('kind')
    where = "json_extract(CAST(r.raw AS TEXT),'$.source_state')='replica_root'"
    if kind == 'bootstrap.probe':
        closed = probe._fields(payload, probe._FIELDS['probe'])
        subject = resource._dual_key_shape(closed['subject']); digest = closed['bootstrap_grant_sha256']
        probe._shape(probe.original._digest, digest)
        rows = db.execute('SELECT r.resource_id FROM open_repair_copy_read_config r WHERE ' + where + ' AND r.owner=? AND r.grant_sha256=? LIMIT 2',
            (subject['signing_key']['key_id'], digest)).fetchall()
    elif kind in ('bootstrap.answer', 'bootstrap.proof_child_request'):
        challenge = kind == 'bootstrap.answer'
        closed = probe._fields(payload, probe._FIELDS['answer']) if challenge else proof._fields(payload, proof.CHILD_FIELDS - {'bootstrap_grant_sha256'})
        parent = probe._ref(closed['challenge_ref' if challenge else 'handle_ref'])
        table = 'open_repair_bootstrap_challenges' if challenge else 'open_repair_bootstrap_handles'
        if not db.execute('SELECT 1 FROM sqlite_master WHERE name=?', (table,)).fetchone(): return None
        field = 'challenge_digest' if challenge else 'digest'
        rows = db.execute('SELECT r.resource_id FROM ' + table + ' c JOIN open_repair_copy_read_config r ON c.resource_id=r.resource_id WHERE '
            + where + ' AND c.' + field + '=? LIMIT 2', (parent.raw_sha256,)).fetchall()
    else: return None
    if not rows: return None
    if len(rows) != 1: wire._fail('repair_service_unavailable')
    service = MailboxRootReplicaReadService(state); service.initialize()
    return service
