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


class MailboxFeedReplicaReadService(MailboxRootReplicaReadService):
    resource_state = 'replica_feed'
    consumer = 'mailbox_feed'
    response_profile = 'mailbox_feed_service_v1'
    context_root = 'expected_slot'
    bound_context = frozenset({'expected_sender'})

    def __init__(self, state):
        from memory_vault_open_repair_mailbox_feed_copy_state import MailboxFeedCopyState
        self.state, self.db = state, state.db
        self.store = MailboxFeedCopyState(state)
        self.access = ReplicaReadAccess(self)

    def _prepare_read(self, *args, **options):
        return self.store.prepare_feed_read(*args, **options)


class MailboxMessageReplicaReadService(MailboxFeedReplicaReadService):
    resource_state = 'replica_message'
    bound_context = frozenset({'expected_sender', 'expected_envelope_ref'})
    supports_mailbox_body = True

    def __init__(self, state):
        from memory_vault_open_repair_mailbox_message_copy_state import MailboxMessageCopyState
        self.state, self.db = state, state.db
        self.store = MailboxMessageCopyState(state)
        self.access = ReplicaReadAccess(self)

    def _prepare_read(self, *args, **options):
        return self.store.prepare_message_read(*args, **options)

    def child(self, packet, *, body=False):
        return self._run(packet,'body' if body else 'child')

    def _body_original(self, resource_id, core_raw, request, budget):
        cfg=self._configuration(resource_id,budget)
        reference=wire.raw_ref(cfg['context']['expected_envelope_ref'])
        core=wire.parse_new_wire(core_raw,budget.policy,budget).value['payload']
        if (core['kind']!='admission.core' or core['slot_key']!=cfg['context']['expected_slot']
                or core['envelope_ref']!=reference.as_dict() or request['envelope_ref']!=reference.as_dict()):
            wire._fail('repair_copy_scope')
        return self.store.read_local_original(resource_id,reference.as_dict(),_budget=budget)


def root_replica_service_for_packet(state, payload):
    """Select only an existing typed configuration; the service verifies access."""
    db = state.db
    consumer = payload.get('consumer')
    if consumer not in ('mailbox_root', 'mailbox_feed'): return None
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='open_repair_copy_read_config'").fetchone(): return None
    kind = payload.get('kind')
    variant = 'replica_root' if consumer == 'mailbox_root' else 'replica_feed'
    where = "json_extract(CAST(r.raw AS TEXT),'$.source_state')" + (" IN ('replica_feed','replica_message')" if consumer=='mailbox_feed' else "='replica_root'")
    if kind == 'bootstrap.probe':
        closed = probe._fields(payload, probe._FIELDS['probe'])
        subject = resource._dual_key_shape(closed['subject']); digest = closed['bootstrap_grant_sha256']
        probe._shape(probe.original._digest, digest)
        rows = db.execute('SELECT r.resource_id FROM open_repair_copy_read_config r WHERE ' + where + ' AND r.owner=? AND r.grant_sha256=? LIMIT 2',
            (subject['signing_key']['key_id'], digest)).fetchall()
    elif kind in ('bootstrap.answer', 'bootstrap.proof_child_request', 'mailbox.body_read'):
        challenge = kind == 'bootstrap.answer'
        closed = probe._fields(payload, probe._FIELDS['answer']) if challenge else proof._fields(payload,
            (proof.CHILD_FIELDS - {'bootstrap_grant_sha256'}) | ({'envelope_ref'} if kind=='mailbox.body_read' else set()))
        parent = probe._ref(closed['challenge_ref' if challenge else 'handle_ref'])
        table = 'open_repair_bootstrap_challenges' if challenge else 'open_repair_bootstrap_handles'
        if not db.execute('SELECT 1 FROM sqlite_master WHERE name=?', (table,)).fetchone(): return None
        field = 'challenge_digest' if challenge else 'digest'
        rows = db.execute('SELECT r.resource_id FROM ' + table + ' c JOIN open_repair_copy_read_config r ON c.resource_id=r.resource_id WHERE '
            + where + ' AND c.' + field + '=? LIMIT 2', (parent.raw_sha256,)).fetchall()
    else: return None
    if not rows: return None
    if len(rows) != 1: wire._fail('repair_service_unavailable')
    saved=db.execute('SELECT raw FROM open_repair_copy_read_config WHERE resource_id=?',(rows[0][0],)).fetchone()
    import json
    variant=json.loads(bytes(saved[0]))['source_state']
    service = {'replica_root':MailboxRootReplicaReadService,'replica_feed':MailboxFeedReplicaReadService,
        'replica_message':MailboxMessageReplicaReadService}[variant](state); service.initialize()
    return service
