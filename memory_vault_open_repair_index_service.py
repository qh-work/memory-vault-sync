"""Bounded HTTP adapter for the separate ACK directory publication state."""
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_index_state import encode_entry, decode_entry

MAX_BYTES = 65536
KINDS = frozenset(('ack.index_allocate','proof.stage_intent','proof.stage_answer','proof.stage_close','ack.index_publish'))


class RepairIndexService:
    def __init__(self, state):
        self.state = state

    def initialize(self):
        self.state.initialize()

    def handle(self, kind, entry):
        budget = wire.RepairBudget(self.state.policy)
        if kind not in KINDS:
            wire._fail('repair_index_operation')
        if kind == 'ack.index_allocate':
            raw = entry if isinstance(entry,bytes) else entry['raw']
            if len(raw)>MAX_BYTES:
                wire._fail('repair_control_too_large')
            value = wire.parse_new_wire(raw,self.state.policy,budget).value
            wire.object_fields(value,{'schema_version','kind','allocation','owner','receipt_writer'})
            if value['schema_version'] != 'memory-vault-open-repair/v1' or value['kind'] != kind:
                wire._fail('repair_index_operation')
            result = self.state.allocate(decode_entry(value['allocation'],self.state.policy,budget),
                expected_owner=value['owner'],expected_receipt_writer=value['receipt_writer'])
            response = wire.build_new_wire(dict(schema_version='memory-vault-open-repair/v1',kind='ack.index_allocation',
                offer=encode_entry(result['offer']),status=encode_entry(result['status'])),self.state.policy,budget)
        else:
            if len(entry['raw'])>MAX_BYTES:
                wire._fail('repair_control_too_large')
            method = {'proof.stage_intent':'stage_intent','proof.stage_answer':'stage_answer',
                'proof.stage_close':'stage_close','ack.index_publish':'accept'}[kind]
            result = getattr(self.state,method)(entry)
            if kind == 'ack.index_publish':
                response = wire.build_new_wire(dict(schema_version='memory-vault-open-repair/v1',kind='ack.index_published',
                    index_lease=result),self.state.policy,budget)
            else:
                response = wire.parse_new_wire(result['raw'],self.state.policy,budget)
        if len(response.raw)>MAX_BYTES:
            wire._fail('repair_control_too_large')
        return response

    def handle_blob(self, frame):
        return self.state.stage_child(frame)
