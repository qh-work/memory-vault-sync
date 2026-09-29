"""Durable provisional ACK-copy uploads under an existing real reservation.

The transport caller must verify advance disclosure and destination possession.
This receiver proves uploader possession and retains exact chunks; a closed stage
is not replica custody. Full current COPY verification remains a separate commit.
"""
from contextlib import contextmanager
import json
import secrets

from memory_vault import canonical_bytes
from memory_vault_open_repair_copy_state import RepairCopyState
from memory_vault_open_repair_index_state import encode_entry, decode_entry
from memory_vault_open_repair_state import ROW_CHARGE
import memory_vault_open_repair_original as original
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire


def _dump(value):
    return canonical_bytes(encode_entry(value))


class RepairCopyUpload:
    def __init__(self,state):
        self.state,self.db=state,state.db;self.store=RepairCopyState(state)

    def initialize(self):
        self.store.initialize()
        with self.state._transaction():
            for sql in (
                'CREATE TABLE IF NOT EXISTS open_repair_copy_upload_sessions(resource_id TEXT PRIMARY KEY,intent BLOB NOT NULL,challenge BLOB NOT NULL,nonce BLOB NOT NULL,answer BLOB,handle BLOB,closed BLOB,result BLOB,expires_at INTEGER NOT NULL)',
                'CREATE TABLE IF NOT EXISTS open_repair_copy_upload_chunks(resource_id TEXT NOT NULL,child_index INTEGER NOT NULL,offset INTEGER NOT NULL,digest TEXT NOT NULL,raw BLOB NOT NULL,response BLOB NOT NULL,PRIMARY KEY(resource_id,child_index,offset))',
                'CREATE TABLE IF NOT EXISTS open_repair_copy_upload_work(id TEXT PRIMARY KEY,resource_id TEXT NOT NULL,allowance INTEGER NOT NULL,actual INTEGER,wire_bytes INTEGER NOT NULL)'):
                self.db.execute(sql)

    def _entry(self,raw,budget):
        return decode_entry(wire.parse_new_wire(bytes(raw),budget.policy,budget).value,budget.policy,budget)

    def _resource(self,rid,budget):
        s=self.state;row=s._one('SELECT * FROM open_repair_copy_resources WHERE resource_id=?',(rid,))
        if row is None:wire._fail('repair_copy_upload_missing')
        reference=wire.raw_ref(json.loads(bytes(row['request_ref'])))
        raw=bytes(row['request'])
        if (len(raw)!=reference.size or budget._hash(raw)!=reference.raw_sha256
                or budget._hash(canonical_bytes(reference.as_dict()))!=row['request_digest']):
            wire._fail('repair_storage_corrupt')
        allocation=wire.parse_new_wire(raw,budget.policy,budget).value['payload']
        intent=allocation['intent'];caps=intent['budget']
        ledger=s._one("SELECT * FROM open_capacity_reservations WHERE service='repair_copy' AND reservation_id=?",(rid,))
        if (ledger is None or ledger['digest']!=row['request_digest'] or ledger['charge_bytes']!=row['charge_bytes']
                or ledger['retain_until']!=row['retain_until'] or ledger['owner']!=row['caller']
                or ledger['operation_id']!=row['allocation_id']):wire._fail('repair_copy_ledger_missing')
        now=s._now();node=s.node['payload']
        if (not node['issued_at']<=now<node['expires_at'] or node['status']!='active'
                or now>=row['reservation_until'] or intent['target']!=s.target
                or intent['target_storage_epoch']!=node['storage_epoch']):wire._fail('repair_copy_upload_expired')
        return row,intent,caps

    def _options(self,intent,budget):
        return dict(expected_subject=intent['caller'],expected_target=self.state.target,
            target_storage_epoch=self.state.node['payload']['storage_epoch'],at=self.state._now(),
            expected_consumer='ack_copy_unbound',policy=budget.policy,budget=budget)

    @contextmanager
    def _work(self,rid,entry,input_bytes,budget):
        row,intent,caps=self._resource(rid,budget)
        parsed,ref=self.state._entry(entry,budget)
        signed=wire.object_fields(parsed.value,{'payload','proof'})
        original._verify_control_signature(signed['payload'],signed['proof'],intent['caller']['signing_key'],budget)
        attempt=secrets.token_hex(16);allowance=budget.policy.max_signature_checks
        with self.state._transaction():
            fresh,_,_=self._resource(rid,budget)
            if fresh!=row:wire._fail('repair_access_generation')
            work=self.state._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(rid,))
            count=work['requests'] if work else 0
            used=self.db.execute('SELECT coalesce(sum(coalesce(actual,allowance)),0),coalesce(sum(wire_bytes),0) FROM open_repair_copy_upload_work WHERE resource_id=?',(rid,)).fetchone()
            if (count>=min(64,caps['max_requests'],caps['max_replay_records'])
                    or used[0]+allowance>64*min(64,caps['max_requests'])
                    or used[1]+input_bytes>4*caps['max_job_bytes']):wire._fail('repair_copy_work_capacity')
            self._room(row,caps,ROW_CHARGE)
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)',(rid,count+1))
            self.db.execute('INSERT INTO open_repair_copy_upload_work VALUES(?,?,?,NULL,?)',(attempt,rid,allowance,input_bytes))
        try:yield row,intent,caps,ref,attempt
        finally:
            actual=budget.snapshot()['signature_checks']
            with self.state._transaction():
                held=self.state._one('SELECT * FROM open_repair_copy_upload_work WHERE id=?',(attempt,))
                if held is None or held['actual'] is not None or not 1<=actual<=allowance:wire._fail('repair_service_work_corrupt')
                self.db.execute('UPDATE open_repair_copy_upload_work SET actual=? WHERE id=?',(actual,attempt))

    def _room(self,row,caps,extra):
        if self.store._metadata(row)+extra>caps['max_meta_bytes']:wire._fail('repair_copy_upload_capacity')

    def _session(self,rid):
        return self.state._one('SELECT * FROM open_repair_copy_upload_sessions WHERE resource_id=?',(rid,))

    def _live(self,row,saved,budget):
        current,_,_=self._resource(row['resource_id'],budget)
        if current!=row or self._session(row['resource_id'])!=saved:wire._fail('repair_access_generation')
        if saved is not None and self.state._now()>=saved['expires_at']:wire._fail('repair_copy_upload_expired')

    def _parents(self,saved,budget):
        if saved is None:wire._fail('repair_stage_missing')
        return {name:self._entry(saved[name],budget) for name in ('intent','challenge','answer','handle','closed','result') if saved[name] is not None}

    def _output(self,rid,caps,raw,attempt):
        used=self.db.execute('SELECT coalesce(sum(wire_bytes),0) FROM open_repair_copy_upload_work WHERE resource_id=?',(rid,)).fetchone()[0]
        if used+len(raw)>4*caps['max_job_bytes']:wire._fail('repair_copy_work_capacity')
        self.db.execute('UPDATE open_repair_copy_upload_work SET wire_bytes=wire_bytes+? WHERE id=? AND resource_id=? AND actual IS NULL',(len(raw),attempt,rid))

    def intent(self,rid,entry):
        budget=wire.RepairBudget(self.state.policy)
        with self._work(rid,entry,len(entry['raw']),budget) as (row,allocation,caps,_,attempt):
            options=self._options(allocation,budget);checked=stage.verify_stage_intent(entry,**options)
            manifest=checked.payload['manifest']
            if (checked.payload['allocation_id']!=row['allocation_id'] or manifest['root_key']!=allocation['root_key']
                    or manifest['scope']!=allocation['scope'] or checked.payload['expires_at']>row['reservation_until']
                    or checked.payload['requested_bytes']>caps['max_job_bytes']
                    or checked.payload['requested_items']>caps['max_items']):wire._fail('repair_copy_upload_mismatch')
            saved=self._session(rid)
            if saved is not None:
                parents=self._parents(saved,budget)
                if parents['intent']!=entry:wire._fail('repair_stage_replay_conflict')
                stage.verify_stage_challenge(parents['challenge'],entry,**options)
                with self.state._transaction():self._live(row,saved,budget);self._output(rid,caps,parents['challenge']['raw'],attempt)
                return parents['challenge']
            challenge=stage.issue_stage_challenge(entry,signer=self.state.identity,expires_at=checked.payload['expires_at'],**options)
            values=(_dump(entry),_dump(challenge.original),challenge.nonce)
            with self.state._transaction():
                self._live(row,None,budget);self._room(row,caps,sum(map(len,values))+ROW_CHARGE)
                self.db.execute('INSERT INTO open_repair_copy_upload_sessions VALUES(?,?,?,?,NULL,NULL,NULL,NULL,?)',(rid,*values,checked.payload['expires_at']))
                self._output(rid,caps,challenge.original.raw,attempt)
            return dict(raw=challenge.original.raw,ref=challenge.original.ref.as_dict())

    def answer(self,rid,entry):
        budget=wire.RepairBudget(self.state.policy)
        with self._work(rid,entry,len(entry['raw']),budget) as (row,allocation,caps,_,attempt):
            saved=self._session(rid);parents=self._parents(saved,budget);options=self._options(allocation,budget)
            checked=stage.verify_stage_answer(parents['intent'],parents['challenge'],entry,caller_nonce=bytes(saved['nonce']),**options)
            if 'answer' in parents:
                if parents['answer']!=entry:wire._fail('repair_stage_replay_conflict')
                stage.verify_stage_handle(parents['handle'],parents['intent'],**options)
                with self.state._transaction():self._live(row,saved,budget);self._output(rid,caps,parents['handle']['raw'],attempt)
                return parents['handle']
            handle=stage.make_stage_handle(parents['intent'],parents['challenge'],entry,caller_nonce=bytes(saved['nonce']),
                signer=self.state.identity,reservation_generation=1,expires_at=checked.originals['answer'].payload['expires_at'],**options)
            values=(_dump(entry),_dump(handle))
            with self.state._transaction():
                self._live(row,saved,budget);self._room(row,caps,sum(map(len,values)))
                self.db.execute('UPDATE open_repair_copy_upload_sessions SET answer=?,handle=? WHERE resource_id=?',(*values,rid))
                self._output(rid,caps,handle.raw,attempt)
            return dict(raw=handle.raw,ref=handle.ref.as_dict())

    def child(self,rid,frame):
        budget=wire.RepairBudget(self.state.policy);entry,_=stage._decode_frame(frame,budget.policy,budget)
        with self._work(rid,entry,len(frame),budget) as (row,allocation,caps,ref,attempt):
            saved=self._session(rid);parents=self._parents(saved,budget);options=self._options(allocation,budget)
            if 'answer' not in parents or 'handle' not in parents:wire._fail('repair_stage_possession_required')
            stage.verify_stage_answer(parents['intent'],parents['challenge'],parents['answer'],caller_nonce=bytes(saved['nonce']),**options)
            checked=stage.verify_stage_child_frame(frame,parents['intent'],parents['handle'],**options)
            key=(rid,checked.child_index,checked.offset)
            old=self.state._one('SELECT * FROM open_repair_copy_upload_chunks WHERE resource_id=? AND child_index=? AND offset=?',key)
            if old is not None:
                if old['digest']!=ref.raw_sha256 or bytes(old['raw'])!=checked.chunk:wire._fail('repair_stage_replay_conflict')
                response=bytes(old['response']);stage.verify_stage_child_response_frame(response,frame,parents['intent'],parents['handle'],**options)
                with self.state._transaction():self._live(row,saved,budget);self._output(rid,caps,response,attempt)
                return response
            if 'closed' in parents:wire._fail('repair_stage_closed')
            prefix=self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM open_repair_copy_upload_chunks WHERE resource_id=? AND child_index=?',key[:2]).fetchone()[0]
            if prefix!=checked.offset:wire._fail('repair_stage_range')
            response=stage.make_stage_child_response_frame(frame,parents['intent'],parents['handle'],signer=self.state.identity,
                durable_prefix=prefix+len(checked.chunk),expires_at=checked.header.payload['expires_at'],**options)
            with self.state._transaction():
                self._live(row,saved,budget)
                actual=self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM open_repair_copy_upload_chunks WHERE resource_id=? AND child_index=?',key[:2]).fetchone()[0]
                total=self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM open_repair_copy_upload_chunks WHERE resource_id=?',(rid,)).fetchone()[0]
                if actual!=prefix:wire._fail('repair_access_generation')
                if total+len(checked.chunk)>caps['max_job_bytes']:wire._fail('repair_copy_upload_capacity')
                self._room(row,caps,len(response)+ROW_CHARGE)
                self.db.execute('INSERT INTO open_repair_copy_upload_chunks VALUES(?,?,?,?,?,?)',(*key,ref.raw_sha256,checked.chunk,response))
                self._output(rid,caps,response,attempt)
            return response

    def _children(self,rid,parents,budget):
        manifest=wire.parse_new_wire(parents['intent']['raw'],budget.policy,budget).value['payload']['manifest']
        result=[]
        for child in manifest['children']:
            parts=[];offset=0;reference=wire.raw_ref(child['ref'])
            for row in self.db.execute('SELECT offset,raw FROM open_repair_copy_upload_chunks WHERE resource_id=? AND child_index=? ORDER BY offset',(rid,child['index'])):
                if row[0]!=offset:wire._fail('repair_stage_incomplete')
                raw=bytes(row[1]);budget._bytes('input_bytes',len(raw));parts.append(raw);offset+=len(raw)
            raw=b''.join(parts)
            if len(raw)!=reference.size or budget._hash(raw)!=reference.raw_sha256:wire._fail('repair_stage_incomplete')
            result.append(dict(role=child['role'],raw=raw,ref=reference.as_dict()))
        return result

    def _stamp(self,rid):
        return tuple(tuple(r) for r in self.db.execute('SELECT child_index,offset,digest,raw,response FROM open_repair_copy_upload_chunks WHERE resource_id=? ORDER BY child_index,offset',(rid,)))

    def close(self,rid,entry):
        budget=wire.RepairBudget(self.state.policy)
        with self._work(rid,entry,len(entry['raw']),budget) as (row,allocation,caps,_,attempt):
            saved=self._session(rid);parents=self._parents(saved,budget);options=self._options(allocation,budget)
            if 'answer' not in parents or 'handle' not in parents:wire._fail('repair_stage_possession_required')
            stage.verify_stage_answer(parents['intent'],parents['challenge'],parents['answer'],caller_nonce=bytes(saved['nonce']),**options)
            checked=stage.verify_stage_close(entry,parents['intent'],parents['handle'],**options)
            stamp=self._stamp(rid);self._children(rid,parents,budget)
            if 'closed' in parents:
                if parents['closed']!=entry:wire._fail('repair_stage_replay_conflict')
                stage.verify_stage_result(parents['result'],entry,parents['intent'],parents['handle'],**options)
                with self.state._transaction():
                    self._live(row,saved,budget)
                    if self._stamp(rid)!=stamp:wire._fail('repair_access_generation')
                    self._output(rid,caps,parents['result']['raw'],attempt)
                return parents['result']
            result=stage.make_stage_result(entry,parents['intent'],parents['handle'],signer=self.state.identity,
                expires_at=checked.payload['expires_at'],**options)
            values=(_dump(entry),_dump(result))
            with self.state._transaction():
                self._live(row,saved,budget)
                if self._stamp(rid)!=stamp:wire._fail('repair_access_generation')
                self._room(row,caps,sum(map(len,values)))
                self.db.execute('UPDATE open_repair_copy_upload_sessions SET closed=?,result=? WHERE resource_id=?',(*values,rid))
                self._output(rid,caps,result.raw,attempt)
            return dict(raw=result.raw,ref=result.ref.as_dict())

    def commit_closed(self,rid,*,expected_ack_slot,expected_owner,expected_source,source_storage_epoch,expected_maintainer):
        """Local commit after staged transfer; all original/current COPY checks run."""
        budget=wire.RepairBudget(self.state.policy)
        saved=self._session(rid);parents=self._parents(saved,budget)
        if 'closed' not in parents or 'result' not in parents:wire._fail('repair_stage_incomplete')
        with self._work(rid,parents['closed'],len(parents['closed']['raw']),budget) as (row,allocation,caps,_,attempt):
            result=self._commit_closed(rid,row,allocation,parents,budget,expected_ack_slot=expected_ack_slot,
                expected_owner=expected_owner,expected_source=expected_source,source_storage_epoch=source_storage_epoch,
                expected_maintainer=expected_maintainer)
            with self.state._transaction():self._output(rid,caps,result['raw'],attempt)
            return result

    def _commit_closed(self,rid,row,allocation,parents,budget,*,expected_ack_slot,expected_owner,expected_source,
                       source_storage_epoch,expected_maintainer):
        if allocation['caller']!=expected_maintainer:wire._fail('repair_copy_upload_mismatch')
        stage.verify_stage_result(parents['result'],parents['closed'],parents['intent'],parents['handle'],**self._options(allocation,budget))
        children=self._children(rid,parents,budget);roles={}
        for child in children:roles.setdefault(child['role'],[]).append(dict(raw=child['raw'],ref=child['ref']))
        one=lambda role:roles[role][0]
        # The displayed direct originals must agree with the exact packed
        # source closure; the full verifier below authenticates that closure.
        manifest=wire.parse_new_wire(one('history.ack_unbound')['raw'],budget.policy,budget).value
        for member in manifest['roles']:
            if [e['ref'] for e in roles.get(member['role'],())]!=[member['document_ref']]:wire._fail('repair_copy_upload_mismatch')
        if (one('copy.allocation')!=self.state._saved(row,'request')
                or one('copy.offer')!=self.state._saved(row,'offer')):wire._fail('repair_copy_upload_mismatch')
        resolver=wire.LocalRawResolver(self.state.policy,budget)
        for entry in roles['history.raw_pack']:resolver.put(entry['ref']['namespace'],entry['ref']['key'],entry['raw'])
        return self.store.commit_unbound(one('history.ack_unbound'),resolver,one('ack.slot_custody'),
            one('copy.allocation'),one('copy.offer'),one('copy.assignment'),one('copy.reservation_consent'),
            one('copy.owner_disclosure'),one('copy.source_disclosure'),expected_ack_slot=expected_ack_slot,
            expected_owner=expected_owner,expected_source=expected_source,source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected_maintainer,current_statuses=roles['copy.current_status'],limit_policy=self.state.limits)
