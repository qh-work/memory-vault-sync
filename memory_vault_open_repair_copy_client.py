"""Explicit unbound replica upload to an already reserved destination.

The maintainer's private preparation database retains outgoing requests before
HTTP. Target possession precedes disclosure; custody is independently verified.
This client neither allocates remote capacity nor grants owner READ access.
"""
import secrets
import threading
import time
from types import SimpleNamespace

import memory_vault_open_blob as blob
import memory_vault_open_repair_copy_authority as authority
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_prepare import AckCopyPreparation
from memory_vault_open_repair_copy_upload import make_copy_commit_request
from memory_vault_open_repair_index_client import AckIndexPublicationClient, _node, _raw_entry
from memory_vault_open_repair_index_state import decode_entry
from memory_vault_open_transport import OpenHTTPTransport, endpoint


def _entry(item):
    return dict(raw=item.raw,ref=item.ref.as_dict())


class AckCopyUploadClient:
    # These helpers use only identity, target keys/epoch, the finite deadline and
    # this client's own durable _step. No index allocation/publication is used.
    _provider_rpc=AckIndexPublicationClient._provider_rpc
    _request_provider=AckIndexPublicationClient._request_provider
    _response_provider=AckIndexPublicationClient._response_provider
    _target=AckIndexPublicationClient._target
    _prove_directory=AckIndexPublicationClient._prove_directory

    def __init__(self,journal,*,encryption_identity,transport=None,allow_loopback=False):
        if type(journal) is not AckCopyPreparation or encryption_identity.public_descriptor()!=journal.keys['encryption_key']:
            wire._fail('repair_invalid_context')
        self.journal,self.db,self.policy=journal,journal.db,journal.policy
        self.identity,self.encryption=journal.identity,encryption_identity
        self.state=SimpleNamespace(target=journal.keys)
        self.transport=transport or OpenHTTPTransport(allow_loopback=allow_loopback)
        self.own_transport=transport is None;self.allow_loopback=allow_loopback;self.lock=threading.Lock()
        journal.initialize()
        with journal._upload_transaction():
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_client_sessions(job_id TEXT PRIMARY KEY,raw BLOB NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_client_steps(job_id TEXT NOT NULL,step INTEGER NOT NULL,mode TEXT NOT NULL,request BLOB NOT NULL,response BLOB,PRIMARY KEY(job_id,step))')
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_client_work(id TEXT PRIMARY KEY,job_id TEXT NOT NULL,wire_bytes INTEGER NOT NULL,signature_checks INTEGER,network INTEGER NOT NULL)')

    def close(self):
        if self.own_transport:self.transport.close()

    def _budget(self):return wire.RepairBudget(self.policy)
    def _now(self):return int(time.time())

    def _guard(self):
        if self._now()>=self.until or time.monotonic()>=self.deadline:wire._fail('repair_access_expired')
        blocked=self.db.execute("SELECT reason FROM ack_copy_prepare_blocked WHERE root_digest IN (?, '*')",(self.root_digest,)).fetchone()
        if blocked:wire._fail(blocked[0])
        stamp=tuple((bytes(r[0]),bytes(r[1])) for r in self.db.execute('SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? ORDER BY raw_digest',(self.root_digest,)))
        if stamp!=self.status_stamp:wire._fail('repair_status_changed')

    def _expected(self,budget):
        return dict(expected_subject=self.journal.keys,expected_target=self.plan.intent['target'],
            target_storage_epoch=self.plan.intent['target_storage_epoch'],expected_consumer='ack_copy_unbound',
            at=self._now(),policy=self.policy,budget=budget)

    def _step(self,number,build,check_request,verify,*,mode='repair',response_allowance=8192):
        if mode not in ('provider','repair','blob') or not 0<=number<68:wire._fail('repair_invalid_context')
        budget=self._budget();ticket=secrets.token_hex(16);sent=False;response=None;request=None
        with self.journal._upload_transaction():
            self._guard()
            count,checks=self.db.execute('SELECT count(*),coalesce(sum(coalesce(signature_checks,64)),0) FROM ack_copy_client_work WHERE job_id=?',(self.job,)).fetchone()
            if count>=256 or checks+64>16384:wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT INTO ack_copy_client_work VALUES(?,?,0,NULL,0)',(ticket,self.job))
            self._metadata()
        try:
            saved=self.db.execute('SELECT mode,request,response FROM ack_copy_client_steps WHERE job_id=? AND step=?',(self.job,number)).fetchone()
            if saved is not None and saved[0]!=mode:wire._fail('repair_copy_upload_conflict')
            request=bytes(saved[1]) if saved is not None else build(budget)
            check_request(request,budget)
            if saved is not None and saved[2] is not None:
                response=bytes(saved[2]);result=verify(response,request,budget)
                self._guard();return request,response,result
            with self.journal._upload_transaction():
                self._guard()
                if saved is None:
                    self.db.execute('INSERT INTO ack_copy_client_steps VALUES(?,?,?,?,NULL)',(self.job,number,mode,request))
                count,used=self.db.execute('SELECT coalesce(sum(network),0),coalesce(sum(wire_bytes),0) FROM ack_copy_client_work WHERE job_id=?',(self.job,)).fetchone()
                reserve=len(request)+response_allowance
                if count>=min(68,self.plan.intent['budget']['max_requests']) or used+reserve>4*self.plan.intent['budget']['max_job_bytes']:
                    wire._fail('repair_copy_work_capacity')
                self.db.execute('UPDATE ack_copy_client_work SET network=1,wire_bytes=? WHERE id=?',(reserve,ticket))
                self._metadata()
            sent=True
            if mode=='provider':
                reply=self.transport.request(self.base,wire.parse_new_wire(request,self.policy,budget).value,deadline=self.deadline)
                response=wire.build_new_wire(reply.response,self.policy,budget).raw
                if reply.wire_bytes!=len(response):wire._fail('repair_invalid_response')
            elif mode=='blob':
                header,chunk=stage._decode_frame(request,self.policy,budget)
                reply=self.transport.request_blob(self.base,wire.parse_new_wire(header['raw'],self.policy,budget).value,chunk,deadline=self.deadline)
                response=blob.encode_blob_frame(reply.header,reply.chunk)
                if reply.wire_bytes!=len(response):wire._fail('repair_invalid_response')
            else:response=self.transport.request_repair(self.base,request,deadline=self.deadline)
            if type(response) is not bytes or not 0<len(response)<=response_allowance:wire._fail('repair_invalid_response')
            result=verify(response,request,budget)
            with self.journal._upload_transaction():
                self._guard()
                held=self.db.execute('SELECT response FROM ack_copy_client_steps WHERE job_id=? AND step=?',(self.job,number)).fetchone()
                if held[0] is not None and bytes(held[0])!=response:wire._fail('repair_copy_upload_conflict')
                self.db.execute('UPDATE ack_copy_client_steps SET response=? WHERE job_id=? AND step=?',(response,self.job,number))
                self._metadata()
            return request,response,result
        finally:
            with self.journal._upload_transaction():
                self.db.execute('UPDATE ack_copy_client_work SET signature_checks=? WHERE id=?',(budget.snapshot()['signature_checks'],ticket))
                # An interrupted response keeps its original allowance.
                if sent and type(response) is bytes and len(response)<=response_allowance:
                    self.db.execute('UPDATE ack_copy_client_work SET wire_bytes=? WHERE id=?',(len(request)+len(response),ticket))

    def _metadata(self):
        size=self.db.execute('SELECT coalesce(sum(length(request)+coalesce(length(response),0)+128),0) FROM ack_copy_client_steps WHERE job_id=?',(self.job,)).fetchone()[0]
        size+=self.db.execute('SELECT count(*)*128 FROM ack_copy_client_work WHERE job_id=?',(self.job,)).fetchone()[0]
        size+=self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM ack_copy_client_sessions WHERE job_id=?',(self.job,)).fetchone()[0]
        if size>self.plan.intent['budget']['max_meta_bytes']:wire._fail('repair_copy_journal_capacity')

    def upload(self,base,*args,target_node_entry,timeout=60,**context):
        """Use the same originals/arguments as prepare_upload_unbound, except at.

        Pass a fresh bounded resolver on each invocation. A caller still supplies
        current authenticated statuses; this method does not invent freshness.
        """
        if type(timeout) not in (int,float) or not 0<timeout<=60:wire._fail('repair_invalid_context')
        with self.lock:
            self.deadline=time.monotonic()+timeout
            budget=self._budget()
            self.context=wire.build_new_wire({k:context[k] for k in ('expected_ack_slot','expected_owner','expected_source','source_storage_epoch','expected_target','target_storage_epoch','limit_policy')},self.policy,budget).value
            prepared=self.journal.prepare_upload_unbound(*args,at=self._now(),**dict(context,**self.context))
            allocation_entry=next(e['entry'] for e in prepared['children'] if e['role']=='copy.allocation')
            allocation=wire.parse_new_wire(allocation_entry['raw'],self.policy,budget).value['payload']
            self.plan=SimpleNamespace(intent=allocation['intent']);self.job=self.plan.intent['job_id']
            self.until=prepared['expires_at'];self.children=prepared['children'];self.intent=prepared['intent']
            self.status_stamp=prepared['status_stamp']
            self._open_network(base,target_node_entry,budget)
            result,step=self._stage()
            return self._commit(result,step)

    def _open_network(self,base,target_node_entry,budget):
        node,node_entry=_node(target_node_entry,self.plan.intent['target'],self.plan.intent['target_storage_epoch'],self._now(),self.policy,budget)
        if endpoint(base,allow_loopback=self.allow_loopback)!=endpoint(node.payload['base_url'],allow_loopback=self.allow_loopback):wire._fail('repair_provider_proof_mismatch')
        self.base=node.payload['base_url']
        self.root_digest=budget._hash(wire._canonical(self.plan.intent['root_key'],budget))
        binding=dict(base=self.base,target=self.plan.intent['target'],epoch=self.plan.intent['target_storage_epoch'],intent_ref=self.intent['ref'],until=self.until)
        with self.journal._upload_transaction():
            self._guard()
            held=self.db.execute('SELECT raw FROM ack_copy_client_sessions WHERE job_id=?',(self.job,)).fetchone()
            if held is None:
                raw=wire.build_new_wire(dict(binding=binding,nonce=secrets.token_hex(32)),self.policy,budget).raw
                self.db.execute('INSERT INTO ack_copy_client_sessions VALUES(?,?)',(self.job,raw))
            else:raw=bytes(held[0])
            session=wire.parse_new_wire(raw,self.policy,budget).value
            if session['binding']!=binding:wire._fail('repair_copy_upload_conflict')
        nonce=bytes.fromhex(session['nonce'])
        if len(nonce)!=32:wire._fail('repair_storage_corrupt')
        self._prove_directory(nonce)

    def reserve(self,base,manifest_entry,resolver,custody_entry,consent_entry,intent,*,target_node_entry,timeout=60,**context):
        """Obtain a remote offer after original reservation-disclosure checks.

        The result is capacity only. Call assign_unbound with fresh original
        authority, then obtain owner/source upload disclosures before upload.
        """
        import memory_vault_open_repair_index as index
        import memory_vault_open_repair_resource as resource
        import memory_vault_open_repair_history as history
        from memory_vault_open_repair_index_state import encode_entry
        if type(timeout) not in (int,float) or not 0<timeout<=60:wire._fail('repair_invalid_context')
        with self.lock:
            self.deadline=time.monotonic()+timeout
            prepared=self.journal.prepare_reservation_unbound(manifest_entry,resolver,custody_entry,consent_entry,intent,
                at=self._now(),budget=resolver.budget,**context)
            self.intent=allocation=prepared['allocation'];self.status_stamp=prepared['status_stamp']
            budget=self._budget();p=wire.parse_new_wire(allocation['raw'],self.policy,budget).value['payload']
            self.plan=SimpleNamespace(intent=p['intent']);self.until=p['expires_at']
            # NUL is forbidden in public opaque job IDs, so this private phase
            # namespace cannot collide with an upload's original job ID.
            self.job='\0reservation:'+self.plan.intent['job_id']
            self._open_network(base,target_node_entry,budget)
            request=wire.build_new_wire(dict(schema_version=resource.SCHEMA,kind='ack.copy_allocate',
                caller=self.journal.keys,allocation=encode_entry(allocation)),self.policy,budget).raw
            def check(raw,b):
                if raw!=request:wire._fail('repair_copy_upload_conflict')
            def verify(raw,q,b):
                value=wire.parse_new_wire(raw,self.policy,b).value
                wire.object_fields(value,{'schema_version','kind','offer'})
                if value['schema_version']!=resource.SCHEMA or value['kind']!='ack.copy_allocation':wire._fail('repair_invalid_response')
                offered=decode_entry(value['offer'],self.policy,b)
                offer=index._signed(offered,self.plan.intent['target']['signing_key'],'resource.offer',index.OFFER_FIELDS,self.policy,b)
                o=offer.payload;i=self.plan.intent
                resource._budget(o['budget']);resource._windows(o['windows']);history._resource(o['resource']);resource._opaque(o['offer_id'])
                if (o['intent']!=i or o['intent_sha256']!=p['intent_sha256'] or o['allocation_request_ref']!=allocation['ref']
                        or o['target_encryption_key']!=i['target']['encryption_key']
                        or o['resource']['node_key_id']!=i['target']['signing_key']['key_id'] or o['resource']['storage_epoch']!=i['target_storage_epoch']
                        or o['budget']!=i['budget'] or o['windows']!=i['windows'] or wire.u53(o['reservation_generation'],1)!=1
                        or not p['issued_at']<=wire.u53(o['issued_at'])<=self._now()<wire.u53(o['reservation_until'])<=p['expires_at']):
                    wire._fail('repair_copy_offer_mismatch')
                return dict(state='capacity_reserved',allocation=allocation,offer=offered)
            return self._step(2,lambda b:request,check,verify,response_allowance=65536)[2]

    def _stage(self):
        intent=self.intent
        def check_intent(raw,b):
            if raw!=intent['raw']:wire._fail('repair_stage_mismatch')
            return stage.verify_stage_intent(intent,**self._expected(b))
        _,_,challenge=self._step(2,lambda b:intent['raw'],check_intent,
            lambda raw,q,b:stage.verify_stage_challenge(_raw_entry(raw,b),intent,**self._expected(b)),response_allowance=16384)
        def answer(b):return stage.solve_stage_challenge(intent,_entry(challenge),signer=self.identity,encryption_identity=self.encryption,expires_at=self.until,**self._expected(b)).raw
        def check_answer(raw,b):
            nonce=probe._decrypt(challenge.payload['jwe'],self.encryption,self.journal.keys['encryption_key'],probe._aad(challenge.payload,'jwe',b),b)
            return stage.verify_stage_answer(intent,_entry(challenge),_raw_entry(raw,b),caller_nonce=nonce,**self._expected(b))
        _,_,handle=self._step(3,answer,check_answer,lambda raw,q,b:stage.verify_stage_handle(_raw_entry(raw,b),intent,**self._expected(b)))
        step=4
        for i,row in enumerate(self.children):
            child=row['entry']
            for offset in range(0,len(child['raw']),stage.STAGE_CHUNK_BYTES):
                chunk=child['raw'][offset:offset+stage.STAGE_CHUNK_BYTES]
                def build(b):return stage.make_stage_child_frame(intent,_entry(handle),signer=self.identity,child_index=i,offset=offset,chunk=chunk,expires_at=self.until,**self._expected(b))
                def check(raw,b):
                    item=stage.verify_stage_child_frame(raw,intent,_entry(handle),**self._expected(b))
                    if item.child_index!=i or item.offset!=offset or item.chunk!=chunk or item.child_ref!=wire.raw_ref(child['ref']):wire._fail('repair_stage_mismatch')
                self._step(step,build,check,lambda raw,q,b:stage.verify_stage_child_response_frame(raw,q,intent,_entry(handle),**self._expected(b)),mode='blob')
                step+=1
        _,_,result=self._step(step,lambda b:stage.make_stage_close(intent,_entry(handle),signer=self.identity,expires_at=self.until,**self._expected(b)).raw,
            lambda raw,b:stage.verify_stage_close(_raw_entry(raw,b),intent,_entry(handle),**self._expected(b)),
            lambda raw,q,b:stage.verify_stage_result(_raw_entry(raw,b),_raw_entry(q,b),intent,_entry(handle),**self._expected(b)))
        return result,step+1

    def _commit(self,result,step):
        context=self.context
        offer=next(e['entry'] for e in self.children if e['role']=='copy.offer')
        rid=wire.parse_new_wire(offer['raw'],self.policy,self._budget()).value['payload']['resource']['resource_id']
        def build(b):return make_copy_commit_request(self.identity,intent_entry=self.intent,result_entry=_entry(result),resource_id=rid,
            expected_owner=context['expected_owner'],expected_source=context['expected_source'],source_storage_epoch=context['source_storage_epoch'],expires_at=self.until,**self._expected(b)).raw
        def check(raw,b):
            from memory_vault_open_repair_copy_upload import COMMIT_FIELDS
            import memory_vault_open_repair_index as index
            item=index._signed(_raw_entry(raw,b),self.journal.keys['signing_key'],'ack.copy_commit',COMMIT_FIELDS,self.policy,b)
            stage._window(item.payload,self._now())
            p=item.payload
            wanted=dict(resource_id=rid,intent_ref=self.intent['ref'],stage_result_ref=result.ref.as_dict(),owner=context['expected_owner'],source=context['expected_source'],source_storage_epoch=context['source_storage_epoch'],subject=probe._dual(self.journal.keys),target_node_key_id=self.plan.intent['target']['signing_key']['key_id'],target_storage_epoch=self.plan.intent['target_storage_epoch'])
            if any(p[k]!=v for k,v in wanted.items()) or p['expires_at']>self.until or p['issued_at']<result.payload['closed_at']:wire._fail('repair_stage_mismatch')
        def verify(raw,q,b):
            value=wire.parse_new_wire(raw,self.policy,b).value;wire.object_fields(value,{'schema_version','kind','manifest','custody'})
            if value['schema_version']!=stage.SCHEMA or value['kind']!='ack.copy_committed':wire._fail('repair_invalid_response')
            manifest,custody=(decode_entry(value[k],self.policy,b) for k in ('manifest','custody'))
            resolver=wire.LocalRawResolver(self.policy,b)
            for row in self.children:
                e=row['entry'];resolver.put(e['ref']['namespace'],e['ref']['key'],e['raw'])
            checked=authority.verify_unbound_replica_event(manifest,resolver,custody,expected_maintainer=self.journal.keys,
                **context,policy=self.policy,budget=b)
            if checked['custody'].payload['resource']['resource_id']!=rid:wire._fail('repair_ref_mismatch')
            return dict(state='replica_committed',manifest=manifest,custody=custody)
        return self._step(step,build,check,verify,response_allowance=131072)[2]
