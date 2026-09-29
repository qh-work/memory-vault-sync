"""Local A/R provisioning before encrypting one never-uploaded delivery.

The operator supplies its existing sender client and source node. B's public
keys come from the real approved outbox session; no recipient key is loaded.
This adapter uses existing source operations, not a new network protocol.
"""
import base64
import hashlib
import json
import secrets

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document
from memory_vault_open_contact import verify_decision
from memory_vault_open_delivery import envelope_ref, verify_envelope
from memory_vault_open_delivery_client import OpenDeliveryClient, _DeliveryBudget, MAX_SESSION_BYTES
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
from memory_vault_open_repair_empty_state import RepairAckEmptyState
from memory_vault_open_repair_access import RepairAckAccess
import memory_vault_open_repair_history as history
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
from memory_vault_open_repair_state import RepairAckState, RECEIPT_WORKFLOW_LIMITS, INDEX_WORKFLOW_LIMITS
import memory_vault_open_repair_wire as wire

PROFILES = {'receipt':RECEIPT_WORKFLOW_LIMITS,'receipt-index':INDEX_WORKFLOW_LIMITS}
MAX_RECORDS = 16
MAX_RECORD_BYTES = 1048576
SAVED_REQUEST_SCHEMA = 'memory-vault-open-saved-ack-request/v1'
PLAN_VERSION = 2
COPY_PLAN_VERSION = 3


def _fail(code):
    wire._fail(code)


def _digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _copy_maintainer(value,profile,policy):
    """Explicit optional owner opt-in, never inferred from source selection."""
    if value is None:return None
    if profile!='receipt-index':_fail('repair_copy_profile_required')
    budget=wire.RepairBudget(policy)
    frozen=wire.build_new_wire(value,policy,budget)
    resource._dual_key(frozen.value,budget)
    return json.loads(frozen.raw)


def _entry(raw):
    digest = hashlib.sha256(raw).hexdigest()
    return dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))


def _encoded(value):
    if type(value) is bytes:
        return {'_provision_bytes':base64.urlsafe_b64encode(value).decode('ascii')}
    if isinstance(value,dict):
        return {key:_encoded(item) for key,item in value.items()}
    if isinstance(value,(list,tuple)):
        return [_encoded(item) for item in value]
    return value


def _decoded(value):
    if type(value) is dict and set(value)=={'_provision_bytes'}:
        try:
            return base64.b64decode(value['_provision_bytes'],altchars=b'-_',validate=True)
        except (ValueError,TypeError):
            _fail('repair_provision_corrupt')
    if type(value) is dict:
        return {key:_decoded(item) for key,item in value.items()}
    if type(value) is list:
        return [_decoded(item) for item in value]
    return value


def encode_original(entry):
    return dict(ref=entry['ref'],raw_base64url=base64.urlsafe_b64encode(entry['raw']).rstrip(b'=').decode('ascii'))


def decode_saved_request(bundle):
    """Decode the recipient artifact for the existing publish_saved_ack API."""
    if (type(bundle) is not dict or set(bundle)!={'schema_version','base_url','repair_profile','request'}
            or bundle['schema_version']!=SAVED_REQUEST_SCHEMA or bundle['repair_profile'] not in PROFILES):
        _fail('repair_invalid_request_bundle')
    from memory_vault_open_repair_admin import _entry as decode
    from memory_vault_open_repair_receipt import REQUEST_FIELDS
    request=bundle['request']
    if type(request) is not dict or set(request)!=REQUEST_FIELDS:
        _fail('repair_invalid_request_bundle')
    return {name:([decode(item) for item in value] if name=='current_statuses' else
        decode(value) if name.endswith('_entry') else value) for name,value in request.items()}


class AckSourceProvisioner:
    def __init__(self, delivery_client, source_state):
        if type(delivery_client) is not OpenDeliveryClient or type(source_state) is not RepairAckState:
            _fail('repair_invalid_context')
        self.delivery,self.source=delivery_client,source_state
        self.owner=dict(signing_key=delivery_client.identity.public_descriptor(),encryption_key=delivery_client.encryption.public_descriptor())
        self.policy=source_state.policy
        source_state.initialize()
        self.empty=RepairAckEmptyState(source_state);self.empty.initialize()
        with self.delivery.participant.state.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS open_repair_source_provision(
                request_id TEXT PRIMARY KEY,plan BLOB NOT NULL,steps BLOB NOT NULL)''')

    @staticmethod
    def _unsent(row):
        if row is None:
            _fail('repair_provision_outbox_missing')
        if any(row[name] is not None for name in ('intent','result','acknowledgement')) or row['upload_offset']:
            _fail('repair_provision_already_sent')

    def _load(self, request_id):
        with self.delivery.participant.state.db() as db:
            row=db.execute('SELECT plan,steps FROM open_repair_source_provision WHERE request_id=?',(request_id,)).fetchone()
        if row is None:return None
        if len(row[0])+len(row[1])>MAX_RECORD_BYTES:_fail('repair_provision_capacity')
        return _decoded(json.loads(bytes(row[0]))),_decoded(json.loads(bytes(row[1])))

    def _step(self, name, build):
        held=self._load(self.plan['request_id'])
        if held is None or held[0]!=self.plan:_fail('repair_provision_conflict')
        if name in held[1]:return held[1][name]
        value=build()
        with self.delivery.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT plan,steps FROM open_repair_source_provision WHERE request_id=?',(self.plan['request_id'],)).fetchone()
            if row is None or _decoded(json.loads(bytes(row[0])))!=self.plan:_fail('repair_provision_conflict')
            steps=_decoded(json.loads(bytes(row[1])))
            if name in steps:
                if steps[name]!=value:_fail('repair_provision_conflict')
                return steps[name]
            steps[name]=value
            raw=canonical_bytes(_encoded(steps))
            if len(row[0])+len(raw)>MAX_RECORD_BYTES:_fail('repair_provision_capacity')
            db.execute('UPDATE open_repair_source_provision SET steps=? WHERE request_id=?',(raw,self.plan['request_id']))
        return value

    def _sign(self, kind, **values):
        payload=dict(schema_version=resource.SCHEMA,kind=kind,signing_key=self.delivery.identity.public_descriptor(),**values)
        return _entry(canonical_bytes(dict(payload=payload,proof=self.delivery.identity.sign_message(payload))))

    def _scope(self, kind, value):
        return status.status_scope(self.plan['slot']['root_key'],kind,value,self.policy,wire.RepairBudget(self.policy))

    def _status(self, authorities, revision, *, include_slot=True):
        rows=[dict(scope_kind='authority',scope_id=self._scope('authority',dict(authority_kind=kind,
            authority_sha256=entry['ref']['raw_sha256'])),minimum_document_revision=1,status='active',operation_mask=127)
            for kind,entry in authorities]
        if include_slot:
            rows.append(dict(scope_kind='ack_slot',scope_id=self._scope('ack_slot',self.plan['slot']),
                minimum_document_revision=0,status='active',operation_mask=127))
        payload=dict(schema_version=status.SCHEMA,kind='authority.status',signing_key=self.owner['signing_key'],
            scope_key=dict(root_key=self.plan['slot']['root_key'],issuer_key_id=self.delivery.identity.key_id),revision=revision,
            issued_at=self.source._now(),valid_until=self.plan['until'],entries=sorted(rows,key=lambda row:(row['scope_kind'],row['scope_id'])))
        return _entry(canonical_bytes(dict(payload=payload,proof=self.delivery.identity.sign_message(payload))))

    async def queue_and_prepare(self, request_id, recipient, *, text='', memory_ids=None,
            profile='receipt', lifetime=3600,copy_maintainer=None):
        """Retain a selection, establish unbound custody, then freeze and bind E.

        Subsequent ordinary send must use exactly this request ID and selection.
        Contact approval is still required; this operation does not grant it.
        """
        digest, selected=self.delivery._send_input(request_id,[recipient],text,memory_ids,None)
        self.delivery._prepare_outbox(request_id,recipient,digest,text,selected)
        return await self.prepare_existing(request_id,profile=profile,lifetime=lifetime,copy_maintainer=copy_maintainer)

    async def prepare_existing(self, request_id, *, profile='receipt', lifetime=3600,copy_maintainer=None):
        if type(profile) is not str or profile not in PROFILES or type(lifetime) is not int or not 120<=lifetime<=86400:
            _fail('repair_invalid_request_bundle')
        resource._opaque(request_id)
        copy_maintainer=_copy_maintainer(copy_maintainer,profile,self.policy)
        plan_version=COPY_PLAN_VERSION if copy_maintainer is not None else PLAN_VERSION
        row=self.delivery._outbox(request_id);self._unsent(row)
        held=self._load(request_id)
        if held is not None and held[0].get('copy_maintainer')!=copy_maintainer:_fail('repair_provision_conflict')
        if held is not None and held[0].get('plan_version')!=plan_version:
            _fail('repair_provision_legacy_order')
        if held is None:
            if row['envelope'] is not None or row['session'] is not None:
                _fail('repair_provision_preexisting_envelope')
            session=await self.delivery._sending_session(row['recipient'],_DeliveryBudget())
            session_raw=canonical_bytes(session)
        else:
            session_raw=held[0]['session']
            session=document(session_raw,maximum=MAX_SESSION_BYTES)
            decision=verify_decision(session['decision'],request=session['request'],policy=session['policy'],
                lease=session['lease'],node=session['node'],now=held[0]['created_at'])
            if decision['decision']!='approved' or decision['grant'] is None:
                _fail('repair_provision_outbox_mismatch')
            if row['envelope'] is not None and 'encryption_authorized' not in held[1]:
                _fail('repair_provision_preexisting_envelope')
        keys=self.delivery._keys(session)
        if (keys['sender_signing_key']!=self.owner['signing_key'] or keys['sender_encryption_key']!=self.owner['encryption_key']
                or keys['recipient_signing_key']['key_id']!=row['recipient']):
            _fail('repair_provision_outbox_mismatch')
        writer=dict(signing_key=keys['recipient_signing_key'],encryption_key=keys['recipient_encryption_key'])
        if copy_maintainer is not None and any(
                copy_maintainer[k]['key_id']==party[k]['key_id']
                for party in (self.owner,writer,self.source.target) for k in ('signing_key','encryption_key')):
            _fail('repair_copy_maintainer_distinct_parties_required')
        stable=dict(request_id=request_id,input_sha256=row['input_sha256'],message_id=row['message_id'],
            body_sha256=hashlib.sha256(bytes(row['body'])).hexdigest(),session=session_raw,
            owner=self.owner,writer=writer,target=self.source.target,epoch=self.source.node['payload']['storage_epoch'],profile=profile,lifetime=lifetime)
        if copy_maintainer is not None:stable['copy_maintainer']=copy_maintainer
        if held is None:
            now=self.source._now();until=min(now+lifetime,self.source.node['payload']['expires_at'])
            if until-now<120:_fail('repair_provision_expiring_source')
            limits=dict(PROFILES[profile])
            if any(limits[name]>self.source.limits[name] for name in limits):_fail('repair_provision_profile_not_enabled')
            token=secrets.token_hex(24)
            owner_id={name+'_id':value['key_id'] for name,value in self.owner.items()}
            writer_id={name+'_id':value['key_id'] for name,value in writer.items()}
            root=dict(owner=owner_id,root_kind='ack_return',anchor_ref=dict(namespace='anchor',key=secrets.token_hex(32)),
                owner_epoch='owner_'+token,root_id='ack_'+token)
            caps=dict(max_live_bytes=16384,max_meta_bytes=limits['max_proof_bytes'],max_items=128,
                max_requests=limits['max_signature_checks'],max_pending=limits['max_pending'],max_replay_records=limits['max_replay_records'],
                max_jobs=16,max_job_bytes=limits['max_proof_bytes'])
            plan=dict(stable,plan_version=plan_version,slot=dict(root_key=root,slot_id='slot_'+token,receipt_writer=writer_id,grant_id='write_'+token),
                created_at=now,until=until,token=token,limits=limits,caps=caps,node=_entry(canonical_bytes(self.source.node)))
            encoded=canonical_bytes(_encoded(plan))
            with self.delivery.participant.state.db() as db:
                db.execute('BEGIN IMMEDIATE')
                if db.execute('SELECT count(*) FROM open_repair_source_provision').fetchone()[0]>=MAX_RECORDS:_fail('repair_provision_capacity')
                actual=db.execute('SELECT * FROM open_delivery_outbox WHERE request_id=?',(request_id,)).fetchone()
                self._unsent(actual)
                if actual['envelope'] is not None or actual['session'] is not None:
                    _fail('repair_provision_preexisting_envelope')
                db.execute('INSERT OR IGNORE INTO open_repair_source_provision VALUES(?,?,?)',(request_id,encoded,b'{}'))
            held=self._load(request_id)
        self.plan=held[0]
        if self.plan.get('plan_version')!=plan_version:_fail('repair_provision_legacy_order')
        if any(self.plan.get(name)!=value for name,value in stable.items()):_fail('repair_provision_conflict')
        if self.source._now()>=self.plan['until']:_fail('repair_provision_expired')
        unbound=self._provision_unbound()
        self._authorize_encryption(unbound)
        row=self.delivery._outbox(request_id);self._unsent(row)
        row=self.delivery._encrypt_outbox(row,session)
        self._unsent(row)
        raw=bytes(row['envelope'])
        checked=verify_envelope(raw,**keys)
        if checked['context']['message_id']!=self.plan['message_id'] or bytes(row['session'])!=session_raw:
            _fail('repair_provision_outbox_mismatch')
        reference=envelope_ref(raw)
        frozen=self._step('envelope',lambda:reference)
        if frozen!=reference:_fail('repair_provision_outbox_mismatch')
        result=self._provision_bound(unbound,reference)
        current=self.delivery._outbox(request_id);self._unsent(current)
        if bytes(current['envelope'])!=raw or bytes(current['session'])!=bytes(row['session']):_fail('repair_provision_outbox_mismatch')
        return result

    def _authorize_encryption(self, unbound):
        """Commit the pre-E boundary while the actual outbox still has no E."""
        marker=dict(resource_id=unbound['resource_id'],custody_ref=unbound['custody']['ref'],
            session_sha256=hashlib.sha256(self.plan['session']).hexdigest())
        held=self._load(self.plan['request_id'])
        if held is None or held[0]!=self.plan:_fail('repair_provision_conflict')
        if 'encryption_authorized' in held[1]:
            if held[1]['encryption_authorized']!=marker:_fail('repair_provision_conflict')
            actual=self.delivery._outbox(self.plan['request_id']);self._unsent(actual)
            if actual['envelope'] is not None:
                return
            # A pre-E crash leaves the marker but creates no ciphertext. First
            # encryption still requires a live complete unbound source now.
        # Authenticate the actual durable pins and current source floors before
        # permitting any ciphertext creation, not merely journaled result bytes.
        access=RepairAckAccess(self.source);access.initialize()
        prepared=access.prepare(unbound['resource_id'],action='challenge',
            current_statuses=[unbound['owner_status'],unbound['active']['status']])
        with self.source._transaction():
            decision=access.check_locked(prepared)
            actual=self.source._row(unbound['resource_id'])
            if bytes(actual['custody'])!=unbound['custody']['raw'] or json.loads(bytes(actual['custody_ref']))!=marker['custody_ref']:
                _fail('repair_provision_conflict')
        if not decision.allowed:_fail(decision.code)
        with self.delivery.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT plan,steps FROM open_repair_source_provision WHERE request_id=?',(self.plan['request_id'],)).fetchone()
            if row is None or _decoded(json.loads(bytes(row[0])))!=self.plan:_fail('repair_provision_conflict')
            steps=_decoded(json.loads(bytes(row[1])))
            actual=db.execute('SELECT * FROM open_delivery_outbox WHERE request_id=?',(self.plan['request_id'],)).fetchone()
            self._unsent(actual)
            if 'encryption_authorized' in steps:
                if steps['encryption_authorized']!=marker:_fail('repair_provision_conflict')
                return
            if actual['envelope'] is not None or actual['session'] is not None:
                _fail('repair_provision_preexisting_envelope')
            if (actual['input_sha256']!=self.plan['input_sha256'] or actual['message_id']!=self.plan['message_id']
                    or hashlib.sha256(bytes(actual['body'])).hexdigest()!=self.plan['body_sha256']):
                _fail('repair_provision_outbox_mismatch')
            steps['encryption_authorized']=marker
            raw=canonical_bytes(_encoded(steps))
            if len(row[0])+len(raw)>MAX_RECORD_BYTES:_fail('repair_provision_capacity')
            db.execute('UPDATE open_repair_source_provision SET steps=? WHERE request_id=?',(raw,self.plan['request_id']))

    def _build_owner_setup(self, offer):
        p=self.plan;slot=p['slot'];rootkey=slot['root_key'];token=p['token'];until=p['until']
        windows={name:until for name in resource._WINDOWS}
        op=json.loads(offer['raw'])['payload']
        now=self.source._now()
        maintainers=[{name+'_id':value['key_id'] for name,value in p['target'].items()}] if p['profile']=='receipt-index' else []
        operation_mask=91 if p['profile']=='receipt-index' else 75
        if p.get('copy_maintainer') is not None:
            maintainers.append({name+'_id':value['key_id'] for name,value in p['copy_maintainer'].items()})
            maintainers.sort(key=lambda item:(item['signing_key_id'],item['encryption_key_id']))
            operation_mask|=4
        root=self._sign('ack.root_authority',issued_at=now,expires_at=until,ack_slot=slot,authority_id='authority_'+token,
            owner=rootkey['owner'],receipt_writer=slot['receipt_writer'],original_resource_ref=op['resource'],
            original_resource_offer_ref=offer['ref'],maintainers=maintainers,operation_mask=operation_mask,
            allowed_roles=sorted(ack.ROLES|empty.ROLES|occupied.ROLES|{'bootstrap.grant','ack_owner_service_v1','ack_offer_service_v1'}),
            max_bindings=1,max_receipts=1,budget=p['caps'],windows=windows,max_delegate_depth=2,
            max_destinations_per_job=1,max_concurrent_jobs=1,revision=1)
        read=self._sign('ack.read_grant',issued_at=now,expires_at=until,grant_id='read_'+token,ack_slot=slot,
            reader=rootkey['owner'],root_authority_ref=root['ref'],operation_mask=2,budget=p['caps'],windows=windows,revision=1)
        bootstrap=self._bootstrap(root,read,'ack_owner',rootkey['owner'],now)
        activation=self._sign('resource.activation',issued_at=now,expires_at=min(until,op['reservation_until']),
            activation_id='activation_'+token,subject=self.owner,target_node_key_id=p['target']['signing_key']['key_id'],
            target_storage_epoch=p['epoch'],root_key=rootkey,scope=dict(kind='ack_unbound',ack_slot=slot,root_authority_ref=root['ref']),
            resource_offer_refs=[offer['ref']],authority_refs=[dict(role='ack.read_grant',ref=read['ref']),dict(role='ack.root_authority',ref=root['ref'])])
        return dict(root=root,read=read,bootstrap=bootstrap,activation=activation)

    def _provision_unbound(self):
        p=self.plan;slot=p['slot'];rootkey=slot['root_key'];token=p['token'];until=p['until']
        windows={name:until for name in resource._WINDOWS}
        allocation=self._step('allocation',lambda:self._sign('resource.allocate',issued_at=p['created_at'],expires_at=until,
            request_id='allocate_'+token,target_node_key_id=p['target']['signing_key']['key_id'],target_storage_epoch=p['epoch'],
            **self._allocation(windows)))
        offer=self._step('offer',lambda:self.source.allocate(allocation,expected_owner=self.owner))
        op=json.loads(offer['raw'])['payload'];resource_id=op['resource']['resource_id']
        setup=self._step('setup',lambda:self._build_owner_setup(offer))
        active=self._step('active',lambda:self.source.activate(resource_id,setup,expected_ack_slot=slot))
        base_authorities=[('ack.root_authority',setup['root']),('ack.read_grant',setup['read']),('bootstrap.grant',setup['bootstrap'])]
        owner_status=self._step('owner_status',lambda:self._status(base_authorities,2))
        def historical():
            roles={name:owner_status for name in ack.ROLES if name.startswith('historical.status.')}
            roles.update({'ack.root_authority':setup['root'],'ack.read_grant':setup['read'],'bootstrap.ack_owner':setup['bootstrap'],
                'resource.ack_allocate':allocation,'resource.ack_offer':offer,'resource.ack_activation':setup['activation'],
                'resource.ack_active':active['active'],'source.descriptor':p['node'],'historical.status.ack_resource':active['status']})
            pack=wire.build_raw_pack(list(dict.fromkeys(entry['raw'] for entry in roles.values())),self.policy,wire.RepairBudget(self.policy))
            positions={entry.raw_sha256:i for i,entry in enumerate(pack.entries)}
            manifest=dict(schema_version=history.SCHEMA,kind='historical.manifest',variant='ack_unbound',root_key=rootkey,
                ack_slot=slot,root_authority_ref=setup['root']['ref'],roles=[dict(role=role,document_ref=entry['ref'],
                    pack_ref=pack.ref.as_dict(),entry_index=positions[entry['ref']['raw_sha256']]) for role,entry in sorted(roles.items())])
            return dict(manifest=_entry(canonical_bytes(manifest)),packs=[dict(raw=pack.raw,ref=pack.ref.as_dict())])
        inputs=self._step('historical',historical)
        custody=self._step('custody',lambda:self.source.finalize_unbound(resource_id,inputs['manifest'],inputs['packs'],
            expected_ack_slot=slot,read_until=until,retain_until=until))
        return dict(resource_id=resource_id,setup=setup,active=active,owner_status=owner_status,custody=custody)

    def _binding_statuses(self, base_authorities, write, bootstrap, active):
        current=self._status([*base_authorities,('ack.write_grant',write),('bootstrap.grant',bootstrap)],3)
        return [current,active['status']]

    def _provision_bound(self, unbound, envelope_reference):
        p=self.plan;slot=p['slot'];rootkey=slot['root_key'];token=p['token'];until=p['until']
        resource_id=unbound['resource_id'];setup=unbound['setup'];active=unbound['active']
        windows={name:until for name in resource._WINDOWS}
        base_authorities=[('ack.root_authority',setup['root']),('ack.read_grant',setup['read']),('bootstrap.grant',setup['bootstrap'])]
        def write_inputs():
            now=self.source._now()
            write=self._sign('ack.write_grant',issued_at=now,expires_at=until,grant_id=slot['grant_id'],ack_slot=slot,
                root_authority_ref=setup['root']['ref'],owner=rootkey['owner'],receipt_writer=slot['receipt_writer'],
                message_id=p['message_id'],envelope_ref=envelope_reference,operation='receipt.put',max_receipts=1,
                budget=p['caps'],windows=windows,revision=1)
            bootstrap=self._bootstrap(setup['root'],write,'ack_offer',slot['receipt_writer'],now)
            return dict(write=write,bootstrap=bootstrap,
                statuses=self._binding_statuses(base_authorities,write,bootstrap,active))
        write=self._step('write_inputs',write_inputs)
        # Invoke the durable bind on every retry: it revalidates actual pins,
        # current floors and capacity instead of treating journal bytes as proof.
        bound=self.empty.bind(resource_id,write['write'],write['bootstrap'],expected_receipt_writer=p['writer'],
            expected_message_id=p['message_id'],expected_envelope_ref=envelope_reference,current_statuses=write['statuses'],
            read_until=until,retain_until=until)
        self._step('bound',lambda:bound)
        owner_bundle=dict(schema_version='memory-vault-open-ack-occupied-recovery-request/v1',target=p['target'],ack_slot=slot,
            node=encode_original(p['node']),root=encode_original(setup['root']),read=encode_original(setup['read']),
            bootstrap=encode_original(setup['bootstrap']),known_statuses=[encode_original(item) for item in write['statuses']],
            receipt_writer=p['writer'],message_id=p['message_id'],envelope_ref=envelope_reference)
        request=dict(message_id=p['message_id'],envelope_ref=envelope_reference,ack_slot=slot,owner=p['owner'],target=p['target'],
            target_node_entry=p['node'],root_entry=setup['root'],write_entry=write['write'],bootstrap_entry=write['bootstrap'],
            binding_entry=bound['binding'],current_statuses=write['statuses'],read_until=until,retain_until=until)
        recipient=dict(schema_version=SAVED_REQUEST_SCHEMA,base_url=json.loads(p['node']['raw'])['payload']['base_url'],repair_profile=p['profile'],
            request={name:([encode_original(item) for item in value] if name=='current_statuses' else
                encode_original(value) if name.endswith('_entry') else value) for name,value in request.items()})
        return dict(state='empty',resource_id=resource_id,message_id=p['message_id'],envelope_ref=envelope_reference,
            owner_request=owner_bundle,recipient_request=recipient,delivery_uploaded=False,recipient_saved=False)

    def _allocation(self,windows):
        p=self.plan
        intent=dict(kind='resource.owner_intent',allocation_id='allocation_'+p['token'],root_key=p['slot']['root_key'],
            owner=p['owner'],target=p['target'],target_storage_epoch=p['epoch'],purpose='ack_slot',budget=p['caps'],windows=windows)
        return dict(intent=intent,intent_sha256=_digest(intent))

    def _bootstrap(self,root,caller,consumer,subject,now):
        p=self.plan;owner=consumer=='ack_owner'
        selector=dict(root_key_sha256=_digest(p['slot']['root_key']),ack_slot_sha256=_digest(p['slot']),
            root_authority_sha256=root['ref']['raw_sha256'])
        selector['read_grant_sha256' if owner else 'write_grant_sha256']=caller['ref']['raw_sha256']
        return self._sign('bootstrap.grant',issued_at=now,expires_at=p['until'],grant_id=consumer+'_'+p['token'],revision=1,
            owner=p['slot']['root_key']['owner'],subject=subject,root_key=p['slot']['root_key'],consumer=consumer,selector=selector,
            parent_authority_ref=root['ref'],caller_authority_ref=caller['ref'],probe_until=p['until'],proof_until=p['until'],
            upload_until=p['until'],probe_profile='opaque_v1',response_profile=consumer+'_service_v1',
            upload_roles=['ack.read_grant','ack.root_authority','ack.write_grant','bootstrap.grant'] if owner else
                ['ack.root_authority','ack.write_grant','bootstrap.grant'],limits=p['limits'])
