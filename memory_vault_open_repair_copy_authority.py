"""Whole-original authority for unbound and bound-empty ACK replica commits.

The returned observations must be retained before a caller acts on denial_code.
This module does not reserve storage, persist bytes, advertise or serve a replica.
"""
from dataclasses import dataclass
from types import MappingProxyType

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_copy_source as copy_source
from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS
from memory_vault_open_repair_copy_resources import INTENT_FIELDS

DISCLOSURE_FIELDS = resource.COMMON | frozenset('issued_at expires_at consent_id revision variant root_key assignment_ref source_custody_ref historical_manifest_ref target target_storage_epoch disclosure'.split())
REPLICA_FIELDS = resource.COMMON | frozenset('root_key scope original_custody_ref replica_manifest_ref assignment_ref resource_offer_ref resource reservation_generation stored_at read_until retain_until'.split())


def _same(value):
    if not value:wire._fail('repair_copy_authority_mismatch')


def verify_unbound_replica_event(*args,**options):
    return _verify_replica_event(*args,**options,source_state='unbound',bound={})


def verify_empty_replica_event(*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**options):
    return _verify_replica_event(*args,**options,source_state='empty',bound=dict(
        expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
        expected_envelope_ref=expected_envelope_ref))


def _verify_replica_event(manifest_entry,resolver,custody_entry,*,expected_ack_slot,
        expected_owner,expected_source,source_storage_epoch,expected_maintainer,expected_target,
        target_storage_epoch,limit_policy,policy,budget,source_state,bound):
    """Reconstruct P's historical copy event from exact originals on any client.

    No database, local identity, network or current serving authority is assumed.
    P's signature never substitutes for the original R event or A-to-M-to-P
    authority. A caller must separately establish live READ and disclosure rights.
    """
    wire._context(policy,budget)
    if resolver.policy is not policy or resolver.budget is not budget:
        wire._fail('repair_invalid_context')
    target=wire.build_new_wire(expected_target,policy,budget).value
    target_ids=resource._dual_key(target,budget)
    custody=index._signed(custody_entry,target['signing_key'],'replica.custody',REPLICA_FIELDS,policy,budget)
    p=custody.payload
    history._resource(p['resource']);history._root(p['root_key'])
    stored_at=wire.u53(p['stored_at'])
    if (not stored_at<wire.u53(p['read_until'])<=wire.u53(p['retain_until'])
            or wire.u53(p['reservation_generation'],1)!=1
            or p['resource']['node_key_id']!=target_ids['signing_key_id']
            or p['resource']['storage_epoch']!=target_storage_epoch):
        wire._fail('repair_copy_commit_mismatch')
    wire.object_fields(manifest_entry,{'raw','ref'})
    ref=wire.raw_ref(manifest_entry['ref'])
    manifest=wire.parse_new_wire(manifest_entry['raw'],policy,budget)
    if ref.namespace!='meta' or len(manifest.raw)!=ref.size or budget._hash(manifest.raw)!=ref.raw_sha256:
        wire._fail('repair_ref_mismatch')
    value=wire.object_fields(manifest.value,{'schema_version','kind','root_key','scope','original_roles','physical_objects','edges'})
    if (value['schema_version']!=resource.SCHEMA or value['kind']!='replica.manifest'
            or p['replica_manifest_ref']!=ref.as_dict() or p['root_key']!=value['root_key']
            or p['scope']!=value['scope'] or value['physical_objects']!=value['original_roles']
            or not isinstance(value['original_roles'],(list,tuple)) or not 1<=len(value['original_roles'])<=128):
        wire._fail('repair_copy_commit_mismatch')
    entries={};previous=None
    for row in value['original_roles']:
        wire.object_fields(row,{'role','ref'})
        if type(row['role']) is not str:wire._fail('repair_copy_commit_mismatch')
        reference=wire.raw_ref(row['ref']);key=(row['role'],*history._ref_tuple(reference))
        if previous is not None and key<=previous:wire._fail('repair_copy_commit_mismatch')
        previous=key
        item=resolver.resolve(reference)
        entries.setdefault(row['role'],[]).append(dict(raw=item.raw,ref=item.ref.as_dict()))
    def one(role):
        values=entries.get(role,())
        if len(values)!=1:wire._fail('repair_copy_commit_mismatch')
        return values[0]
    source_history='history.ack_'+source_state
    source_custody='ack.empty_custody' if source_state=='empty' else 'ack.slot_custody'
    plan=_verify_copy(one(source_history),resolver,one(source_custody),
        one('copy.allocation'),one('copy.offer'),one('copy.assignment'),one('copy.reservation_consent'),
        one('copy.owner_disclosure'),one('copy.source_disclosure'),expected_ack_slot=expected_ack_slot,
        expected_owner=expected_owner,expected_source=expected_source,source_storage_epoch=source_storage_epoch,
        expected_maintainer=expected_maintainer,expected_target=target,target_storage_epoch=target_storage_epoch,
        current_statuses=entries.get('copy.current_status',()),at=stored_at,
        limit_policy=limit_policy,policy=policy,budget=budget,source_state=source_state,bound=bound)
    if plan.denial_code:wire._fail(plan.denial_code)
    if (p['assignment_ref']!=plan.assignment.ref.as_dict()
            or p['original_custody_ref']!=plan.source.custody.ref.as_dict()
            or p['resource_offer_ref']!=plan.offer.ref.as_dict() or p['resource']!=plan.offer.payload['resource']
            or p['root_key']!=plan.assignment.payload['root_key'] or p['scope']!=plan.assignment.payload['scope']
            or p['read_until']!=plan.read_until or p['retain_until']!=plan.retain_until):
        wire._fail('repair_copy_commit_mismatch')
    roles={(item.role,*history._ref_tuple(item.original.ref)) for item in plan.originals}
    for role,item in (('copy.allocation',plan.allocation),('copy.offer',plan.offer),('copy.assignment',plan.assignment),
            ('copy.owner_disclosure',plan.disclosures[0]),('copy.source_disclosure',plan.disclosures[1])):
        roles.add((role,*history._ref_tuple(item.ref)))
    roles.update(('copy.current_status',*history._ref_tuple(item.ref)) for item in plan.statuses)
    edges=[]
    for role,entry,source_manifest in copy_source.source_histories(plan.source,one(source_history)):
        roles.add((role,*history._ref_tuple(entry['ref'])))
        for item in source_manifest.manifest.value['roles']:
            roles.add(('history.raw_pack',*history._ref_tuple(item['pack_ref'])))
            for child in (item['document_ref'],item['pack_ref']):
                edges.append(dict(parent_ref=entry['ref'],relation='manifest-member',child_ref=child))
    edge_key=lambda e:(*history._ref_tuple(e['parent_ref']),e['relation'],*history._ref_tuple(e['child_ref']))
    edges=sorted({edge_key(e):e for e in edges}.values(),key=edge_key)
    if (roles!={(item['role'],*history._ref_tuple(item['ref'])) for item in value['original_roles']}
            or value['edges']!=edges
            or len({history._ref_tuple(item['ref']) for item in value['original_roles']})>plan.offer.payload['budget']['max_items']):
        wire._fail('repair_copy_commit_mismatch')
    return dict(state='historical_replica',custody=custody,source=plan.source,authority=plan,
        entries=MappingProxyType({role:tuple(values) for role,values in entries.items()}))


def source_inventory(source, reservation, policy, budget):
    rows = {}
    inputs=[(r.role,r.original) for manifest in copy_source.source_manifests(source) for r in manifest.roles]
    for role, item in inputs + [
            (copy_source.source_custody_role(source),source.custody),('copy.reservation_consent',reservation)]:
        value = wire.parse_new_wire(item.raw,policy,budget).value
        if 'payload' not in value:continue
        issuer = value['payload']['signing_key']['key_id']
        rows[index._pair(role,item.ref)] = index.IndexOriginal(role,item,issuer)
    return tuple(rows[key] for key in sorted(rows))


def disclosure_permissions(rows, issuer, root, policy, budget):
    originals, scopes = index._permissions(rows, issuer, policy, budget)
    for row in rows:
        if row.issuer == issuer and row.role == 'copy.reservation_consent':
            scopes.append(dict(scope_kind='authority',scope_id=index._authority(root,row.original,policy,budget)))
    scopes = [dict(scope_kind=k,scope_id=v) for k,v in sorted({(e['scope_kind'],e['scope_id']) for e in scopes})]
    return originals, scopes


@dataclass(frozen=True)
class UnboundCopyAuthority:
    source: object
    allocation: object
    offer: object
    assignment: object
    reservation: object
    disclosures: tuple
    originals: tuple
    statuses: tuple
    obligations: tuple
    read_until: int
    retain_until: int
    denial_code: object


def verify_unbound_copy(*args,**options):
    return _verify_copy(*args,**options,source_state='unbound',bound={})


def verify_empty_copy(*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**options):
    return _verify_copy(*args,**options,source_state='empty',bound=dict(
        expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
        expected_envelope_ref=expected_envelope_ref))


def _verify_copy(manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,assignment_entry,
        reservation_entry,owner_disclosure_entry,source_disclosure_entry,*,expected_ack_slot,expected_owner,
        expected_source,source_storage_epoch,expected_maintainer,expected_target,target_storage_epoch,
        current_statuses,at,limit_policy,policy,budget,source_state,bound,on_observed=None):
    wire._context(policy,budget);at=wire.u53(at)
    context=wire.build_new_wire(dict(owner=expected_owner,source=expected_source,maintainer=expected_maintainer,
        target=expected_target),policy,budget).value
    ids={name:resource._dual_key(value,budget) for name,value in context.items()}
    source=copy_source.authenticate_source(manifest_entry,resolver,custody_entry,source_state=source_state,bound=bound,
        expected_ack_slot=expected_ack_slot,expected_owner=context['owner'],expected_target=context['source'],
        target_storage_epoch=source_storage_epoch,limit_policy=limit_policy,policy=policy,budget=budget)
    root=source.resources.originals['root'];read=source.resources.originals['read'];active=source.resources.originals['active']
    bootstrap=source.bootstrap.originals['bootstrap'];slot=root.payload['ack_slot'];root_key=slot['root_key']
    _same(ids['maintainer'] in root.payload['maintainers'] and root.payload['operation_mask'] & 78 == 78
        and root.payload['max_delegate_depth']>=2 and ids['target'] not in (ids['source'],ids['maintainer']))
    allocation=index._signed(allocation_entry,context['maintainer']['signing_key'],'resource.allocate',index.ALLOCATE_FIELDS,policy,budget)
    offer=index._signed(offer_entry,context['target']['signing_key'],'resource.offer',index.OFFER_FIELDS,policy,budget)
    assignment=index._signed(assignment_entry,context['maintainer']['signing_key'],'maintenance.assignment',index.ASSIGNMENT_FIELDS,policy,budget)
    a,o,m=(v.payload for v in (allocation,offer,assignment))
    index._timed(a,at);index._timed(m,at)
    for name,p in (('request_id',a),('offer_id',o),('assignment_id',m)):resource._opaque(p[name])
    intent=resource._fields(a['intent'],INTENT_FIELDS)
    resource._budget(intent['budget']);resource._windows(intent['windows'],issued=at)
    history._resource(o['resource'])
    for name in ('allocation_id','job_id','target_storage_epoch'):resource._opaque(intent[name])
    digest=budget._hash(wire._canonical(intent,budget))
    _same(intent['kind']=='resource.copy_intent' and intent['purpose']=='ack_replica'
        and intent['caller']==context['maintainer'] and intent['target']==context['target']
        and intent['target_storage_epoch']==target_storage_epoch and intent['root_key']==root_key
        and intent['scope']==copy_source.source_scope(source)
        and intent['historical_manifest_ref']==wire.raw_ref(manifest_entry['ref']).as_dict()
        and o['intent']==intent and a['intent_sha256']==o['intent_sha256']==digest
        and o['allocation_request_ref']==allocation.ref.as_dict()
        and o['target_encryption_key']==context['target']['encryption_key']
        and o['resource']['node_key_id']==ids['target']['signing_key_id']
        and o['resource']['storage_epoch']==target_storage_epoch and wire.u53(o['reservation_generation'],1)==1
        and o['budget']==intent['budget'] and o['windows']==intent['windows']
        and a['issued_at']<=wire.u53(o['issued_at'])<=m['issued_at']<=at<wire.u53(o['reservation_until'])<=a['expires_at'])
    _same(all(intent['budget'][name]<=root.payload['budget'][name] for name in resource._BUDGET)
        and all(intent['windows'][name]<=root.payload['windows'][name] for name in resource._WINDOWS))
    _same(m['job_id']==intent['job_id'] and m['root_key']==root_key and m['parent_root_ref']==root.ref.as_dict()
        and m['parent_assignment_ref'] is None and wire.u53(m['depth'])==2 and m['subject']==ids['target']
        and wire.u53(m['operation_mask'])==70 and m['scope']==intent['scope']
        and m['resource_intent_sha256']==digest and m['resource_offer_ref']==offer.ref.as_dict()
        and m['resource']==o['resource'] and m['bootstrap_grant_refs']==copy_source.bootstrap_refs(source)
        and m['budget']==o['budget'] and m['windows']==o['windows']
        and all(value<=m['expires_at'] for value in m['windows'].values())
        and m['expires_at']<=min(root.payload['expires_at'],read.payload['expires_at'],read.payload['windows']['read_until'],
            bootstrap.payload['expires_at'],bootstrap.payload['probe_until'],bootstrap.payload['proof_until'],bootstrap.payload['upload_until'],
            *copy_source.additional_deadlines(source)))
    for p in (a,m):
        _same(p['target_node_key_id']==ids['target']['signing_key_id'] and p['target_storage_epoch']==target_storage_epoch)
    reservation=index._signed(reservation_entry,context['owner']['signing_key'],'ack.copy_reservation_consent',CONSENT_FIELDS,policy,budget)
    c=reservation.payload;index._timed(c,at);resource._opaque(c['consent_id']);wire.u53(c['revision'],1)
    disclosure=resource._fields(c['reservation_disclosure'],{'intent_sha256','until'})
    maximum=min(source.read_until,source.retain_until,active.payload['windows']['copy_until'],
        root.payload['expires_at'],root.payload['windows']['copy_until'],c['expires_at'],intent['windows']['copy_until'],
        *copy_source.additional_deadlines(source))
    _same(c['root_authority_ref']==root.ref.as_dict() and c['source_custody_ref']==source.custody.ref.as_dict()
        and c['historical_manifest_ref']==intent['historical_manifest_ref'] and c['maintainer']==ids['maintainer']
        and c['target']==context['target'] and c['target_storage_epoch']==target_storage_epoch
        and source.stored_at<=c['issued_at']<=a['issued_at'] and disclosure['intent_sha256']==digest
        and at<wire.u53(disclosure['until'])<=maximum)
    rows=source_inventory(source,reservation,policy,budget)
    signers={context[n]['signing_key']['key_id']:context[n]['signing_key'] for n in ('owner','source','maintainer')}
    allowed={key:[] for key in signers};consents=[]
    until=min(maximum,m['expires_at'])
    for variant,entry in (('owner',owner_disclosure_entry),('source',source_disclosure_entry)):
        signer=context[variant]['signing_key']
        consent=index._signed(entry,signer,'ack.copy_disclosure',DISCLOSURE_FIELDS,policy,budget)
        p=consent.payload;index._timed(p,at);resource._opaque(p['consent_id']);wire.u53(p['revision'],1)
        _same(p['variant']==variant and p['root_key']==root_key and p['assignment_ref']==assignment.ref.as_dict()
            and p['source_custody_ref']==source.custody.ref.as_dict() and p['historical_manifest_ref']==intent['historical_manifest_ref']
            and p['target']==context['target'] and p['target_storage_epoch']==target_storage_epoch
            and m['issued_at']<=p['issued_at'])
        d=wire.object_fields(p['disclosure'],{'originals','status_scopes','until'})
        originals,scopes=disclosure_permissions(rows,signer['key_id'],root_key,policy,budget)
        _same(d['originals']==originals and d['status_scopes']==scopes
            and at<wire.u53(d['until'])<=min(maximum,p['expires_at']))
        allowed[signer['key_id']].extend(scopes)
        allowed[signer['key_id']].append(dict(scope_kind='authority',scope_id=index._authority(root_key,consent,policy,budget)))
        until=min(until,p['disclosure']['until'],p['expires_at']);consents.append(consent)
    # The reservation consent is itself a disclosed original; its status scope is
    # not present in the older source's historical status documents.
    allowed[context['owner']['signing_key']['key_id']].append(dict(scope_kind='authority',scope_id=index._authority(root_key,reservation,policy,budget)))
    assignment_scope=status.status_scope(root_key,'assignment',dict(assignment_kind='maintenance.assignment',assignment_sha256=assignment.ref.raw_sha256),policy,budget)
    allowed[context['maintainer']['signing_key']['key_id']].append(dict(scope_kind='assignment',scope_id=assignment_scope))
    allowed={key:[dict(scope_kind=k,scope_id=v) for k,v in sorted({(e['scope_kind'],e['scope_id']) for e in values})] for key,values in allowed.items()}
    obligations=[index._obligation(context['owner']['signing_key'],'authority',index._authority(root_key,item,policy,budget),item.payload['revision'],mask)
        for item,mask in ((root,78),(read,2),(bootstrap,10),(reservation,4))]
    obligations.extend(copy_source.additional_obligations(source,context['owner'],policy,budget))
    obligations.extend((index._obligation(context['owner']['signing_key'],'ack_slot',status.status_scope(root_key,'ack_slot',slot,policy,budget),root.payload['revision'],70),
        index._obligation(context['source']['signing_key'],'resource',status.status_scope(root_key,'resource',active.payload['resource'],policy,budget),active.payload['reservation_generation'],4),
        index._obligation(context['maintainer']['signing_key'],'assignment',assignment_scope,0,70)))
    obligations.extend(index._obligation(context[variant]['signing_key'],'authority',index._authority(root_key,item,policy,budget),item.payload['revision'],4)
        for variant,item in zip(('owner','source'),consents))
    checked,denial=[],None
    def observe(item):
        checked.append(item)
        if on_observed is not None:on_observed(item)
    if not isinstance(current_statuses,(list,tuple)) or not 1<=len(current_statuses)<=16:wire._fail('repair_status_missing')
    for entry in current_statuses:
        try:
            p=wire.parse_new_wire(entry['raw'],policy,budget).value['payload'];issuer=p['signing_key']['key_id']
            if issuer not in signers:wire._fail('repair_status_disclosure')
            status.authenticate_status_original(entry,expected_root=root_key,expected_signing_key=signers[issuer],at=at,
                allowed_scopes=allowed[issuer],policy=policy,budget=budget,on_authenticated=observe)
        except (KeyError,TypeError):denial=denial or 'repair_invalid_status'
        except wire.RepairWireError as error:denial=denial or error.code
    if len({s.ref for s in checked})!=len(checked):denial=denial or 'repair_duplicate_status'
    try:empty._history_floors((*source.statuses,*checked),previous=source.statuses,current=checked)
    except wire.RepairWireError as error:denial=denial or error.code
    for need in obligations:
        observations=[e for s in checked if s.payload['signing_key']==need['signer'] for e in s.payload['entries']
            if (e['scope_kind'],e['scope_id'])==(need['scope_kind'],need['scope_id'])]
        if not observations:denial=denial or 'repair_status_missing'
        for e in observations:
            if e['status']=='revoked':denial=denial or 'repair_authority_revoked'
            elif e['minimum_document_revision']>need['revision']:denial=denial or 'repair_status_revision'
            elif e['operation_mask']&need['mask']!=need['mask']:denial=denial or 'repair_status_operation'
    read_until=min(until,read.payload['expires_at'],read.payload['windows']['read_until'],bootstrap.payload['expires_at'],
        bootstrap.payload['proof_until'],bootstrap.payload['probe_until'],bootstrap.payload['upload_until'],intent['windows']['read_until'])
    retain_until=min(until,intent['windows']['retain_until'],root.payload['windows']['retain_until'])
    if checked:read_until=min(read_until,*(item.payload['valid_until'] for item in checked))
    if at>=min(read_until,retain_until):denial=denial or 'repair_resource_expired'
    return UnboundCopyAuthority(source,allocation,offer,assignment,reservation,tuple(consents),rows,tuple(checked),tuple(obligations),read_until,retain_until,denial)


RETURN_FIELDS = resource.COMMON | frozenset('issued_at expires_at consent_id revision variant root_key source_custody_ref historical_manifest_ref assignment_ref subject target target_storage_epoch bootstrap_grant_ref return_permission'.split())


def copy_return_permissions(plan, issuer, policy, budget):
    """Exact return-consent signing inputs, available before the copy commit.

    The caller must independently verify the full copy plan. This helper grants
    no authority. Future whole status documents are bounded by explicit scopes.
    """
    rows={}
    candidates=[(row.role,row.original) for row in plan.originals]
    candidates.extend((('copy.allocation',plan.allocation),('copy.offer',plan.offer),('copy.assignment',plan.assignment),
        ('copy.owner_disclosure',plan.disclosures[0]),('copy.source_disclosure',plan.disclosures[1])))
    for role,item in candidates:
        payload=wire.parse_new_wire(item.raw,policy,budget).value['payload']
        if payload['signing_key']['key_id']==issuer:
            rows[index._pair(role,item.ref)]=index.IndexOriginal(role,item,issuer)
    originals,scopes=index._permissions(tuple(rows[key] for key in sorted(rows)),issuer,policy,budget)
    root=plan.assignment.payload['root_key']
    for row in rows.values():
        item=row.original;kind=wire.parse_new_wire(item.raw,policy,budget).value['payload']['kind']
        if kind in ('ack.copy_reservation_consent','ack.copy_disclosure'):
            scopes.append(dict(scope_kind='authority',scope_id=index._authority(root,item,policy,budget)))
        elif kind=='maintenance.assignment':
            scopes.append(dict(scope_kind='assignment',scope_id=status.status_scope(root,'assignment',
                dict(assignment_kind=kind,assignment_sha256=item.ref.raw_sha256),policy,budget)))
    scopes=[dict(scope_kind=k,scope_id=v) for k,v in sorted({(e['scope_kind'],e['scope_id']) for e in scopes})]
    return originals,scopes


def replica_return_permissions(replica, issuer, policy, budget):
    return copy_return_permissions(replica['authority'],issuer,policy,budget)


def _check_unbound_owner_return(replica,consent_entries,*,expected_owner,expected_source,expected_maintainer,
        expected_target,target_storage_epoch,current_statuses,at,action,policy,budget,on_observed=None):
    """Internal: replica must come from full original reconstruction in this call.

    Return consent adds no COPY/ADMIT authority, recipient permission or key
    possession. The storage/service caller must retain authenticated observations
    before acting on denial_code and check its live physical resource separately.
    """
    wire._context(policy,budget);at=wire.u53(at)
    if action not in ('challenge','proof','child'):wire._fail('repair_access_action')
    source=replica['source'];plan=replica['authority'];custody=replica['custody']
    root=plan.assignment.payload['root_key'];bootstrap=source.bootstrap.originals['bootstrap']
    parties=dict(owner=expected_owner,source=expected_source,maintainer=expected_maintainer,target=expected_target)
    parties=wire.build_new_wire(parties,policy,budget).value
    owner_id=resource._dual_key(parties['owner'],budget)
    signers={p['signing_key']['key_id']:p['signing_key'] for p in parties.values()}
    if len(signers)!=4:wire._fail('repair_replica_read_distinct_parties_required')
    wire.object_fields(consent_entries,{'owner','source','maintainer'})
    obligations=[];allowed={key:[] for key in signers};consents=[];denial=None
    expires=min(custody.payload['read_until'],custody.payload['retain_until'],bootstrap.payload['expires_at'],
        bootstrap.payload['probe_until'] if action=='challenge' else bootstrap.payload['proof_until'])
    for variant in ('owner','source','maintainer'):
        signer=parties[variant]['signing_key']
        item=index._signed(consent_entries[variant],signer,'ack.replica_return_consent',RETURN_FIELDS,policy,budget)
        p=item.payload;resource._opaque(p['consent_id']);wire.u53(p['revision'],1)
        resource._lifetime(p)
        if not p['issued_at']<=at<p['expires_at']:denial=denial or 'repair_access_expired'
        _same(p['variant']==variant and p['root_key']==root and p['source_custody_ref']==source.custody.ref.as_dict()
            and p['historical_manifest_ref']==plan.allocation.payload['intent']['historical_manifest_ref']
            and p['assignment_ref']==plan.assignment.ref.as_dict() and p['subject']==owner_id
            and p['target']==parties['target'] and p['target_storage_epoch']==target_storage_epoch
            and p['bootstrap_grant_ref']==bootstrap.ref.as_dict() and p['issued_at']>=plan.assignment.payload['issued_at'])
        permission=wire.object_fields(p['return_permission'],{'originals','status_scopes','until'})
        originals,scopes=replica_return_permissions(replica,signer['key_id'],policy,budget)
        _same(permission['originals']==originals and permission['status_scopes']==scopes
            and p['issued_at']<wire.u53(permission['until'])<=min(p['expires_at'],plan.assignment.payload['windows']['read_until'],source.read_until,bootstrap.payload['proof_until']))
        expires=min(expires,permission['until'],p['expires_at'])
        own_scope=index._authority(root,item,policy,budget)
        allowed[signer['key_id']]=scopes+[dict(scope_kind='authority',scope_id=own_scope)]
        obligations.append(index._obligation(signer,'authority',own_scope,p['revision'],2))
        consents.append(item)
    # Commit-time status documents are returned whole too. Their future bytes
    # need not be predicted by a pre-copy consent, but every contained scope
    # must be expressly returnable by that original issuer.
    for item in plan.statuses:
        permitted={(e['scope_kind'],e['scope_id']) for e in allowed[item.payload['signing_key']['key_id']]}
        if any((e['scope_kind'],e['scope_id']) not in permitted for e in item.payload['entries']):
            wire._fail('repair_status_disclosure')
    root_original=source.resources.originals['root'];read=source.resources.originals['read']
    for item,mask in ((root_original,10 if action=='challenge' else 2),(read,2),(bootstrap,10 if action=='challenge' else 2)):
        obligations.append(index._obligation(parties['owner']['signing_key'],'authority',
            index._authority(root,item,policy,budget),item.payload['revision'],mask))
        expires=min(expires,item.payload['expires_at'])
    obligations.extend(copy_source.additional_obligations(source,parties['owner'],policy,budget))
    expires=min(expires,*copy_source.additional_deadlines(source)) if copy_source.bound_source(source) else expires
    obligations.append(index._obligation(parties['owner']['signing_key'],'ack_slot',
        status.status_scope(root,'ack_slot',root_original.payload['ack_slot'],policy,budget),root_original.payload['revision'],2))
    obligations.append(index._obligation(parties['maintainer']['signing_key'],'assignment',
        status.status_scope(root,'assignment',dict(assignment_kind='maintenance.assignment',assignment_sha256=plan.assignment.ref.raw_sha256),policy,budget),0,2))
    target_scope=status.status_scope(root,'resource',custody.payload['resource'],policy,budget)
    allowed[parties['target']['signing_key']['key_id']]=[dict(scope_kind='resource',scope_id=target_scope)]
    obligations.append(index._obligation(parties['target']['signing_key'],'resource',target_scope,custody.payload['reservation_generation'],2))
    if type(current_statuses) not in (list,tuple) or not 1<=len(current_statuses)<=16:wire._fail('repair_status_missing')
    checked=[]
    def observe(item):
        checked.append(item)
        if on_observed is not None:on_observed(item)
    for entry in current_statuses:
        try:
            payload=wire.parse_new_wire(entry['raw'],policy,budget).value['payload'];issuer=payload['signing_key']['key_id']
            if issuer not in signers:wire._fail('repair_status_disclosure')
            status.authenticate_status_original(entry,expected_root=root,expected_signing_key=signers[issuer],at=at,
                allowed_scopes=allowed[issuer],policy=policy,budget=budget,on_authenticated=observe)
        except (KeyError,TypeError):denial=denial or 'repair_invalid_status'
        except wire.RepairWireError as error:denial=denial or error.code
    if len({s.ref for s in checked})!=len(checked):denial=denial or 'repair_duplicate_status'
    previous=(*source.statuses,*plan.statuses)
    try:empty._history_floors((*previous,*checked),previous=previous,current=checked)
    except wire.RepairWireError as error:denial=denial or error.code
    for need in obligations:
        rows=[e for item in checked if item.payload['signing_key']==need['signer'] for e in item.payload['entries']
            if (e['scope_kind'],e['scope_id'])==(need['scope_kind'],need['scope_id'])]
        if not rows:denial=denial or 'repair_status_missing'
        for entry in rows:
            if entry['status']=='revoked':denial=denial or 'repair_authority_revoked'
            elif entry['minimum_document_revision']>need['revision']:denial=denial or 'repair_status_revision'
            elif entry['operation_mask']&need['mask']!=need['mask']:denial=denial or 'repair_status_operation'
    if checked:expires=min(expires,*(item.payload['valid_until'] for item in checked))
    if at>=expires:denial=denial or 'repair_access_expired'
    return dict(expires_at=expires,consents=tuple(consents),statuses=tuple(checked),obligations=tuple(obligations),
        subject=owner_id,bootstrap=bootstrap,denial_code=denial)
