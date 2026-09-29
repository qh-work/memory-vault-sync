"""Whole-original authority for an unbound ACK replica application commit.

The returned observations must be retained before a caller acts on denial_code.
This module does not reserve storage, persist bytes, advertise or serve a replica.
"""
from dataclasses import dataclass

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS
from memory_vault_open_repair_copy_resources import INTENT_FIELDS

DISCLOSURE_FIELDS = resource.COMMON | frozenset('issued_at expires_at consent_id revision variant root_key assignment_ref source_custody_ref historical_manifest_ref target target_storage_epoch disclosure'.split())


def _same(value):
    if not value:wire._fail('repair_copy_authority_mismatch')


def source_inventory(source, reservation, policy, budget):
    rows = {}
    for role, item in [(r.role,r.original) for r in source.manifest.roles] + [
            ('ack.slot_custody',source.custody),('copy.reservation_consent',reservation)]:
        value = wire.parse_new_wire(item.raw,policy,budget).value
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


def verify_unbound_copy(manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,assignment_entry,
        reservation_entry,owner_disclosure_entry,source_disclosure_entry,*,expected_ack_slot,expected_owner,
        expected_source,source_storage_epoch,expected_maintainer,expected_target,target_storage_epoch,
        current_statuses,at,limit_policy,policy,budget,on_observed=None):
    wire._context(policy,budget);at=wire.u53(at)
    context=wire.build_new_wire(dict(owner=expected_owner,source=expected_source,maintainer=expected_maintainer,
        target=expected_target),policy,budget).value
    ids={name:resource._dual_key(value,budget) for name,value in context.items()}
    source=ack.verify_ack_unbound_source_event(manifest_entry,resolver,custody_entry,
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
        and intent['scope']==dict(kind='ack_unbound',ack_slot=slot,root_authority_ref=root.ref.as_dict())
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
        and m['resource']==o['resource'] and m['bootstrap_grant_refs']==[bootstrap.ref.as_dict()]
        and m['budget']==o['budget'] and m['windows']==o['windows']
        and all(value<=m['expires_at'] for value in m['windows'].values())
        and m['expires_at']<=min(root.payload['expires_at'],read.payload['expires_at'],read.payload['windows']['read_until'],
            bootstrap.payload['expires_at'],bootstrap.payload['probe_until'],bootstrap.payload['proof_until'],bootstrap.payload['upload_until']))
    for p in (a,m):
        _same(p['target_node_key_id']==ids['target']['signing_key_id'] and p['target_storage_epoch']==target_storage_epoch)
    reservation=index._signed(reservation_entry,context['owner']['signing_key'],'ack.copy_reservation_consent',CONSENT_FIELDS,policy,budget)
    c=reservation.payload;index._timed(c,at);resource._opaque(c['consent_id']);wire.u53(c['revision'],1)
    disclosure=resource._fields(c['reservation_disclosure'],{'intent_sha256','until'})
    maximum=min(source.read_until,source.retain_until,active.payload['windows']['copy_until'],
        root.payload['expires_at'],root.payload['windows']['copy_until'],c['expires_at'],intent['windows']['copy_until'])
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
