"""Exact original replica evidence for a durably received message or memory.

Reopening this local receipt verifies permissions at its recorded receipt time.
It grants no new network access and never extends an expired COPY/READ grant.
"""
from dataclasses import replace
from types import MappingProxyType, SimpleNamespace

import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_index as index
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import DEFAULT_POLICY, MAILBOX_WORKFLOW_LIMITS
from memory_vault_open_repair_mailbox_message_copy import (
    verify_mailbox_message_replica, verify_message_body, check_message_return)

SCHEMA = 'memory-vault-mailbox-replica-inbox/v1'


def message_replica_inbox_evidence(recovered, *, limits, received_at):
    from memory_vault_network_crypto import b64url
    children=recovered.proof.manifest.value['children']
    def reference(role):
        values=[v['ref'] for v in children if v['role']==role]
        if len(values)!=1:wire._fail('repair_proof_mismatch')
        return values[0]
    expected=recovered.context['expected'];bound=recovered.context['bound']
    refs={wire.raw_ref(v['ref']) for values in recovered.replica['entries'].values() for v in values}
    refs.update(wire.raw_ref(reference(role)) for role in ('replica.manifest','replica.custody','return.owner','return.source','return.maintainer','return.sender'))
    originals={ref:recovered.originals[ref] for ref in refs}
    originals.update((item.ref,item.raw) for item in (*recovered.current_statuses,*recovered.archive_statuses))
    return dict(schema_version=SCHEMA,received_at=received_at,slot=expected['slot'],sender=expected['sender'],
        source=expected['source'],target=expected['target'],maintainer=expected['maintainer'],
        target_storage_epoch=recovered.proof.handle.payload['target_storage_epoch'],envelope_ref=bound['expected_envelope_ref'],limits=limits,
        manifest_ref=reference('replica.manifest'),custody_ref=reference('replica.custody'),
        consent_refs={name:reference('return.'+name) for name in ('owner','source','maintainer','sender')},
        originals=[dict(ref=ref.as_dict(),raw_base64url=b64url(raw)) for ref,raw in sorted(originals.items(),key=lambda v:(v[0].namespace,v[0].key))],
        status_refs=[item.ref.as_dict() for item in recovered.current_statuses],
        archive_status_refs=[item.ref.as_dict() for item in recovered.archive_statuses])


def verify_message_replica_inbox_evidence(evidence, envelope, *, owner, encryption_identity, staged_at):
    from memory_vault_network_crypto import object_fields, unb64url
    from memory_vault_open_repair_client import _verify_mailbox_admission_metadata, AckOwnerRecoveryClient
    value=object_fields(evidence,{'schema_version','received_at','slot','sender','source','target','maintainer',
        'target_storage_epoch','envelope_ref','limits','manifest_ref','custody_ref','consent_refs','originals','status_refs','archive_status_refs'})
    if value['schema_version']!=SCHEMA:wire._fail('repair_invalid_context')
    at=wire.u53(value['received_at'])
    if at>wire.u53(staged_at):wire._fail('repair_invalid_context')
    policy=replace(DEFAULT_POLICY,max_signature_checks=512);budget=wire.RepairBudget(policy)
    limits=wire.build_new_wire(value['limits'],policy,budget).value;bootstrap._limits(limits)
    if any(limits[name]>maximum for name,maximum in MAILBOX_WORKFLOW_LIMITS.items()):wire._fail('repair_over_budget')
    if (type(value['originals']) is not list or not 1<=len(value['originals'])<=limits['max_proof_items']
            or type(value['status_refs']) is not list or not 1<=len(value['status_refs'])<=16
            or type(value['archive_status_refs']) is not list or len(value['archive_status_refs'])>32):wire._fail('repair_over_budget')
    resolver=wire.LocalRawResolver(policy,budget);originals={};total=len(envelope)
    for item in value['originals']:
        object_fields(item,{'ref','raw_base64url'});ref=wire.raw_ref(item['ref'])
        if ref.namespace!='meta' or ref in originals or ref.size>policy.max_document_bytes:wire._fail('repair_ref_mismatch')
        raw=unb64url(item['raw_base64url'],maximum=policy.max_document_bytes);total+=len(raw)
        if total>limits['max_proof_bytes']:wire._fail('repair_over_budget')
        if resolver.put(ref.namespace,ref.key,raw).ref!=ref:wire._fail('repair_ref_mismatch')
        originals[ref]=raw
    def entry(reference):
        ref=wire.raw_ref(reference)
        if ref not in originals:wire._fail('repair_original_missing')
        return dict(raw=originals[ref],ref=ref.as_dict())
    context=dict(expected_slot=value['slot'],expected_owner=owner,expected_sender=value['sender'],expected_source=value['source'],
        source_storage_epoch=value['slot']['writer_storage_epoch'],expected_maintainer=value['maintainer'],expected_target=value['target'],
        target_storage_epoch=value['target_storage_epoch'],expected_envelope_ref=value['envelope_ref'])
    replica=verify_mailbox_message_replica(entry(value['manifest_ref']),resolver,entry(value['custody_ref']),
        **context,limit_policy=limits,policy=policy,budget=budget)
    if replica['custody'].payload['stored_at']>at:wire._fail('repair_access_expired')
    return_context={k:v for k,v in context.items() if k not in ('expected_slot','expected_envelope_ref','source_storage_epoch')}
    wire.object_fields(value['consent_refs'],{'owner','source','maintainer','sender'})
    permission=check_message_return(replica,{name:entry(ref) for name,ref in value['consent_refs'].items()},**return_context,
        current_statuses=[entry(ref) for ref in value['status_refs']],at=at,action='child',policy=policy,budget=budget)
    if permission['denial_code']:wire._fail(permission['denial_code'])
    # Reauthenticate retained observations without treating them as current.
    from memory_vault_open_repair_status import authenticate_status_original
    parties=(owner,value['sender'],value['source'],value['maintainer'],value['target'])
    signers={keys['signing_key']['key_id']:keys['signing_key'] for keys in parties};archive=[]
    for reference in value['archive_status_refs']:
        saved=entry(reference);p=wire.parse_new_wire(saved['raw'],policy,budget).value['payload'];signer=p['signing_key']
        if signers.get(signer['key_id'])!=signer or p['issued_at']>at:wire._fail('repair_status_disclosure')
        archive.append(authenticate_status_original(saved,expected_root=value['slot']['root_key'],expected_signing_key=signer,
            at=p['issued_at'],allowed_scopes=[dict(scope_kind=e['scope_kind'],scope_id=e['scope_id']) for e in p['entries']],policy=policy,budget=budget))
    empty._history_floors((*archive,*permission['statuses']),previous=archive,current=permission['statuses'])
    AckOwnerRecoveryClient._floors(SimpleNamespace(subject=owner),archive,permission['statuses'],
        [dict(item,kind=item['scope_kind']) for item in permission['obligations']])
    checked=_verify_mailbox_admission_metadata(replica['source']['message_member'],expected_slot=value['slot'],
        expected_signing_key=value['source']['signing_key'],expected_owner=owner,expected_sender=value['sender'],expected_target=value['source'],
        encryption_identity=encryption_identity,read_original=lambda ref:entry(ref)['raw'],at=at,limit_policy=limits,policy=policy,budget=budget)
    body=verify_message_body(dict(raw=envelope,ref=value['envelope_ref']),checked['core']['envelope_ref'],policy,budget)
    member_originals=dict(checked['originals']);member_originals[(body.ref.namespace,body.ref.key)]=index._entry(body)
    return dict(checked,envelope=body.raw,originals=MappingProxyType(member_originals),current_statuses=permission['statuses'])
