"""Private normalization of fully authenticated ACK copy source generations.

Bound copies retain the original binding and every historical generation.
The copy assignment still grants only COPY/READ/RETAIN, never receipt admission.
No caller-provided object is accepted as a pre-authenticated source.
"""
from dataclasses import dataclass

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_wire as wire


@dataclass(frozen=True)
class _EmptyCopySource:
    event: object

    @property
    def empty_event(self):return self.event
    @property
    def source_state(self):return 'empty'

    @property
    def manifest(self):return self.event.manifest
    @property
    def custody(self):return self.event.custody
    @property
    def resources(self):return self.empty_event.predecessor.resources
    @property
    def bootstrap(self):return self.empty_event.predecessor.bootstrap
    @property
    def stored_at(self):return self.event.stored_at
    @property
    def read_until(self):return self.event.read_until
    @property
    def retain_until(self):return self.event.retain_until
    @property
    def statuses(self):
        rows={item.ref:item for event in source_events(self) for item in event.statuses}
        return tuple(rows.values())


@dataclass(frozen=True)
class _OccupiedCopySource(_EmptyCopySource):
    receipt_writer: object

    @property
    def empty_event(self):return self.event.predecessor
    @property
    def source_state(self):return 'occupied'
    @property
    def custody(self):return self.event.commit


def authenticate_source(manifest_entry,resolver,custody_entry,*,source_state,bound,**options):
    if source_state=='unbound':
        if bound:wire._fail('repair_copy_scope')
        return ack.verify_ack_unbound_source_event(manifest_entry,resolver,custody_entry,**options)
    if source_state not in ('empty','occupied'):wire._fail('repair_copy_scope')
    wire.object_fields(bound,{'expected_receipt_writer','expected_message_id','expected_envelope_ref'})
    if source_state=='occupied':
        event=occupied.verify_ack_occupied_source_event(manifest_entry,resolver,custody_entry,**options,**bound)
        writer=wire.build_new_wire(bound['expected_receipt_writer'],options['policy'],options['budget']).value
        return _OccupiedCopySource(event,writer)
    return _EmptyCopySource(empty.verify_ack_empty_source_event(
        manifest_entry,resolver,custody_entry,**options,**bound))


def bound_source(source):return isinstance(source,_EmptyCopySource)


def occupied_source(source):return isinstance(source,_OccupiedCopySource)


def source_events(source):
    if not bound_source(source):return (source,)
    events=(source.empty_event,source.empty_event.predecessor)
    return (source.event,*events) if occupied_source(source) else events


def history_role(state):
    return 'history.ack_occupied_inputs' if state=='occupied' else 'history.ack_'+state


def source_scope(source):
    root=source.resources.originals['root']
    if bound_source(source):
        value=dict(kind='ack_'+source.source_state,ack_slot=root.payload['ack_slot'],
            grant_ref=source.empty_event.authorities.originals['write'].ref.as_dict(),
            binding_ref=source.empty_event.binding.ref.as_dict())
        if occupied_source(source):value.update(receipt_ref=source.event.inputs['receipt'].ref.as_dict(),
            original_ack_commit_ref=source.event.commit.ref.as_dict())
        return value
    return dict(kind='ack_unbound',ack_slot=root.payload['ack_slot'],root_authority_ref=root.ref.as_dict())


def source_custody_role(source):
    if occupied_source(source):return 'ack.commit'
    return 'ack.empty_custody' if bound_source(source) else 'ack.slot_custody'


def source_histories(source,outer_entry):
    """Every original history keeps its own exact reference and child edges."""
    if not bound_source(source):return (('history.ack_unbound',outer_entry,source.manifest),)
    events=source_events(source)
    roles=(('history.ack_occupied_inputs','history.ack_empty','history.ack_unbound')
        if occupied_source(source) else ('history.ack_empty','history.ack_unbound'))
    rows=[(roles[0],outer_entry,events[0].manifest)]
    for i,role in enumerate(roles[1:],1):
        prior=[item.original for item in events[i-1].manifest.roles if item.role==role]
        if len(prior)!=1:wire._fail('repair_copy_commit_mismatch')
        item=prior[0]
        rows.append((role,dict(raw=item.raw,ref=item.ref.as_dict()),events[i].manifest))
    return tuple(rows)


def source_manifests(source):
    return tuple(event.manifest for event in source_events(source))


def resolve_occupied_stage_originals(children,resolver,policy,budget):
    """Expand exact staged history bytes, without granting any authority.

    The original signed source and copy authorities must still be verified.
    The three advertised manifests must be the same transitive originals;
    unrelated parallel histories cannot supply replacement metadata.
    """
    histories={}
    for child in children:
        role=child['role']
        if role in ('history.ack_unbound','history.ack_empty','history.ack_occupied_inputs'):
            if role in histories:wire._fail('repair_copy_upload_mismatch')
            histories[role]=dict(raw=child['raw'],ref=child['ref'])
    if len(histories)!=3:wire._fail('repair_copy_upload_mismatch')
    outer=histories['history.ack_occupied_inputs']
    tree=history.resolve_historical_inputs(outer['raw'],resolver,policy,budget)
    pending=[tree];seen=set();nested={}
    while pending:
        item=pending.pop();variant=item.manifest.value['variant']
        if variant in seen:wire._fail('repair_copy_upload_mismatch')
        seen.add(variant)
        for row in item.roles:
            original=row.original;ref=original.ref
            if resolver.put(ref.namespace,ref.key,original.raw).ref!=ref:wire._fail('repair_ref_mismatch')
            if row.role in histories:
                entry=dict(raw=original.raw,ref=ref.as_dict())
                if row.role in nested and nested[row.role]!=entry:wire._fail('repair_copy_upload_mismatch')
                nested[row.role]=entry
        pending.extend(item.predecessors)
    if (seen!={'ack_unbound','ack_empty','ack_occupied_inputs'}
            or set(nested)!={'history.ack_empty','history.ack_unbound'}
            or any(histories[role]!=entry for role,entry in nested.items())):
        wire._fail('repair_copy_upload_mismatch')


def bootstrap_refs(source):
    refs=[source.bootstrap.originals['bootstrap'].ref]
    if bound_source(source):refs.append(source.empty_event.authorities.originals['bootstrap'].ref)
    return [item.as_dict() for item in sorted(refs,key=history._ref_tuple)]


def additional_deadlines(source):
    if not bound_source(source):return ()
    if occupied_source(source):
        consent=source.event.inputs['disclosure'].payload
        return (consent['expires_at'],consent['consent_until'],consent['bootstrap_return']['until'])
    write=source.empty_event.authorities.originals['write'].payload
    bootstrap=source.empty_event.authorities.originals['bootstrap'].payload
    return (write['expires_at'],write['windows']['read_until'],write['windows']['copy_until'],
        write['windows']['retain_until'],bootstrap['expires_at'],bootstrap['probe_until'],
        bootstrap['proof_until'],bootstrap['upload_until'])


def additional_obligations(source,owner,policy,budget):
    if not bound_source(source):return ()
    root=source.resources.originals['root'].payload['ack_slot']['root_key']
    if occupied_source(source):
        # A saved receipt does not need a new ADMIT. Its original B disclosure
        # must still permit READ; separate explicit consents authorize copying.
        consent=source.event.inputs['disclosure']
        return (index._obligation(source.receipt_writer['signing_key'],'authority',
            index._authority(root,consent,policy,budget),consent.payload['revision'],2),)
    # Retaining a bound slot never revives a revoked write or offer grant. These
    # checks preserve the existing bound-source obligations without authorizing
    # the replacement to ADMIT a receipt through its COPY-only assignment.
    return tuple(index._obligation(owner['signing_key'],'authority',
        index._authority(root,item,policy,budget),item.payload['revision'],mask)
        for item,mask in ((source.event.authorities.originals['write'],1),
                          (source.event.authorities.originals['bootstrap'],11)))
