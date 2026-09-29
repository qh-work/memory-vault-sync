"""Private normalization of fully authenticated ACK copy source generations.

An empty copy retains the original binding and both historical generations.
The copy assignment still grants only COPY/READ/RETAIN, never receipt admission.
No caller-provided object is accepted as a pre-authenticated source.
"""
from dataclasses import dataclass

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_wire as wire


@dataclass(frozen=True)
class _EmptyCopySource:
    event: object

    @property
    def manifest(self):return self.event.manifest
    @property
    def custody(self):return self.event.custody
    @property
    def resources(self):return self.event.predecessor.resources
    @property
    def bootstrap(self):return self.event.predecessor.bootstrap
    @property
    def stored_at(self):return self.event.stored_at
    @property
    def read_until(self):return self.event.read_until
    @property
    def retain_until(self):return self.event.retain_until
    @property
    def statuses(self):
        rows={item.ref:item for item in (*self.event.predecessor.statuses,*self.event.statuses)}
        return tuple(rows.values())


def authenticate_source(manifest_entry,resolver,custody_entry,*,source_state,bound,**options):
    if source_state=='unbound':
        if bound:wire._fail('repair_copy_scope')
        return ack.verify_ack_unbound_source_event(manifest_entry,resolver,custody_entry,**options)
    if source_state!='empty':wire._fail('repair_copy_scope')
    wire.object_fields(bound,{'expected_receipt_writer','expected_message_id','expected_envelope_ref'})
    return _EmptyCopySource(empty.verify_ack_empty_source_event(
        manifest_entry,resolver,custody_entry,**options,**bound))


def bound_source(source):return isinstance(source,_EmptyCopySource)


def source_scope(source):
    root=source.resources.originals['root']
    if bound_source(source):
        return dict(kind='ack_empty',ack_slot=root.payload['ack_slot'],
            grant_ref=source.event.authorities.originals['write'].ref.as_dict(),
            binding_ref=source.event.binding.ref.as_dict())
    return dict(kind='ack_unbound',ack_slot=root.payload['ack_slot'],root_authority_ref=root.ref.as_dict())


def source_custody_role(source):
    return 'ack.empty_custody' if bound_source(source) else 'ack.slot_custody'


def source_histories(source,outer_entry):
    """Every original history keeps its own exact reference and child edges."""
    if not bound_source(source):return (('history.ack_unbound',outer_entry,source.manifest),)
    prior=[item.original for item in source.manifest.roles if item.role=='history.ack_unbound']
    if len(prior)!=1:wire._fail('repair_copy_commit_mismatch')
    item=prior[0]
    return (('history.ack_empty',outer_entry,source.manifest),
        ('history.ack_unbound',dict(raw=item.raw,ref=item.ref.as_dict()),source.event.predecessor.manifest))


def source_manifests(source):
    return (source.manifest,source.event.predecessor.manifest) if bound_source(source) else (source.manifest,)


def bootstrap_refs(source):
    refs=[source.bootstrap.originals['bootstrap'].ref]
    if bound_source(source):refs.append(source.event.authorities.originals['bootstrap'].ref)
    return [item.as_dict() for item in sorted(refs,key=history._ref_tuple)]


def additional_deadlines(source):
    if not bound_source(source):return ()
    write=source.event.authorities.originals['write'].payload
    bootstrap=source.event.authorities.originals['bootstrap'].payload
    return (write['expires_at'],write['windows']['read_until'],write['windows']['copy_until'],
        write['windows']['retain_until'],bootstrap['expires_at'],bootstrap['probe_until'],
        bootstrap['proof_until'],bootstrap['upload_until'])


def additional_obligations(source,owner,policy,budget):
    if not bound_source(source):return ()
    root=source.resources.originals['root'].payload['ack_slot']['root_key']
    # Retaining a bound slot never revives a revoked write or offer grant. These
    # checks preserve the existing bound-source obligations without authorizing
    # the replacement to ADMIT a receipt through its COPY-only assignment.
    return tuple(index._obligation(owner['signing_key'],'authority',
        index._authority(root,item,policy,budget),item.payload['revision'],mask)
        for item,mask in ((source.event.authorities.originals['write'],1),
                          (source.event.authorities.originals['bootstrap'],11)))
