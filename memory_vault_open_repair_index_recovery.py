"""An independent owner discovers R at D and actually recovers the ACK receipt.

A directory lease is only an observation. USABLE requires a new owner READ
exchange and the exact occupied commit named by the chosen provider fact.
"""
import asyncio
from dataclasses import dataclass
import hashlib
import math
import time
from types import MappingProxyType

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document
from memory_vault_open_control import verify_node
import memory_vault_open_provider as provider
from memory_vault_open_provider_client import OpenProviderClient
from memory_vault_open_routing import LookupBudget
from memory_vault_open_repair_client import AckOwnerRecoveryClient
import memory_vault_open_repair_history as history
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire


def _fail(code):
    wire._fail(code)


@dataclass(frozen=True,slots=True)
class DiscoveredAckReceipt:
    state: str
    recovery: object
    fact: object
    index_lease: object
    directory: object
    source_node: object
    metrics: object


class DiscoveredAckRecoveryClient:
    def __init__(self, provider_client, recovery_client):
        if type(provider_client) is not OpenProviderClient or type(recovery_client) is not AckOwnerRecoveryClient:
            _fail('repair_invalid_context')
        if provider_client.subject != recovery_client.subject:
            _fail('repair_index_owner_mismatch')
        self.provider,self.recovery=provider_client,recovery_client

    async def recover(self, *, expected_directory_node, expected_directory, expected_target,
            expected_source_epoch, expected_ack_slot, root_entry, read_entry, bootstrap_entry,
            expected_receipt_writer, expected_message_id, expected_envelope_ref,
            known_statuses=(), archive_statuses=(), lookup_budget=None, timeout=30):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            _fail('repair_invalid_deadline')
        deadline=time.monotonic()+timeout
        policy=self.recovery.policy
        local=wire.RepairBudget(policy)
        expected=wire.build_new_wire(dict(directory=expected_directory,target=expected_target,slot=expected_ack_slot,
            epoch=expected_source_epoch),policy,local).value
        resource._dual_key(expected['directory'],local);resource._dual_key(expected['target'],local)
        resource._opaque(expected['epoch'])
        history._slot(expected['slot'],expected['slot']['root_key'],ack=True)
        if expected['slot']['root_key']['owner'] != provider.as_dual(self.recovery.subject):
            _fail('repair_index_owner_mismatch')
        directory=document(canonical_bytes(expected_directory_node),maximum=4096)
        node=verify_node(directory,now=self.recovery._now())
        if (node['signing_key'] != expected['directory']['signing_key']
                or node['status']!='active' or 'directory' not in node['roles']):
            _fail('repair_index_directory_mismatch')
        if lookup_budget is None:
            lookup_budget=LookupBudget(maximum_seconds=min(timeout,10))
        elif type(lookup_budget) is not LookupBudget:
            _fail('repair_invalid_context')
        # This is the same live routing budget, not a fresh budget per page.
        lookup_budget.deadline=min(lookup_budget.deadline,lookup_budget.clock()+max(0,deadline-time.monotonic()))
        lookup_budget.check()
        target=await self.provider.prove_target(directory,lookup_budget)
        descriptor=provider.verify_document(target,'provider.target',now=self.recovery._now())
        if (descriptor['signing_key'] != expected['directory']['signing_key']
                or descriptor['targetEncryptionKey'] != expected['directory']['encryption_key']
                or descriptor['storage_epoch'] != node['storage_epoch']):
            _fail('repair_index_directory_mismatch')
        ref=expected['slot']['root_key']['anchor_ref']
        found=await self.provider.find_at(directory,ref,lookup_budget,maximum_candidates=8)
        wanted=None
        for candidate in found['candidates']:
            raw=verify_node(candidate['node'],now=self.recovery._now())
            proven=provider.verify_document(candidate['target'],'provider.target',now=self.recovery._now())
            if (raw['signing_key'] != expected['target']['signing_key'] or raw['storage_epoch'] != expected['epoch']
                    or raw['status']!='active' or proven['signing_key'] != expected['target']['signing_key']
                    or proven['targetEncryptionKey'] != expected['target']['encryption_key']
                    or proven['storage_epoch'] != expected['epoch']):
                continue
            observations=[]
            for item in candidate['facts']:
                if item['directory'] != directory:
                    continue
                fact=provider.verify_document(item['fact'],'provider.fact',now=self.recovery._now())
                provider.verify_index_lease(item['index_lease'],fact=item['fact'],node=directory,now=self.recovery._now())
                if (fact['ref']==ref and fact['status']=='active' and fact['signing_key']==expected['target']['signing_key']
                        and fact['storage_epoch']==expected['epoch']):
                    observations.append(item)
            if observations:
                wanted=(candidate,observations)
                break
        if wanted is None:
            _fail('repair_index_not_observed')
        candidate,observations=wanted
        remaining=deadline-time.monotonic()
        if remaining<=0:
            _fail('repair_access_expired')
        raw=canonical_bytes(candidate['node']);digest=hashlib.sha256(raw).hexdigest()
        recovered=await asyncio.to_thread(self.recovery.recover_occupied,candidate['node']['payload']['base_url'],
            target_node_entry=dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw))),
            expected_target=expected['target'],expected_ack_slot=expected['slot'],root_entry=root_entry,read_entry=read_entry,
            bootstrap_entry=bootstrap_entry,expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref,known_statuses=known_statuses,archive_statuses=archive_statuses,timeout=remaining)
        if time.monotonic()>=deadline:
            _fail('repair_access_expired')
        # Revalidate all observation windows after the actual source read.
        verify_node(candidate['node'],now=self.recovery._now())
        verify_node(directory,now=self.recovery._now())
        if self.recovery._now()>=min(recovered.source.read_until,recovered.source.retain_until,
                recovered.proof.handle.payload['expires_at'],*(item.payload['valid_until'] for item in recovered.current_statuses)):
            _fail('repair_access_expired')
        custody='ack_'+recovered.source.commit.ref.raw_sha256
        for item in observations:
            fact=provider.verify_document(item['fact'],'provider.fact',now=self.recovery._now())
            provider.verify_index_lease(item['index_lease'],fact=item['fact'],node=directory,now=self.recovery._now())
            if fact['custody_id']==custody and self.provider._fact_current(item['fact']):
                snapshot=wire.build_new_wire(dict(fact=item['fact'],lease=item['index_lease'],directory=directory,node=candidate['node']),policy,local).value
                metrics=MappingProxyType(dict(discovery=self.provider._metrics(lookup_budget),recovery=dict(recovered.metrics)))
                if time.monotonic()>=deadline:
                    _fail('repair_access_expired')
                return DiscoveredAckReceipt('usable',recovered,snapshot['fact'],snapshot['lease'],snapshot['directory'],snapshot['node'],metrics)
        _fail('repair_index_custody_mismatch')
