/** An index observation becomes usable only after an independent owner READ. */
import {performance} from 'node:perf_hooks';
import {canonicalBytes,document,sha256} from './crypto.ts';
import {verifyNode} from './open-control.ts';
import type {SignedNode} from './open-control.ts';
import {asDual,verifyDocument,verifyIndexLease} from './open-provider.ts';
import {OpenProviderClient} from './open-provider-client.ts';
import {LookupBudget} from './open-routing.ts';
import {AckOwnerRecoveryClient} from './open-repair-client.ts';
import type {AckOwnerRecoverOccupiedOptions,RecoveredAckOwnerOccupiedProof} from './open-repair-client.ts';
import {RepairError,objectFields} from './open-repair-wire.ts';
type Obj=Record<string,any>;
const same=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
const clock=()=>performance.now()/1000;
function fail(code:string):never{throw new RepairError(code);}
export interface DiscoveredAckOptions extends Omit<AckOwnerRecoverOccupiedOptions,'targetNodeEntry'>{
  readonly expectedDirectoryNode:SignedNode;readonly expectedDirectory:unknown;readonly expectedSourceEpoch:string;
}
export interface DiscoveredAckReceipt{readonly state:'usable';readonly recovery:RecoveredAckOwnerOccupiedProof;
  readonly fact:Obj;readonly index_lease:Obj;readonly directory:SignedNode;readonly source_node:SignedNode;}
export class DiscoveredAckRecoveryClient{
  readonly provider:OpenProviderClient;readonly recovery:AckOwnerRecoveryClient;
  constructor(provider:OpenProviderClient,recovery:AckOwnerRecoveryClient){
    if(!(provider instanceof OpenProviderClient)||!(recovery instanceof AckOwnerRecoveryClient))fail('repair_invalid_context');
    this.provider=provider;this.recovery=recovery;
  }
  async recover(value:DiscoveredAckOptions):Promise<DiscoveredAckReceipt>{
    const required=['expectedDirectoryNode','expectedDirectory','expectedSourceEpoch','expectedTarget','expectedAckSlot',
      'rootEntry','readEntry','bootstrapEntry','expectedReceiptWriter','expectedMessageId','expectedEnvelopeRef'];
    const args=objectFields(value,[...required,...['knownStatuses','archiveStatuses','timeout'].filter(n=>Object.hasOwn(value,n))]) as Obj;
    const timeout=args.timeout??30;
    if(typeof timeout!=='number'||!Number.isFinite(timeout)||timeout<=0||timeout>60)fail('repair_invalid_deadline');
    const deadline=clock()+timeout;
    const held=document(canonicalBytes({directory:args.expectedDirectory,target:args.expectedTarget,
      slot:args.expectedAckSlot,epoch:args.expectedSourceEpoch}),65536) as Obj;
    asDual(held.directory);asDual(held.target);
    if(!same(held.slot.root_key.owner,asDual(this.provider.subject)))fail('repair_index_owner_mismatch');
    const directory=document(canonicalBytes(args.expectedDirectoryNode),4096) as SignedNode,node=verifyNode(directory);
    if(!same(node.signing_key,held.directory.signing_key)||node.status!=='active'||!node.roles.includes('directory'))fail('repair_index_directory_mismatch');
    const budget=new LookupBudget({maximum_seconds:Math.min(timeout,10)});
    const target=await this.provider.proveTarget(directory,budget),descriptor=verifyDocument(target,'provider.target');
    if(!same(descriptor.signing_key,held.directory.signing_key)||!same(descriptor.targetEncryptionKey,held.directory.encryption_key)||
      descriptor.storage_epoch!==node.storage_epoch)fail('repair_index_directory_mismatch');
    const ref=held.slot.root_key.anchor_ref,found=await this.provider.findAt(directory,ref,{budget,maximum_candidates:8});
    let selected:Obj|undefined,observations:Obj[]=[];
    for(const candidate of found.candidates){
      const source=verifyNode(candidate.node),proven=verifyDocument(candidate.target,'provider.target');
      if(!same(source.signing_key,held.target.signing_key)||source.storage_epoch!==held.epoch||source.status!=='active'||
        !same(proven.signing_key,held.target.signing_key)||!same(proven.targetEncryptionKey,held.target.encryption_key)||proven.storage_epoch!==held.epoch)continue;
      const matches=[];
      for(const item of candidate.facts){
        if(!same(item.directory,directory))continue;
        const fact=verifyDocument(item.fact,'provider.fact');verifyIndexLease(item.index_lease,{fact:item.fact,node:directory});
        if(same(fact.ref,ref)&&fact.status==='active'&&same(fact.signing_key,held.target.signing_key)&&fact.storage_epoch===held.epoch)matches.push(item);
      }
      if(matches.length){selected=candidate;observations=matches;break;}
    }
    if(!selected)fail('repair_index_not_observed');
    const remaining=deadline-clock();if(remaining<=0)fail('repair_access_expired');
    const raw=canonicalBytes(selected.node),digest=sha256(raw);
    const recovered=await this.recovery.recoverOccupied(selected.node.payload.base_url,{
      targetNodeEntry:{raw,ref:{namespace:'meta',key:digest,raw_sha256:digest,size:raw.length}},
      expectedTarget:held.target,expectedAckSlot:held.slot,rootEntry:args.rootEntry,readEntry:args.readEntry,
      bootstrapEntry:args.bootstrapEntry,expectedReceiptWriter:args.expectedReceiptWriter,expectedMessageId:args.expectedMessageId,
      expectedEnvelopeRef:args.expectedEnvelopeRef,knownStatuses:args.knownStatuses??[],archiveStatuses:args.archiveStatuses??[],timeout:remaining});
    if(clock()>=deadline)fail('repair_access_expired');
    verifyNode(selected.node);verifyNode(directory);
    if(Math.floor(Date.now()/1000)>=Math.min(recovered.source.read_until,recovered.source.retain_until,
      recovered.proof.handle.payload.expires_at as number,...recovered.current_statuses.map(s=>s.payload.valid_until as number)))fail('repair_access_expired');
    const custody='ack_'+recovered.source.commit.ref.raw_sha256;
    for(const item of observations){
      const fact=verifyDocument(item.fact,'provider.fact');verifyIndexLease(item.index_lease,{fact:item.fact,node:directory});
      if(fact.custody_id===custody&&this.provider.factCurrent(item.fact)){
        if(clock()>=deadline)fail('repair_access_expired');
        return Object.freeze({state:'usable',recovery:recovered,fact:item.fact,index_lease:item.index_lease,directory,source_node:selected.node});
      }
    }
    fail('repair_index_custody_mismatch');
  }
}
