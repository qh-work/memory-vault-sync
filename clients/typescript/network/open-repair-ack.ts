/** A complete historical ACK-unbound input closure under its original custody.
 * This authenticates a past source assertion. It neither activates local space
 * nor changes current floors, grants live access or establishes physical custody.
 */
import {buildNewWire,parseNewWire,rawRef,objectFields,u53,RepairError} from './open-repair-wire.ts';
import type {RawRef,RepairPolicy,RepairBudget,LocalRawResolver} from './open-repair-wire.ts';
import {resolveHistoricalInputs} from './open-repair-history.ts';
import type {DraftHistoryInputs} from './open-repair-history.ts';
import {verifyAckResourceInputs} from './open-repair-resource.ts';
import type {AuthenticatedRepairOriginal,AuthenticatedAckResourceInputs} from './open-repair-resource.ts';
import {verifyAckOwnerBootstrapOriginal} from './open-repair-bootstrap.ts';
import type {AuthenticatedAckOwnerBootstrapInputs} from './open-repair-bootstrap.ts';
import {verifySourceNodeOriginal,verifyBoundedControlSignature,parseOriginalControl} from './open-repair-original.ts';
import type {VerifiedOriginalControl} from './open-repair-original.ts';
import {statusScope,verifyStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';

type Obj=Record<string,any>;
const ROLES=Object.freeze(['ack.root_authority','ack.read_grant','bootstrap.ack_owner','resource.ack_allocate',
  'resource.ack_offer','resource.ack_activation','resource.ack_active','source.descriptor','historical.status.ack_root',
  'historical.status.ack_read','historical.status.ack_owner_bootstrap','historical.status.ack_slot','historical.status.ack_resource']);
const CUSTODY_FIELDS=['schema_version','kind','signing_key','ack_slot','root_authority_ref','historical_manifest_ref',
  'resource_ref','stored_at','read_until','retain_until','state'];
export interface AckUnboundSourceEventOptions{
  readonly expectedAckSlot:unknown;readonly expectedOwner:unknown;readonly expectedTarget:unknown;
  readonly targetStorageEpoch:string;readonly limitPolicy:unknown;readonly policy:RepairPolicy;readonly budget:RepairBudget;
}
export interface AuthenticatedAckUnboundSourceEvent{
  readonly manifest:DraftHistoryInputs;readonly custody:AuthenticatedRepairOriginal;
  readonly resources:AuthenticatedAckResourceInputs;readonly bootstrap:AuthenticatedAckOwnerBootstrapInputs;
  readonly descriptor:VerifiedOriginalControl;readonly statuses:readonly AuthenticatedStatusOriginal[];
  readonly stored_at:number;readonly read_until:number;readonly retain_until:number;
}
function fail(code='repair_invalid_ack'):never{throw new RepairError(code);}
function mismatch():never{fail('repair_ack_mismatch');}
function fields(value:unknown,names:readonly string[]):Obj{try{return objectFields(value,names);}catch{fail();}}
function number(value:unknown):number{try{return u53(value);}catch{fail();}}
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));
}
function pattern(value:unknown,re:RegExp):string{if(typeof value!=='string'||re.exec(value)?.[0]!==value)fail();return value;}
function opaque(value:unknown):void{pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function dualId(value:unknown):Obj{const id=fields(value,['signing_key_id','encryption_key_id']);pattern(id.signing_key_id,/^ed25519_[0-9a-f]{64}$/);pattern(id.encryption_key_id,/^x25519_[0-9a-f]{64}$/);return id;}
function slot(value:unknown):Obj{
  const raw=fields(value,['root_key','slot_id','receipt_writer','grant_id']),root=fields(raw.root_key,['owner','root_kind','anchor_ref','owner_epoch','root_id']);
  dualId(root.owner);if(root.root_kind!=='ack_return')fail();const anchor=fields(root.anchor_ref,['namespace','key']);if(anchor.namespace!=='anchor')fail();pattern(anchor.key,/^[0-9a-f]{64}$/);
  opaque(root.owner_epoch);opaque(root.root_id);opaque(raw.slot_id);opaque(raw.grant_id);dualId(raw.receipt_writer);return raw;
}
function dualKey(value:unknown):Obj{const raw=fields(value,['signing_key','encryption_key']);for(const name of ['signing_key','encryption_key'])fields(raw[name],['schema_version','algorithm','key_id','public_key']);return raw;}
function meta(value:unknown):RawRef{const ref=rawRef(value);if(ref.namespace!=='meta')fail();return ref;}
function entry(value:unknown):Obj{const result=fields(value,['raw','ref']);return {raw:result.raw,ref:meta(result.ref)};}
function refKey(ref:RawRef):string{return `${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;}
function resourceShape(value:unknown):void{const raw=fields(value,['node_key_id','storage_epoch','lease_id','resource_id']);pattern(raw.node_key_id,/^ed25519_[0-9a-f]{64}$/);for(const name of ['storage_epoch','lease_id','resource_id'])opaque(raw[name]);}
function authenticateCustody(value:unknown,target:Obj,policy:RepairPolicy,budget:RepairBudget):AuthenticatedRepairOriginal{
  const input=entry(value),parsed=parseNewWire(input.raw,policy,budget),raw=parsed.raw;
  if(raw.length!==input.ref.size||budget.hash(raw)!==input.ref.raw_sha256)fail('repair_ref_mismatch');
  const signed=fields(parsed.value,['payload','proof']),payload=fields(signed.payload,CUSTODY_FIELDS);
  if(payload.schema_version!=='memory-vault-open-repair/v1'||payload.kind!=='ack.slot_custody'||payload.state!=='unbound')fail();
  slot(payload.ack_slot);meta(payload.root_authority_ref);meta(payload.historical_manifest_ref);resourceShape(payload.resource_ref);
  number(payload.stored_at);number(payload.read_until);number(payload.retain_until);
  if(!(payload.stored_at<payload.read_until&&payload.read_until<=payload.retain_until))fail();
  verifyBoundedControlSignature(payload,signed.proof,target.signing_key,budget);
  return Object.freeze({ref:input.ref,payload,get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
}

export function verifyAckUnboundSourceEvent(manifestEntry:unknown,resolver:LocalRawResolver,custodyEntry:unknown,
  options:AckUnboundSourceEventOptions):AuthenticatedAckUnboundSourceEvent{
  const args=fields(options,['expectedAckSlot','expectedOwner','expectedTarget','targetStorageEpoch','limitPolicy','policy','budget']);
  const policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const expected=buildNewWire({ack_slot:args.expectedAckSlot,owner:args.expectedOwner,target:args.expectedTarget,
    target_storage_epoch:args.targetStorageEpoch,limit_policy:args.limitPolicy},policy,budget).value as Obj;
  const expectedSlot=slot(expected.ack_slot),owner=dualKey(expected.owner),target=dualKey(expected.target);opaque(expected.target_storage_epoch);
  const custody=authenticateCustody(custodyEntry,target,policy,budget),event=custody.payload as Obj,at=event.stored_at;
  if(!same(event.ack_slot,expectedSlot))mismatch();
  const h=entry(manifestEntry);
  if(!same(event.historical_manifest_ref,h.ref))mismatch();
  const parsed=parseNewWire(h.raw,policy,budget),raw=parsed.raw;
  if(raw.length!==h.ref.size||budget.hash(raw)!==h.ref.raw_sha256)fail('repair_ref_mismatch');
  const manifest=resolveHistoricalInputs(raw,resolver,policy,budget),value=manifest.manifest.value as Obj;
  if(value.variant!=='ack_unbound'||manifest.predecessors.length!==0||!same(value.root_key,expectedSlot.root_key)||
      !same(value.ack_slot,expectedSlot)||!same(value.root_authority_ref,event.root_authority_ref))mismatch();
  if(manifest.roles.length!==ROLES.length)fail();const roles=new Map<string,Obj>();
  for(const row of manifest.roles){if(!ROLES.includes(row.role)||roles.has(row.role))fail();roles.set(row.role,row.original);}
  if(roles.size!==ROLES.length)fail();
  const original=(role:string):Obj=>{const found=roles.get(role)!;return {raw:found.raw,ref:found.ref};};
  const resources=verifyAckResourceInputs({allocate:original('resource.ack_allocate'),offer:original('resource.ack_offer'),
    root:original('ack.root_authority'),read:original('ack.read_grant'),activation:original('resource.ack_activation'),active:original('resource.ack_active')},
    {expectedAckSlot:expectedSlot,expectedOwner:owner,expectedTarget:target,targetStorageEpoch:expected.target_storage_epoch,policy,budget});
  const bootstrap=verifyAckOwnerBootstrapOriginal(original('bootstrap.ack_owner'),{root:original('ack.root_authority'),read:original('ack.read_grant')},
    {expectedAckSlot:expectedSlot,expectedOwner:owner,at,limitPolicy:expected.limit_policy,policy,budget});
  const node=original('source.descriptor');
  if(node.raw.length!==node.ref.size||budget.hash(node.raw)!==node.ref.raw_sha256)fail('repair_ref_mismatch');
  const descriptor=verifySourceNodeOriginal(node.raw,{expectedSigningKey:target.signing_key,expectedStorageEpoch:expected.target_storage_epoch,at,policy,budget});
  const r=resources.originals.root.payload as Obj,c=resources.originals.read.payload as Obj,g=bootstrap.originals.bootstrap.payload as Obj;
  const activation=resources.originals.activation.payload as Obj,active=resources.originals.active.payload as Obj;
  if(!same(event.root_authority_ref,resources.originals.root.ref)||!same(value.root_authority_ref,resources.originals.root.ref)||
      !same(event.resource_ref,active.resource)||event.resource_ref.node_key_id!==target.signing_key.key_id||event.resource_ref.storage_epoch!==expected.target_storage_epoch||
      g.issued_at>activation.issued_at||active.activated_at>at||(r.operation_mask&74)!==74||(c.operation_mask&2)!==2)mismatch();
  const readUntil=Math.min(r.windows.read_until,r.windows.retain_until,c.windows.read_until,c.windows.retain_until,
    active.windows.read_until,r.expires_at,c.expires_at,g.expires_at,g.probe_until,g.proof_until,g.upload_until);
  if(event.read_until>readUntil||event.retain_until>r.windows.retain_until||event.retain_until>active.windows.retain_until)mismatch();
  const expectedRoot=expectedSlot.root_key;
  const obligations:Obj[]=[
    {role:'historical.status.ack_root',kind:'authority',subject:{authority_kind:'ack.root_authority',authority_sha256:resources.originals.root.ref.raw_sha256},revision:r.revision,mask:74,signer:owner.signing_key},
    {role:'historical.status.ack_read',kind:'authority',subject:{authority_kind:'ack.read_grant',authority_sha256:resources.originals.read.ref.raw_sha256},revision:c.revision,mask:2,signer:owner.signing_key},
    {role:'historical.status.ack_owner_bootstrap',kind:'authority',subject:{authority_kind:'bootstrap.grant',authority_sha256:bootstrap.originals.bootstrap.ref.raw_sha256},revision:g.revision,mask:10,signer:owner.signing_key},
    {role:'historical.status.ack_slot',kind:'ack_slot',subject:expectedSlot,revision:r.revision,mask:66,signer:owner.signing_key},
    {role:'historical.status.ack_resource',kind:'resource',subject:active.resource,revision:active.reservation_generation,mask:66,signer:target.signing_key},
  ];
  for(const obligation of obligations)obligation.scope_id=statusScope(expectedRoot,obligation.kind,obligation.subject,policy,budget);
  const groups=new Map<string,{entry:Obj;signer:Obj;required:Obj[]}>();
  for(const obligation of obligations){
    const held=roles.get(obligation.role)!,identity=refKey(held.ref);
    let group=groups.get(identity);
    if(!group){group={entry:{raw:held.raw,ref:held.ref},signer:obligation.signer,required:[]};groups.set(identity,group);}
    if(!same(group.signer,obligation.signer))mismatch();
    group.required.push({scope_kind:obligation.kind,scope_id:obligation.scope_id,document_revision:obligation.revision,operation_mask:obligation.mask});
  }
  const statuses:AuthenticatedStatusOriginal[]=[];
  for(const group of groups.values()){
    const permitted=obligations.filter(item=>same(item.signer,group.signer));
    const allowed=permitted.map(item=>({scope_kind:item.kind,scope_id:item.scope_id}));
    // A bounded preview may only ADD obligations already derived above. It is
    // not authentication: verifyStatusOriginal subsequently checks the entire
    // signed original and refuses unknown disclosures/malformed entries.
    const preview=parseOriginalControl(group.entry.raw,policy,budget).value as Obj;
    const present=preview?.payload?.entries;
    if(Array.isArray(present))for(const candidate of present){
      if(candidate===null||typeof candidate!=='object'||Array.isArray(candidate))continue;
      const obligation=permitted.find(item=>item.kind===candidate.scope_kind&&item.scope_id===candidate.scope_id);
      if(obligation&&!group.required.some(item=>item.scope_kind===obligation.kind&&item.scope_id===obligation.scope_id))
        group.required.push({scope_kind:obligation.kind,scope_id:obligation.scope_id,document_revision:obligation.revision,operation_mask:obligation.mask});
    }
    statuses.push(verifyStatusOriginal(group.entry,{expectedRoot,expectedSigningKey:group.signer,at,allowedScopes:allowed,required:group.required,policy,budget}));
  }
  const revisions=new Map<string,string>(),scopeObservations=new Map<string,Obj[]>();
  for(const status of statuses){
    const payload=status.payload as Obj,issuer=payload.signing_key.key_id,revisionKey=issuer+':'+payload.revision;
    const prior=revisions.get(revisionKey);
    if(prior!==undefined&&prior!==status.canonical_sha256)fail('repair_status_conflict');
    revisions.set(revisionKey,status.canonical_sha256);
    for(const observation of payload.entries){
      const key=issuer+':'+observation.scope_kind+':'+observation.scope_id;
      const rows=scopeObservations.get(key)??[];rows.push({revision:payload.revision,entry:observation});scopeObservations.set(key,rows);
    }
  }
  for(const rows of scopeObservations.values()){
    rows.sort((a,b)=>a.revision-b.revision);let minimum=0,revoked=false;
    for(const row of rows){
      if(row.entry.minimum_document_revision<minimum)fail('repair_status_rollback');minimum=row.entry.minimum_document_revision;
      revoked=revoked||row.entry.status==='revoked';if(revoked)fail('repair_authority_revoked');
    }
  }
  return Object.freeze({manifest,custody,resources,bootstrap,descriptor,statuses:Object.freeze(statuses),stored_at:at,read_until:event.read_until,retain_until:event.retain_until});
}
