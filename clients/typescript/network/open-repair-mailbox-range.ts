/** Slot-bound depth-16 prefix commitments, not a grant or network authority. */
import {buildNewWire,objectFields,u53,RepairError,RepairBudget} from './open-repair-wire.ts';
import type {RepairPolicy} from './open-repair-wire.ts';

type Obj=Record<string,any>;
export const MAILBOX_DEPTH=16,MAILBOX_CAPACITY=65536;
export interface MailboxRangeState{
  readonly slot_binding:string;readonly count:number;readonly leaf_root:string;
  readonly frontier:readonly (string|null)[];
}
const domain=(name:string)=>Buffer.from('memory-vault-mailbox-'+name+'/v1\0','ascii');
function fail(code='repair_mailbox_range_mismatch'):never{throw new RepairError(code);}
function pattern(value:unknown,re:RegExp,code:string):string{
  if(typeof value!=='string'||re.exec(value)?.[0]!==value)fail(code);return value;
}
const digest=(v:unknown)=>pattern(v,/^[0-9a-f]{64}$/,'repair_invalid_original');
const opaque=(v:unknown)=>pattern(v,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/,'repair_invalid_history');
function fields(v:unknown,names:string[]):Obj{
  try{return objectFields(v,names);}catch{fail('repair_invalid_history');}
}
function dual(v:unknown):void{
  const d=fields(v,['signing_key_id','encryption_key_id']);
  pattern(d.signing_key_id,/^ed25519_[0-9a-f]{64}$/,'repair_invalid_history');
  pattern(d.encryption_key_id,/^x25519_[0-9a-f]{64}$/,'repair_invalid_history');
}
function binding(slot:unknown,policy:RepairPolicy,budget:RepairBudget):string{
  const s=buildNewWire(slot,policy,budget).value as Obj;
  objectFields(s,['root_key','slot_id','writer','writer_storage_epoch']);
  const r=fields(s.root_key,['owner','root_kind','anchor_ref','owner_epoch','root_id']);
  dual(r.owner);if(r.root_kind!=='mailbox')fail('repair_invalid_history');
  const anchor=fields(r.anchor_ref,['namespace','key']);if(anchor.namespace!=='anchor')fail('repair_invalid_history');
  pattern(anchor.key,/^[0-9a-f]{64}$/,'repair_invalid_history');opaque(r.owner_epoch);opaque(r.root_id);
  opaque(s.slot_id);dual(s.writer);opaque(s.writer_storage_epoch);
  return budget.hash(Buffer.concat([domain('slot'),buildNewWire(s,policy,budget).raw]));
}
function node(b:string,height:number,left:string,right:string,budget:RepairBudget):string{
  return budget.hash(Buffer.concat([domain('node'),Buffer.from(b,'hex'),Buffer.from([height]),
    Buffer.from(left,'hex'),Buffer.from(right,'hex')]));
}
function empties(b:string,budget:RepairBudget):string[]{
  const result=[budget.hash(Buffer.concat([domain('empty'),Buffer.from(b,'hex')]))];
  for(let h=1;h<=MAILBOX_DEPTH;h++)result.push(node(b,h,result[h-1],result[h-1],budget));return result;
}
function leaf(b:string,sequence:number,sealed:string,budget:RepairBudget):string{
  digest(sealed);const seq=Buffer.alloc(4);seq.writeUInt32BE(sequence);
  return budget.hash(Buffer.concat([domain('leaf'),Buffer.from(b,'hex'),seq,Buffer.from(sealed,'hex')]));
}
function root(b:string,count:number,frontier:readonly (string|null)[],empty:string[],budget:RepairBudget):string{
  if(count===MAILBOX_CAPACITY)return frontier[16]!;
  let value=empty[0];for(let h=0;h<MAILBOX_DEPTH;h++)value=count&(1<<h)?
    node(b,h+1,frontier[h]!,value,budget):node(b,h+1,value,empty[h],budget);return value;
}
function state(value:unknown,slot:unknown,policy:RepairPolicy,budget:RepairBudget):[MailboxRangeState,string[]]{
  const held=buildNewWire(value,policy,budget).value as Obj;
  objectFields(held,['slot_binding','count','leaf_root','frontier']);const count=u53(held.count);
  if(count>MAILBOX_CAPACITY||held.slot_binding!==binding(slot,policy,budget))fail();
  if(!Array.isArray(held.frontier)||held.frontier.length!==17)fail();
  held.frontier.forEach((v:unknown,h:number)=>{if(count&(1<<h))digest(v);else if(v!==null)fail();});
  const empty=empties(held.slot_binding,budget);
  if(held.leaf_root!==root(held.slot_binding,count,held.frontier,empty,budget))fail();
  return [held as MailboxRangeState,empty];
}
function freeze(value:unknown,policy:RepairPolicy,budget:RepairBudget):MailboxRangeState{
  return buildNewWire(value,policy,budget).value as unknown as MailboxRangeState;
}
export function emptyMailboxState(slot:unknown,policy:RepairPolicy,budget:RepairBudget):MailboxRangeState{
  const b=binding(slot,policy,budget);return freeze({slot_binding:b,count:0,
    leaf_root:empties(b,budget)[16],frontier:Array(17).fill(null)},policy,budget);
}
export function appendMailboxState(value:unknown,sealedCoreSha256:string,slot:unknown,
  policy:RepairPolicy,budget:RepairBudget):MailboxRangeState{
  const [held,empty]=state(value,slot,policy,budget),count=held.count,b=held.slot_binding;
  if(count===MAILBOX_CAPACITY)fail('repair_mailbox_full');
  const frontier=[...held.frontier];let h=0,n=leaf(b,count,sealedCoreSha256,budget);
  while(count&(1<<h)){n=node(b,h+1,frontier[h]!,n,budget);frontier[h]=null;h++;}frontier[h]=n;
  return freeze({slot_binding:b,count:count+1,leaf_root:root(b,count+1,frontier,empty,budget),frontier},policy,budget);
}
export function verifyMailboxInclusion(value:unknown,sequence:number,sealedCoreSha256:string,siblings:unknown,
  slot:unknown,policy:RepairPolicy,budget:RepairBudget):boolean{
  const [held]=state(value,slot,policy,budget),path=buildNewWire(siblings,policy,budget).value;
  u53(sequence);if(sequence>=held.count||!Array.isArray(path)||path.length!==16)fail();
  let n=leaf(held.slot_binding,sequence,sealedCoreSha256,budget);
  path.forEach((s,h)=>{const sibling=digest(s);n=sequence&(1<<h)?node(held.slot_binding,h+1,sibling,n,budget):node(held.slot_binding,h+1,n,sibling,budget);});
  if(n!==held.leaf_root)fail();return true;
}
