/** Native, explicit ACK evidence export through an existing open identity. */
import * as fs from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {canonicalBytes,document,objectFields,decodeBase64url} from './crypto.ts';
import {absolutePath,readPrivate,NetworkError} from './io.ts';
import {writeNewPrivate} from './setup.ts';
import {OpenNetworkClient} from './open-client.ts';
import {AckOwnerRecoveryClient,DEFAULT_REPAIR_CLIENT_LIMITS,DEFAULT_REPAIR_CLIENT_POLICY} from './open-repair-client.ts';
import {OriginalAckStatusJournal} from './open-ack-status.ts';
import type {RawOriginal} from './open-repair-wire.ts';

type Obj=Record<string,any>;
type Phase='unbound'|'empty'|'occupied';
const MAX_BUNDLE=1048576;
const SCHEMAS={unbound:'memory-vault-open-ack-recovery-request/v1',empty:'memory-vault-open-ack-empty-recovery-request/v1',occupied:'memory-vault-open-ack-occupied-recovery-request/v1'};
const PROFILES={unbound:DEFAULT_REPAIR_CLIENT_LIMITS,
  receipt:{...DEFAULT_REPAIR_CLIENT_LIMITS,max_signature_checks:2048,max_proof_bytes:1048576},
  'receipt-index':{...DEFAULT_REPAIR_CLIENT_LIMITS,max_signature_checks:4096,max_proof_bytes:4194304,max_requests:128,max_replay_records:256}};
const hash=(raw:Uint8Array)=>createHash('sha256').update(raw).digest('hex');
const bytes=(value:unknown)=>Buffer.from(canonicalBytes(value,MAX_BUNDLE));
const equal=(a:Uint8Array,b:Uint8Array)=>Buffer.from(a).equals(Buffer.from(b));
function fail(code:string):never{throw new NetworkError(code);}
function entry(value:unknown):RawOriginal{
  const v=objectFields(value,['raw_base64url','ref']);
  return {raw:decodeBase64url(v.raw_base64url,DEFAULT_REPAIR_CLIENT_POLICY.max_document_bytes),ref:v.ref as any};
}
function encode(value:{raw:Uint8Array;ref:unknown}):Obj{return {raw_base64url:Buffer.from(value.raw).toString('base64url'),ref:value.ref};}
function refuseExisting(output:string):void{
  try{fs.lstatSync(output);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
  fail('repair_output_exists');
}

function compact(archive:Obj[]):Obj[]{
  const candidates=archive.map(item=>({item,payload:document(entry(item).raw).payload as Obj}));
  function dominates(a:Obj,b:Obj):boolean{
    if(!equal(bytes(a.scope_key),bytes(b.scope_key))||!equal(bytes(a.signing_key),bytes(b.signing_key))||a.revision<b.revision)return false;
    return b.entries.every((old:Obj)=>a.entries.some((next:Obj)=>next.scope_kind===old.scope_kind&&next.scope_id===old.scope_id&&
      next.minimum_document_revision>=old.minimum_document_revision&&(old.status!=='revoked'||next.status==='revoked'&&(next.operation_mask&old.operation_mask)===old.operation_mask)));
  }
  const kept:typeof candidates=[];
  for(const item of candidates.reverse().sort((a,b)=>b.payload.revision-a.payload.revision))if(!kept.some(other=>dominates(other.payload,item.payload)))kept.push(item);
  if(kept.length>16)fail('repair_status_history_capacity');
  return kept.map(value=>value.item);
}
export async function recoverAck(networkConfig:string,requestPath:string,outputPath:string,
  options:{phase?:Phase;timeout?:number;repairProfile?:keyof typeof PROFILES}={}):Promise<Obj>{
  const phase=options.phase??'unbound',timeout=options.timeout??30,profile=options.repairProfile??(phase==='occupied'?'receipt':'unbound');
  if(!Object.hasOwn(SCHEMAS,phase)||!Object.hasOwn(PROFILES,profile)||!Number.isFinite(timeout)||timeout<=0||timeout>60)fail('repair_invalid_request_bundle');
  const output=absolutePath(outputPath);refuseExisting(output);
  const raw=readPrivate(absolutePath(requestPath),MAX_BUNDLE,true);if(raw===null)fail('repair_request_missing');
  const parsed=document(raw,MAX_BUNDLE),names=['schema_version','target','ack_slot','node','root','read','bootstrap','known_statuses'];
  if(phase!=='unbound')names.push('receipt_writer','message_id','envelope_ref');
  if(Object.hasOwn(parsed,'archive_statuses'))names.push('archive_statuses');
  const request=objectFields(parsed,names) as Obj;
  if(request.schema_version!==SCHEMAS[phase])fail('repair_invalid_request_bundle');
  const known=request.known_statuses,archive=request.archive_statuses??[];
  if(!Array.isArray(known)||known.length>16||!Array.isArray(archive)||archive.length>32)fail('repair_status_history_capacity');
  const originals=Object.fromEntries(['node','root','read','bootstrap'].map(name=>[name,entry(request[name])]));
  const base=(document(originals.node.raw).payload as Obj).base_url;
  const network=new OpenNetworkClient(absolutePath(networkConfig));let client:AckOwnerRecoveryClient|undefined;
  try{
    const journal=new OriginalAckStatusJournal(network.participant,request.ack_slot.root_key);
    const issuers=new Set<string>([network.identity.key_id,request.target.signing_key.key_id]);
    if(phase==='occupied')issuers.add(request.receipt_writer.signing_key.key_id);
    const retained=new Map<string,RawOriginal>();
    for(const item of [...journal.load(issuers),...archive.map(entry)])retained.set(bytes(item.ref).toString('utf8'),item);
    if(retained.size>32)fail('repair_status_history_capacity');
    client=new AckOwnerRecoveryClient(network.identity,network.encryption,{limitPolicy:PROFILES[profile],
      allowLoopback:network.participant.transport.allow_loopback,transport:network.participant.transport,statusObserver:item=>journal.observe(item)});
    const args={targetNodeEntry:originals.node,expectedTarget:request.target,expectedAckSlot:request.ack_slot,
      rootEntry:originals.root,readEntry:originals.read,bootstrapEntry:originals.bootstrap,
      knownStatuses:known.map(entry),archiveStatuses:[...retained.values()],timeout};
    const bound={...args,expectedReceiptWriter:request.receipt_writer,expectedMessageId:request.message_id,expectedEnvelopeRef:request.envelope_ref};
    const result=phase==='unbound'?await client.recover(base,args):phase==='empty'?await client.recoverEmpty(base,bound):await client.recoverOccupied(base,bound);
    for(let source:any=result.source;source;source=source.predecessor)for(const item of source.statuses)journal.observe(item);
    for(const item of result.current_statuses)journal.observe(item);
    const saved=journal.load(issuers).map(encode),retainedStatuses=compact(saved);
    const evidence:Obj={schema_version:'memory-vault-open-ack-recovery-evidence/v1',state:`ack_${phase}_source_recovered`,
      ack_slot:request.ack_slot,target:request.target,handle:encode(result.proof.handle),
      manifest:encode({raw:result.proof.manifest.raw,ref:result.proof.manifest_ref}),
      originals:result.originals.map(encode),current_statuses:result.current_statuses.map(encode),
      known_statuses:retainedStatuses,archive_statuses:saved,metrics:result.metrics};
    if(phase!=='unbound')Object.assign(evidence,{receipt_writer:request.receipt_writer,message_id:request.message_id,envelope_ref:request.envelope_ref});
    if(phase==='occupied')evidence.recipient_receipt=encode((result.source as any).inputs.receipt);
    const encoded=Buffer.concat([bytes(evidence),Buffer.from('\n')]);if(encoded.length>MAX_BUNDLE)fail('repair_over_budget');
    writeNewPrivate(output,encoded);
    return {state:evidence.state,evidence_path:output,evidence_sha256:hash(encoded),original_count:result.originals.length,
      requests:result.metrics.requests,vault_modified:false,recipient_saved:phase==='occupied'};
  }finally{client?.close();network.close();}
}
export async function main(argv:string[]):Promise<number>{
  try{
    const phases:Record<string,Phase>={'recover-ack':'unbound','recover-empty':'empty','recover-occupied':'occupied'};
    const phase=phases[argv[0]];if(!phase)fail('repair_invalid_arguments');
    const flags:Record<string,string>={};
    for(let i=1;i<argv.length;i+=2){const key=argv[i];if(!['--network-config','--request','--output','--timeout','--repair-profile'].includes(key)||flags[key]!==undefined||argv[i+1]===undefined)fail('repair_invalid_arguments');flags[key]=argv[i+1];}
    if(!flags['--network-config']||!flags['--request']||!flags['--output'])fail('repair_invalid_arguments');
    const result=await recoverAck(flags['--network-config'],flags['--request'],flags['--output'],{phase,
      timeout:flags['--timeout']===undefined?30:Number(flags['--timeout']),repairProfile:flags['--repair-profile'] as any});
    process.stdout.write(JSON.stringify(result)+'\n');return 0;
  }catch(error){const code=(error as any)?.code;process.stderr.write(JSON.stringify({error:typeof code==='string'&&/^[a-z][a-z0-9_]{1,63}$/.test(code)?code:'repair_command_unavailable'})+'\n');return 1;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2));
