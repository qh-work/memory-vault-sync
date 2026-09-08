/** Bounded native open routing. No global registry, socket access or Vault writes. */
import {isIP} from 'node:net';
import {performance} from 'node:perf_hooks';
import {canonicalBytes,document,documentSha256,digestHex,sha256} from './crypto.ts';
import type {DocumentInput} from './crypto.ts';
import {coordinate,verifyNode,verifyResponse,OpenControlError,MAX_CONTROL_BYTES,MAX_DESCRIPTOR_BYTES} from './open-control.ts';
import type {SignedNode,SignedOpen,OpenView} from './open-control.ts';

export class OpenRoutingError extends OpenControlError {
  constructor(code:string){super(code);this.name='OpenRoutingError';}
}
const monotonic=()=>performance.now()/1000;
function fail(code:string):never{throw new OpenRoutingError(code);}
export function distance(left:string,right:string):Uint8Array{
  const a=Buffer.from(digestHex(left),'hex'),b=Buffer.from(digestHex(right),'hex'),result=Buffer.alloc(32);
  for(let index=0;index<32;index++)result[index]=a[index]^b[index];
  return result;
}
function compareDistance(target:string,left:SignedNode,right:SignedNode):number{
  return Buffer.compare(distance(target,left.payload.coordinate),distance(target,right.payload.coordinate))||
    left.payload.signing_key.key_id.localeCompare(right.payload.signing_key.key_id,'en');
}
function bucketIndex(self:string,other:string):number{
  const bytes=distance(self,other);
  for(let index=0;index<32;index++)if(bytes[index])return 255-index*8-Math.clz32(bytes[index])+24;
  return -1;
}
export function maintenanceTarget(keyId:string,cycle:number):string{
  const own=coordinate(keyId);if(!Number.isSafeInteger(cycle)||cycle<0)fail('open_invalid_routing_budget');
  if(cycle%4===0)return own;
  return sha256(Buffer.from('memory-vault-open-maintenance/v1\0'+keyId+'\0'+cycle,'ascii'));
}
function ipv6Words(address:string):number[]{
  let value=address.toLowerCase();
  if(value.includes('.')){
    const split=value.lastIndexOf(':'),tail=value.slice(split+1).split('.').map(Number);
    value=value.slice(0,split+1)+((tail[0]<<8)|tail[1]).toString(16)+':'+((tail[2]<<8)|tail[3]).toString(16);
  }
  const halves=value.split('::'),left=halves[0]?halves[0].split(':').map(v=>parseInt(v,16)):[];
  const right=halves.length>1&&halves[1]?halves[1].split(':').map(v=>parseInt(v,16)):[];
  return halves.length===1?left:[...left,...Array(8-left.length-right.length).fill(0),...right];
}
function ipv6Text(words:number[]):string{
  let start=-1,length=0;
  for(let index=0;index<words.length;){
    if(words[index]){index++;continue;}let end=index;while(end<words.length&&!words[end])end++;
    if(end-index>length&&end-index>=2){start=index;length=end-index;}index=end;
  }
  if(start<0)return words.map(v=>v.toString(16)).join(':');
  return words.slice(0,start).map(v=>v.toString(16)).join(':')+'::'+words.slice(start+length).map(v=>v.toString(16)).join(':');
}
/** Only an actual transport-observed literal address, never a advertised label. */
export function sourceGroup(address:string):string{
  if(typeof address!=='string'||address.includes('%'))fail('open_invalid_observed_address');
  const kind=isIP(address);
  if(kind===4)return '4:'+address.split('.').slice(0,3).join('.')+'.0/24';
  if(kind!==6)fail('open_invalid_observed_address');
  const words=ipv6Words(address);
  if(words.slice(0,5).every(v=>v===0)&&words[5]===0xffff)
    return '4:'+[(words[6]>>>8),words[6]&255,(words[7]>>>8),0].join('.')+'/24';
  return '6:'+ipv6Text([...words.slice(0,3),0,0,0,0,0])+'/48';
}
interface Entry{node:SignedNode;group:string;failures:number;}
interface Bucket{active:Entry[];replacement:Entry[];}
/** The host may call learnVerified only after authenticated request/response
 * possession and actual destination/source-address validation. */
export class RoutingTable{
  readonly key_id:string;readonly directory:boolean;readonly clock:()=>number;
  readonly coordinate:string;
  private general=new Map<number,Bucket>();private directories=new Map<number,Bucket>();
  private introductions:Entry[]=[];
  constructor(keyId:string,options:{directory?:boolean;clock?:()=>number}={}){
    if(options.directory!==undefined&&typeof options.directory!=='boolean')fail('open_invalid_view');
    this.key_id=keyId;this.coordinate=coordinate(keyId);this.directory=options.directory??false;
    this.clock=options.clock??(()=>Math.floor(Date.now()/1000));
  }
  private prune():void{
    const now=Math.floor(this.clock());
    for(const view of [this.general,this.directories])for(const [index,bucket] of view){
      bucket.active=bucket.active.filter(e=>e.node.payload.expires_at>now);
      bucket.replacement=bucket.replacement.filter(e=>e.node.payload.expires_at>now);
      // Only previously verified replacements can fill expiry vacancies.
      for(let position=bucket.replacement.length-1;position>=0&&bucket.active.length<8;position--){
        const entry=bucket.replacement[position];
        if(bucket.active.filter(other=>other.group===entry.group).length<2){bucket.active.push(entry);bucket.replacement.splice(position,1);}
      }
      if(!bucket.active.length&&!bucket.replacement.length)view.delete(index);
    }
    this.introductions=this.introductions.filter(e=>e.node.payload.expires_at>now);
  }
  private update(view:Map<number,Bucket>,entry:Entry,participates:boolean,allowReplacementEviction:boolean):boolean{
    const index=bucketIndex(this.coordinate,entry.node.payload.coordinate);
    if(index<0)return false;
    const bucket=view.get(index)??{active:[],replacement:[]};view.set(index,bucket);
    const id=entry.node.payload.signing_key.key_id;
    const position=bucket.active.findIndex(e=>e.node.payload.signing_key.key_id===id);
    const priorSpare=bucket.replacement.findIndex(e=>e.node.payload.signing_key.key_id===id);
    const others=bucket.active.filter(e=>e.node.payload.signing_key.key_id!==id);
    bucket.replacement=bucket.replacement.filter(e=>e.node.payload.signing_key.key_id!==id);
    if(participates&&others.length<8&&others.filter(e=>e.group===entry.group).length<2){
      if(position<0)bucket.active.push({...entry});else bucket.active[position]={...entry};return true;
    }
    bucket.active=others;
    if(participates){
      if(priorSpare>=0)bucket.replacement.splice(priorSpare,0,{...entry});
      else if(bucket.replacement.length<2||allowReplacementEviction){bucket.replacement.push({...entry});if(bucket.replacement.length>2)bucket.replacement.shift();}
    }
    if(!bucket.active.length&&!bucket.replacement.length)view.delete(index);return false;
  }
  learnVerified(value:SignedNode,observedAddress:string,allowReplacementEviction=true):boolean{
    if(typeof allowReplacementEviction!=='boolean')fail('open_invalid_routing_budget');
    const payload=verifyNode(value,{now:Math.floor(this.clock())}),group=sourceGroup(observedAddress);
    const node=document(value as DocumentInput,MAX_DESCRIPTOR_BYTES) as unknown as SignedNode;
    this.prune();if(payload.signing_key.key_id===this.key_id)return false;
    const previous:Entry[]=[...this.introductions];
    for(const view of [this.general,this.directories])for(const bucket of view.values())previous.push(...bucket.active,...bucket.replacement);
    for(const old of previous)if(old.node.payload.signing_key.key_id===payload.signing_key.key_id){
      if(payload.revision<old.node.payload.revision)fail('open_node_rollback');
      if(payload.revision===old.node.payload.revision&&documentSha256(node as DocumentInput)!==documentSha256(old.node as DocumentInput))fail('open_node_revision_conflict');
    }
    if(payload.status!=='active'){this.remove(payload.signing_key.key_id);return false;}
    const entry={node,group,failures:0};let active=false;
    active=this.update(this.general,entry,payload.roles.includes('router'),allowReplacementEviction)||active;
    active=this.update(this.directories,entry,this.directory&&payload.roles.includes('directory'),allowReplacementEviction)||active;
    if(!this.directory&&payload.roles.includes('directory')){
      const index=this.introductions.findIndex(e=>e.node.payload.signing_key.key_id===payload.signing_key.key_id);
      const others=this.introductions.filter(e=>e.node.payload.signing_key.key_id!==payload.signing_key.key_id);
      if(others.filter(e=>e.group===group).length<2){
        if(index>=0)this.introductions[index]={...entry};else if(this.introductions.length<4)this.introductions.push({...entry});
      }else this.introductions=others;
    }else if(!payload.roles.includes('directory'))this.introductions=this.introductions.filter(e=>e.node.payload.signing_key.key_id!==payload.signing_key.key_id);
    return active;
  }
  hasVerified(value:SignedNode):boolean{
    const payload=verifyNode(value,{now:Math.floor(this.clock())});
    const fingerprint=documentSha256(value as DocumentInput);
    this.prune();const entries:Entry[]=[...this.introductions];
    for(const view of [this.general,this.directories])for(const bucket of view.values())entries.push(...bucket.active,...bucket.replacement);
    // A repeat announcement never refreshes a proof or resets failed probes.
    return entries.some(entry=>entry.node.payload.signing_key.key_id===payload.signing_key.key_id&&entry.failures===0&&
      documentSha256(entry.node as DocumentInput)===fingerprint);
  }
  closest(target:string,view:OpenView='general',limit=8):SignedNode[]{
    digestHex(target);if(!['general','directory'].includes(view))fail('open_invalid_view');
    if(!Number.isSafeInteger(limit)||limit<0||limit>32)fail('open_invalid_routing_budget');
    this.prune();const nodes:SignedNode[]=[];
    if(view==='directory'&&!this.directory)nodes.push(...this.introductions.map(e=>e.node));
    else for(const bucket of (view==='general'?this.general:this.directories).values())nodes.push(...bucket.active.map(e=>e.node));
    return nodes.sort((a,b)=>compareDistance(target,a,b)).slice(0,limit).map(node=>document(node as DocumentInput,MAX_DESCRIPTOR_BYTES) as unknown as SignedNode);
  }
  replyCandidates(target:string,view:OpenView='general'):SignedNode[]{
    digestHex(target);if(!['general','directory'].includes(view))fail('open_invalid_view');
    this.prune();const entries:Entry[]=[];
    if(view==='directory'&&!this.directory)entries.push(...this.introductions);
    else for(const bucket of (view==='general'?this.general:this.directories).values())entries.push(...bucket.active,...bucket.replacement);
    // Replacements have answered their own challenge; callers must still probe
    // every introduction. Advertising them never displaces a stable active peer.
    const nodes:SignedNode[]=[],sources=new Map<string,number>();
    for(const entry of entries.sort((a,b)=>compareDistance(target,a.node,b.node))){
      const source=bucketIndex(this.coordinate,entry.node.payload.coordinate)+':'+entry.group;
      if((sources.get(source)??0)>=2)continue;
      nodes.push(entry.node);sources.set(source,(sources.get(source)??0)+1);
      if(nodes.length===8)break;
    }
    if(view==='directory'&&!nodes.length)return this.replyCandidates(target,'general');
    return nodes.map(node=>document(node as DocumentInput,MAX_DESCRIPTOR_BYTES) as unknown as SignedNode);
  }
  private remove(keyId:string):void{
    for(const view of [this.general,this.directories])for(const bucket of view.values()){
      bucket.active=bucket.active.filter(e=>e.node.payload.signing_key.key_id!==keyId);
      bucket.replacement=bucket.replacement.filter(e=>e.node.payload.signing_key.key_id!==keyId);
    }
    this.introductions=this.introductions.filter(e=>e.node.payload.signing_key.key_id!==keyId);
  }
  markFailed(keyId:string):boolean{
    this.prune();let removed=false;
    for(const view of [this.general,this.directories])for(const bucket of view.values()){
      bucket.replacement=bucket.replacement.filter(entry=>{
        if(entry.node.payload.signing_key.key_id===keyId&&++entry.failures>=2){removed=true;return false;}return true;
      });
      const entry=bucket.active.find(e=>e.node.payload.signing_key.key_id===keyId);
      if(!entry||++entry.failures<2)continue;
      bucket.active=bucket.active.filter(e=>e!==entry);removed=true;
      for(let index=bucket.replacement.length-1;index>=0;index--){
        const replacement=bucket.replacement[index];
        if(bucket.active.filter(e=>e.group===replacement.group).length<2){bucket.active.push(replacement);bucket.replacement.splice(index,1);break;}
      }
    }
    this.introductions=this.introductions.filter(entry=>{
      if(entry.node.payload.signing_key.key_id===keyId&&++entry.failures>=2){removed=true;return false;}return true;
    });return removed;
  }
  stats():Record<string,number>{
    this.prune();const count=(view:Map<number,Bucket>,field:'active'|'replacement')=>[...view.values()].reduce((n,b)=>n+b[field].length,0);
    return {general_active:count(this.general,'active'),general_replacements:count(this.general,'replacement'),
      directory_active:count(this.directories,'active'),directory_replacements:count(this.directories,'replacement'),directory_introductions:this.introductions.length};
  }
}
export class LookupBudget{
  readonly deadline:number;readonly maximum_requests:number;readonly maximum_bytes:number;
  readonly clock:()=>number;requests=0;bytes=0;request_bytes=0;
  constructor(options:{maximum_requests?:number;maximum_bytes?:number;maximum_seconds?:number;clock?:()=>number}={}){
    this.maximum_requests=options.maximum_requests??64;this.maximum_bytes=options.maximum_bytes??4*1024*1024;
    const seconds=options.maximum_seconds??10;
    if(!Number.isSafeInteger(this.maximum_requests)||this.maximum_requests<1||this.maximum_requests>64||
      !Number.isSafeInteger(this.maximum_bytes)||this.maximum_bytes<1||this.maximum_bytes>4*1024*1024||
      !Number.isFinite(seconds)||seconds<=0||seconds>10)fail('open_invalid_routing_budget');
    this.clock=options.clock??monotonic;this.deadline=this.clock()+seconds;
  }
  check():void{if(this.clock()>=this.deadline||this.requests>this.maximum_requests||this.bytes>this.maximum_bytes||
    this.request_bytes>this.maximum_requests*MAX_CONTROL_BYTES)fail('open_lookup_budget_exhausted');}
  chargeRequest():void{this.check();if(!this.remaining_requests)fail('open_lookup_budget_exhausted');this.requests++;}
  chargeBytes(bytes:number):void{
    if(!Number.isSafeInteger(bytes)||bytes<0)fail('open_invalid_routing_budget');
    this.bytes+=bytes;this.check();
  }
  chargeRequestBytes(bytes:number):void{
    if(!Number.isSafeInteger(bytes)||bytes<0||bytes>MAX_CONTROL_BYTES)fail('open_invalid_routing_budget');
    this.request_bytes+=bytes;this.check();
  }
  get response_bytes():number{return this.bytes;}
  get remaining_requests():number{return Math.max(0,this.maximum_requests-this.requests);}
  get remaining_bytes():number{return Math.max(0,this.maximum_bytes-this.bytes);}
}
export interface RpcReply{response:SignedOpen|Uint8Array;observed_address:string;wire_bytes:number;}
export interface LookupOptions{
  view?:OpenView;
  rpc:(peer:SignedNode,request:SignedOpen,deadline:number)=>Promise<RpcReply>;
  signRequest:(peer:SignedNode,action:'find',body:{target:string;view:OpenView})=>SignedOpen;
  initialLanes?:readonly (readonly SignedNode[])[];budget?:LookupBudget;
}
interface Candidate{
  node:SignedNode;bits:number;depth:[number,number];parents:[string|null,string|null];
  state:'pending'|'running'|'verified'|'failed';request?:SignedOpen;
}
export interface LookupPath{
  key_id:string;lane:number;source_bits:number;depth:number;parent_key_id:string|null;
  view:OpenView;state:string;
}
export interface LookupMetrics{
  requests:number;bytes:number;request_bytes:number;response_bytes:number;candidate_peak:number;
  concurrency_peak:number;lane_requests:[number,number];paths:LookupPath[];errors:{key_id:string;code:string}[];
}
export interface LookupResult{state:'closest_known'|'budget_exhausted'|'unreachable';candidates:SignedNode[];partial:boolean;metrics:LookupMetrics;}

/** One local attempt. rpc must enforce the supplied absolute monotonic deadline,
 * pin the actual validated destination and never substitute advertised source IPs.
 * Responses arriving after this attempt ends cannot update its routing state. */
export async function lookup(table:RoutingTable,target:string,options:LookupOptions):Promise<LookupResult>{
  digestHex(target);const view=options.view??'general';
  if(view!=='general'&&view!=='directory')fail('open_invalid_view');
  let lanes=options.initialLanes;
  if(lanes===undefined){let seeds=table.closest(target,view,16);if(view==='directory'&&!seeds.length)seeds=table.closest(target,'general',16);
    lanes=[seeds.filter((_,i)=>i%2===0),seeds.filter((_,i)=>i%2===1)];}
  if(!Array.isArray(lanes)||lanes.length>2||lanes.some(l=>!Array.isArray(l)||l.length>16))fail('open_invalid_routing_budget');
  const budget=options.budget??new LookupBudget();
  const metrics:LookupMetrics={requests:0,bytes:0,request_bytes:0,response_bytes:0,candidate_peak:0,
    concurrency_peak:0,lane_requests:[0,0],paths:[],errors:[]};
  const pool=new Map<string,Candidate>();
  const visited=new Map<string,{state:'verified'|'failed';bits:number;children:string[];node_sha256:string}>();
  const successes:[SignedNode[],SignedNode[]]=[[],[]],directoryReady=[false,false];let exhausted=false,turn=0;
  const errors=(key:string,error:unknown)=>{
    const code=typeof (error as any)?.code==='string'&&/^[a-z][a-z0-9_]{1,63}$/.exec((error as any).code)?.[0]===(error as any).code?(error as any).code:'open_rpc_unreachable';
    if(metrics.errors.length<64)metrics.errors.push({key_id:key,code});
    if(code==='open_lookup_budget_exhausted')exhausted=true;
    return code;
  };
  const role=(node:SignedNode)=>node.payload.roles.includes(view==='general'?'router':'directory');
  function rememberSuccess(node:SignedNode,lane:number):void{
    if(!role(node))return;
    if(view==='directory')directoryReady[lane]=true;
    const known=successes[lane];if(!known.some(n=>n.payload.signing_key.key_id===node.payload.signing_key.key_id))known.push(node);
    known.sort((a,b)=>compareDistance(target,a,b));if(known.length>8)known.length=8;
  }
  function add(value:SignedNode,lane:number,depth:number,parent:string|null):void{
    let payload;try{payload=verifyNode(value,{now:Math.floor(table.clock())});}catch{return;}
    if(payload.status!=='active'||payload.signing_key.key_id===table.key_id)return;
    const id=payload.signing_key.key_id,bit=1<<lane;
    let candidate=pool.get(id);
    const outcome=visited.get(id);
    if(outcome&&documentSha256(value as DocumentInput)!==outcome.node_sha256)return;
    if(candidate&&payload.revision!==candidate.node.payload.revision)return;
    const members=[...pool.values()].filter(c=>c.bits&bit);
    if((!candidate||!(candidate.bits&bit))&&members.length>=16){
      const removable=members.filter(c=>c.state!=='running').sort((a,b)=>compareDistance(target,b.node,a.node));
      if(!removable.length||compareDistance(target,value,removable[0].node)>=0)return;
      const removed=removable[0];removed.bits&=~bit;
      if(!removed.bits)pool.delete(removed.node.payload.signing_key.key_id);
    }
    if(!candidate){
      if(pool.size>=32)return;
      candidate={node:document(value as DocumentInput,MAX_DESCRIPTOR_BYTES) as unknown as SignedNode,bits:0,
        depth:[0,0],parents:[null,null],state:'pending'};pool.set(id,candidate);
    }
    const newBit=!(candidate.bits&bit);
    candidate.bits|=bit;candidate.depth[lane]=depth;candidate.parents[lane]=parent;
    metrics.candidate_peak=Math.max(metrics.candidate_peak,pool.size);
    if(outcome){
      candidate.state=outcome.state;outcome.bits|=bit;
      if(outcome.state==='verified')rememberSuccess(candidate.node,lane);
      if(newBit)for(const child of outcome.children){const retained=pool.get(child);
        if(retained&&child!==id&&!(retained.bits&bit))add(retained.node,lane,depth+1,id);}
    }
  }
  for(let lane=0;lane<lanes.length;lane++)for(const node of lanes[lane])add(node,lane,0,null);
  type Completion={candidate:Candidate;lane:number;reply?:RpcReply;error?:unknown};
  const running=new Map<string,{candidate:Candidate;lane:number;promise:Promise<Completion>}>();
  function next(lane:number,ignoreCap=false):Candidate|undefined{
    if(!ignoreCap&&metrics.lane_requests[lane]>=32)return undefined;
    const cutoff=successes[lane].length===8?successes[lane][7]:undefined;
    return [...pool.values()].filter(c=>c.state==='pending'&&(c.bits&(1<<lane))&&
      (!(view==='directory'&&directoryReady[lane])||c.node.payload.roles.includes('directory'))&&
      (!cutoff||compareDistance(target,c.node,cutoff)<0)).sort((a,b)=>compareDistance(target,a.node,b.node))[0];
  }
  function chooseLane():number{
    const eligible=[0,1].filter(lane=>next(lane));if(!eligible.length)return -1;
    const inactive=eligible.filter(lane=>![...running.values()].some(r=>r.candidate.bits&(1<<lane)));
    const choices=inactive.length?inactive:eligible;
    const chosen=choices.includes(turn)?turn:choices[0];turn=1-chosen;return chosen;
  }
  function launch(candidate:Candidate,lane:number):void{
    const request=options.signRequest(candidate.node,'find',{target,view});
    budget.chargeRequestBytes(canonicalBytes(request,MAX_CONTROL_BYTES).byteLength);
    budget.chargeRequest();metrics.lane_requests[lane]++;
    const id=candidate.node.payload.signing_key.key_id;
    candidate.state='running';candidate.request=request;
    const promise=(async():Promise<Completion>=>{
      try{
        const reply=await options.rpc(candidate.node,request,budget.deadline);
        return {candidate,lane,reply};
      }catch(error){return {candidate,lane,error};}
    })();
    running.set(id,{candidate,lane,promise});metrics.concurrency_peak=Math.max(metrics.concurrency_peak,running.size);
  }
  while(true){
    try{
      budget.check();
      while(running.size<3){
        const lane=chooseLane();if(lane<0)break;
        if(!budget.remaining_requests||budget.remaining_bytes<MAX_CONTROL_BYTES*(running.size+1)){exhausted=true;break;}
        launch(next(lane)!,lane);
      }
    }catch(error){if((error as any)?.code!=='open_lookup_budget_exhausted')throw error;exhausted=true;break;}
    if(!running.size)break;
    let timer:ReturnType<typeof setTimeout>|undefined;
    const deadline=new Promise<null>(resolve=>{timer=setTimeout(()=>resolve(null),Math.max(0,(budget.deadline-budget.clock())*1000));});
    const completed=await Promise.race([...running.values()].map(r=>r.promise).concat(deadline as any));
    if(timer!==undefined)clearTimeout(timer);
    if(completed===null){exhausted=true;break;}
    const item=completed as Completion,candidate=item.candidate,id=candidate.node.payload.signing_key.key_id;
    running.delete(id);
    const path:LookupPath={key_id:id,lane:item.lane,source_bits:candidate.bits,depth:candidate.depth[item.lane],
      parent_key_id:candidate.parents[item.lane],view,state:'failed'};
    const children:string[]=[];
    try{
      if(item.error!==undefined)throw item.error;
      const reply=item.reply!;
      if(!reply||typeof reply!=='object')fail('open_invalid_response');
      budget.chargeBytes(reply.wire_bytes);
      const actual=reply.response instanceof Uint8Array?reply.response.byteLength:canonicalBytes(reply.response,MAX_CONTROL_BYTES).byteLength;
      if(reply.wire_bytes<actual||reply.wire_bytes>MAX_CONTROL_BYTES)fail('open_invalid_response_size');
      const body=verifyResponse(reply.response,{request:candidate.request!,node:candidate.node,now:Math.floor(table.clock())}).body;
      delete candidate.request;budget.check();
      if(Object.hasOwn(body,'error'))fail(body.error.code);
      // Exploratory finds cannot evict proven join replacements; direct hello
      // probes retain permission to rotate that bounded replacement list.
      table.learnVerified(candidate.node,reply.observed_address,false);
      candidate.state='verified';path.state='verified';
      for(let lane=0;lane<2;lane++)if(candidate.bits&(1<<lane))rememberSuccess(candidate.node,lane);
      for(const child of body.nodes){children.push(child.payload.signing_key.key_id);
        for(let lane=0;lane<2;lane++)if(candidate.bits&(1<<lane))add(child,lane,candidate.depth[lane]+1,id);
      }
    }catch(error){
      candidate.state='failed';errors(id,error);table.markFailed(id);
    }
    visited.set(id,{state:candidate.state as 'verified'|'failed',bits:candidate.bits,children,node_sha256:documentSha256(candidate.node as DocumentInput)});
    metrics.paths.push(path);
    if(exhausted&&(!running.size||budget.clock()>=budget.deadline||budget.bytes>budget.maximum_bytes))break;
  }
  exhausted=exhausted||[0,1].some(lane=>metrics.lane_requests[lane]>=32&&next(lane,true)!==undefined);
  // Outstanding RPC promises are already observed, but cannot mutate this table
  // after return. The transport remains responsible for deadline/cancellation.
  metrics.requests=budget.requests;metrics.bytes=budget.bytes;metrics.request_bytes=budget.request_bytes;metrics.response_bytes=budget.bytes;
  const results=new Map<string,SignedNode>();for(const lane of successes)for(const node of lane)results.set(node.payload.signing_key.key_id,node);
  const candidates=[...results.values()].sort((a,b)=>compareDistance(target,a,b)).slice(0,8);
  return {state:exhausted?'budget_exhausted':candidates.length?'closest_known':'unreachable',candidates,
    partial:exhausted||metrics.errors.length>0||!candidates.length,metrics};
}
