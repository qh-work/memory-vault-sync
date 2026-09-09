/** Native open participant. One existing transport DB, no Vault or trust writes.
 * Introductions become routes only after a fresh authenticated endpoint reply. */
import {randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import type {DatabaseSync} from 'node:sqlite';
import {canonicalBytes,document,validateSigningIdentity,NetworkCryptoError} from './crypto.ts';
import type {DocumentInput,SigningIdentityDocument} from './crypto.ts';
import {absolutePath,NetworkError,transaction} from './io.ts';
import {openTransportState} from './transport-state.ts';
import {OpenCheckpoints,OpenIndex} from './open-state.ts';
import type {IndexOptions} from './open-state.ts';
import {ContactState} from './open-contact-state.ts';
import type {ContactStateOptions} from './open-contact-state.ts';
import {verifyRpc as verifyContactRpc,signResponse as signContactResponse} from './open-contact.ts';
import {coordinate,contactKey,verifyNode,verifyContact,signRequest,verifyRequest,verifyResponse,signResponse} from './open-control.ts';
import type {SignedNode,SignedContact,SignedOpen,OpenAction,OpenView} from './open-control.ts';
import {RoutingTable,LookupBudget,lookup,maintenanceTarget} from './open-routing.ts';
import type {RpcReply} from './open-routing.ts';
import {OpenHTTPTransport,endpoint} from './open-transport.ts';
type Obj=Record<string,any>;
const now=()=>Math.floor(Date.now()/1000);
function fail(code:string,retryable=false):never{throw new NetworkError(code,retryable);}
function code(error:unknown):string{
  const candidate=(error as any)?.code;
  return typeof candidate==='string'&&/^[a-z][a-z0-9_]{1,63}$/.test(candidate)?candidate:'open_storage_unavailable';
}
const same=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
export interface ParticipantOptions{seeds:SignedNode[];descriptor?:SignedNode;allow_loopback?:boolean;index_policy?:IndexOptions;contact_policy?:ContactStateOptions;}
export class OpenParticipant{
  readonly identity:SigningIdentityDocument;readonly descriptor:SignedNode|null;
  readonly table:RoutingTable;readonly transport:OpenHTTPTransport;readonly seeds:SignedNode[];
  readonly keyId:string;
  private readonly database:DatabaseSync;private readonly checkpoints:OpenCheckpoints;
  private readonly index?:OpenIndex;private readonly contact?:ContactState;
  private readonly pending=new Map<string,SignedNode>();
  private maintenanceCycle=0;private closed=false;private tail:Promise<unknown>=Promise.resolve();
  private seedRefreshAfter=0;
  constructor(identity:SigningIdentityDocument,stateDirectory:string,options:ParticipantOptions){
    if(!Array.isArray(options.seeds)||options.seeds.length>2)fail('open_two_initial_introductions_maximum');
    this.identity=document(identity as unknown as DocumentInput,4096) as unknown as SigningIdentityDocument;
    const signer=validateSigningIdentity(this.identity);this.keyId=signer.key_id;
    this.descriptor=options.descriptor===undefined?null:document(options.descriptor as DocumentInput,4096) as unknown as SignedNode;
    const own=this.descriptor?verifyNode(this.descriptor):null;
    if(own&&(!same(own.signing_key,signer)||own.status!=='active'))fail('open_wrong_node');
    this.transport=new OpenHTTPTransport({allow_loopback:options.allow_loopback});
    this.seeds=options.seeds.map(seed=>document(seed as DocumentInput,4096) as unknown as SignedNode);
    for(const seed of this.seeds){
      // Expired originals remain fixed-key hints, never active routing entries.
      const raw=verifyNode(seed,{allow_expired:true});if(raw.status!=='active')fail('open_seed_inactive');
      endpoint(raw.base_url,this.transport.allow_loopback);
    }
    if(new Set(this.seeds.map(seed=>seed.payload.signing_key.key_id)).size!==this.seeds.length)fail('open_duplicate_seed');
    const policy=options.index_policy??{};
    if(typeof policy!=='object'||Array.isArray(policy)||Object.keys(policy).some(key=>
      !['enabled','maximum_records','maximum_bytes','maximum_replays','maximum_lease_seconds'].includes(key)))fail('open_invalid_index_policy');
    this.table=new RoutingTable(this.keyId,{directory:own?.roles.includes('directory')??false});
    this.database=openTransportState(absolutePath(stateDirectory),{profile:'open-routing-v1',signing_key:signer,storage_epoch:own?.storage_epoch??null});
    try{
      this.checkpoints=new OpenCheckpoints(this.database);this.checkpoints.initialize();
      this.database.exec(`CREATE TABLE IF NOT EXISTS open_peer_cache(key_id TEXT PRIMARY KEY,node BLOB NOT NULL,seen_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS open_peer_seen ON open_peer_cache(seen_at);`);
      if(this.descriptor){
        this.accept(this.descriptor);this.index=new OpenIndex(this.database,this.identity,this.descriptor,policy);this.index.initialize();
        this.contact=new ContactState(this.database,this.identity,this.descriptor,options.contact_policy??{});this.contact.initialize();
      }
    }catch(error){this.database.close();this.transport.close();throw error;}
  }
  close():void{if(this.closed)return;this.closed=true;this.transport.close();this.database.close();}
  private ready():void{if(this.closed)fail('open_transport_closed');}
  private serial<T>(operation:()=>Promise<T>):Promise<T>{
    const next=this.tail.then(()=>{this.ready();return operation();});this.tail=next.catch(()=>undefined);return next;
  }
  private accept(value:SignedNode|SignedContact):void{this.ready();this.checkpoints.accept(value as DocumentInput);}
  /** Synchronous contact storage access; never keep a DB transaction over await. */
  contactStorage<T>(operation:(database:DatabaseSync)=>T):T{this.ready();return operation(this.database);}
  acceptContactControl(value:SignedNode|SignedContact):void{this.accept(value);}
  lookupContactResource(target:string,budget:LookupBudget){this.ready();return this.lookup(target,'general',budget);}
  private cache(node:SignedNode):void{
    this.ready();transaction(this.database,()=>{
      this.database.prepare('INSERT OR REPLACE INTO open_peer_cache VALUES(?,?,?)').run(node.payload.signing_key.key_id,canonicalBytes(node),now());
      this.database.exec('DELETE FROM open_peer_cache WHERE key_id NOT IN (SELECT key_id FROM open_peer_cache ORDER BY seen_at DESC,key_id LIMIT 32)');
    });
  }
  private async refreshSeedIntroductions(budget:LookupBudget,force=false):Promise<string[]>{
    this.ready();const errors:string[]=[];
    if(!force&&performance.now()/1000<this.seedRefreshAfter)return errors;
    this.seedRefreshAfter=performance.now()/1000+30;
    for(let index=0;index<this.seeds.length;index++){
      const before=verifyNode(this.seeds[index],{allow_expired:true});
      if(before.expires_at>now()+60)continue;
      try{
        budget.check();budget.chargeRequest();
        const reply=await this.transport.requestNode(before.base_url,budget.deadline);
        budget.chargeBytes(reply.wire_bytes);this.ready();
        const after=verifyNode(reply.response);
        if(after.status!=='active'||after.revision<=before.revision||
          (['signing_key','storage_epoch','base_url','roles'] as const).some(name=>!same(after[name],before[name])))fail('open_seed_refresh_mismatch');
        const node=document(reply.response as DocumentInput,4096) as unknown as SignedNode;
        this.accept(node);this.cache(node);this.seeds[index]=node;
        // A normal signed hello/challenge must still prove the endpoint.
      }catch(error){errors.push(code(error));}
    }
    return errors;
  }
  private initial(target:string,view:OpenView):SignedNode[][]{
    this.ready();const candidates=[...this.seeds,...this.table.closest(target,view,16)];
    if(view==='directory')candidates.push(...this.table.closest(target,'general',8));
    for(const row of this.database.prepare('SELECT node FROM open_peer_cache ORDER BY seen_at DESC,key_id LIMIT 32').all() as Obj[])
      candidates.push(document(row.node,4096) as unknown as SignedNode);
    const unique=new Map<string,SignedNode>();
    for(const node of candidates){try{const raw=verifyNode(node),key=raw.signing_key.key_id,previous=unique.get(key);
      if(raw.status==='active'&&key!==this.keyId&&(!previous||raw.revision>previous.payload.revision))unique.set(key,node);
    }catch{/* Invalid cache entries are never endpoint proof. */}}
    const nodes=[...unique.values()].slice(0,32);return [nodes.filter((_,i)=>i%2===0),nodes.filter((_,i)=>i%2===1)];
  }
  private request(node:SignedNode,action:OpenAction,body:Obj):SignedOpen{
    const issued=now();return signRequest(this.identity,{node,action,body,request_id:'open_'+randomBytes(16).toString('hex'),issued_at:issued,expires_at:issued+60});
  }
  private async rpc(node:SignedNode,request:SignedOpen,deadline:number):Promise<RpcReply>{
    this.accept(node);
    const reply=await this.transport.request(node.payload.base_url,request as DocumentInput,deadline);
    this.ready();if(performance.now()/1000>=deadline)fail('open_lookup_budget_exhausted');
    const checked=verifyResponse(reply.response,{request,node});this.accept(node);
    const actual=request.payload.action==='hello'&&checked.body.node?checked.body.node:node;
    if(actual!==node)this.accept(actual);
    if(!checked.body.error)this.cache(actual);
    return reply;
  }
  private async call(node:SignedNode,action:OpenAction,body:Obj,budget:LookupBudget,observed?:{socket?:string}):Promise<Obj>{
    budget.check();const request=this.request(node,action,body);
    budget.chargeRequestBytes(canonicalBytes(request).length);budget.chargeRequest();
    const reply=await this.rpc(node,request,budget.deadline);budget.chargeBytes(reply.wire_bytes);
    const payload=verifyResponse(reply.response,{request,node}),actual=action==='hello'?(payload.body.node??node):node;
    if(action==='hello'||!payload.body.error)this.table.learnVerified(actual,reply.observed_address);
    if(payload.body.error)fail(payload.body.error.code,payload.body.error.retryable);
    if(observed)observed.socket=JSON.stringify([reply.observed_address,endpoint(node.payload.base_url,this.transport.allow_loopback).port]);
    return payload.body;
  }
  private async lookup(target:string,view:OpenView,budget:LookupBudget){
    const errors=await this.refreshSeedIntroductions(budget);
    const result=await lookup(this.table,target,{view,budget,rpc:(node,request,deadline)=>this.rpc(node,request,deadline),
      signRequest:(node,action,body)=>this.request(node,action,body),initialLanes:this.initial(target,view)});
    return {...result,partial:result.partial||errors.length>0};
  }
  private metrics(budget:LookupBudget){return {requests:budget.requests,request_bytes:budget.request_bytes,response_bytes:budget.response_bytes};}
  join():Promise<Obj>{return this.serial(async()=>{
    const budget=new LookupBudget(),errors=await this.refreshSeedIntroductions(budget,true);
    const initial=this.initial(coordinate(this.keyId),'general'),known=new Map(initial.flat().map(node=>[node.payload.signing_key.key_id,node]));
    for(const configured of this.seeds){try{await this.call(known.get(configured.payload.signing_key.key_id)??configured,'hello',{node:this.descriptor},budget);}catch(error){errors.push(code(error));}}
    const result=await this.lookup(coordinate(this.keyId),'general',budget);
    if(this.descriptor)for(const peer of result.candidates.slice(0,2)){try{await this.call(peer,'hello',{node:this.descriptor},budget);}catch(error){errors.push(code(error));}}
    return {state:result.state,routing:this.table.stats(),metrics:this.metrics(budget),partial:errors.length>0||result.partial,errors,authority_required:false,discovery_grants_access:false};
  });}
  maintain():Promise<Obj>{return this.serial(async()=>{
    const budget=new LookupBudget({maximum_requests:16,maximum_bytes:1024*1024,maximum_seconds:5}),errors=await this.refreshSeedIntroductions(budget);
    const pending=[...this.pending.entries()].slice(0,2);for(const [key] of pending)this.pending.delete(key);
    for(const [,peer] of pending){try{await this.call(peer,'hello',{node:null},budget);}catch(error){errors.push(code(error));}}
    const cycle=this.maintenanceCycle++,target=maintenanceTarget(this.keyId,cycle);
    if(this.descriptor){const peers=this.table.closest(coordinate(this.keyId),'general',8);
      for(let offset=0;offset<Math.min(2,peers.length);offset++){try{await this.call(peers[(cycle*2+offset)%peers.length],'hello',{node:this.descriptor},budget);}catch(error){errors.push(code(error));}}}
    const result=await this.lookup(target,'general',budget);return {state:result.state,metrics:this.metrics(budget),errors};
  });}
  findContact(ownerKeyId:string,budget=new LookupBudget()):Promise<Obj>{return this.serial(async()=>{
    const key=contactKey(ownerKeyId),route=await this.lookup(key,'directory',budget);
    const found:Obj[]=[],errors:string[]=[],states:string[]=[],peers=[...route.candidates];
    if(this.descriptor?.payload.roles.includes('directory'))peers.push(this.descriptor);
    for(const node of peers.slice(0,8)){try{const body=await this.call(node,'get',{key},budget);states.push(body.state);
      if(body.state==='found'){this.accept(body.contact);found.push(body);}
    }catch(error){errors.push(code(error));}}
    const eligible:Obj[]=[];
    for(const body of found){try{this.accept(body.contact);eligible.push(body);}catch(error){errors.push(code(error));}}
    let best=eligible.sort((a,b)=>b.contact.payload.revision-a.contact.payload.revision)[0];
    if(states.some(state=>state==='conflict'||state==='revoked'))best=undefined;
    return {state:best?'found':'inconclusive',contact:best?.contact??null,lease:best?.lease??null,metrics:this.metrics(budget),route,errors,
      discovery_grants_access:false,encryption_key_possession_proven:false};
  });}
  publishContact(contact:SignedContact,leaseSeconds=300):Promise<Obj>{return this.serial(async()=>{
    const owner=verifyContact(contact);if(!same(owner.signing_key,validateSigningIdentity(this.identity)))fail('open_contact_owner_required');
    try{this.accept(contact);}catch(error){if(owner.status!=='revoked'||code(error)!=='open_control_revoked')throw error;}
    const budget=new LookupBudget(),route=await this.lookup(contactKey(this.keyId),'directory',budget);
    const leases:SignedOpen[]=[],errors:string[]=[],keys=new Set<string>(),addresses=new Set<string>();
    for(const node of route.candidates){if(keys.has(node.payload.signing_key.key_id))continue;
      try{const observed:{socket?:string}={},body=await this.call(node,'put',{contact,lease_seconds:leaseSeconds},budget,observed);
        if(addresses.has(observed.socket!))continue;leases.push(body.lease);keys.add(node.payload.signing_key.key_id);addresses.add(observed.socket!);
      }catch(error){errors.push(code(error));}if(leases.length===3)break;
    }
    return {state:leases.length===3?'leased':'degraded',confirmed_leases:leases.length,desired_leases:3,leases,metrics:this.metrics(budget),errors,physical_failure_domains_verified:false};
  });}
  handle(request:SignedOpen):SignedOpen{
    this.ready();if(!this.descriptor)fail('open_node_not_configured');
    const issued=now(),original=verifyRequest(request,{node:this.descriptor,now:issued});let result:Obj;
    try{
      const {action,body}=original;
      if(action==='hello'){
        if(body.node!==null){this.accept(body.node);const key=body.node.payload.signing_key.key_id;
          if(this.table.hasVerified(body.node))this.pending.delete(key);
          else if(this.pending.size>=32&&!this.pending.has(key))fail('open_pending_capacity',true);
          else this.pending.set(key,body.node);
        }result={node:this.descriptor};
      }else if(action==='find')result={nodes:this.table.replyCandidates(body.target,body.view)};
      else result=this.index!.handle(request,{now:issued});
    }catch(error){if(!(error instanceof NetworkCryptoError))throw error;
      result={error:{code:code(error),retryable:(error as any)?.retryable===true}};}
    return signResponse(this.identity,{request,node:this.descriptor,body:result,issued_at:issued,expires_at:Math.min(issued+60,original.expires_at)});
  }
  /** Real JOSE challenge encryption is async; ordinary routing stays synchronous. */
  async handleContact(request:SignedOpen):Promise<SignedOpen>{
    this.ready();if(!this.descriptor||!this.contact)fail('open_node_not_configured');
    verifyContactRpc(request,{node:this.descriptor});let result:Obj;
    try{result=await this.contact.handle(request);}
    catch(error){if(!(error instanceof NetworkCryptoError))throw error;
      result={error:{code:code(error),retryable:(error as any)?.retryable===true}};}
    this.ready();return signContactResponse(this.identity,{request,node:this.descriptor,body:result});
  }
}
