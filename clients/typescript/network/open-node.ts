/** Standalone finite native HTTP node. Public TLS termination remains owner-run. */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {pathToFileURL} from 'node:url';
import {canonicalBytes,document,objectFields,documentSha256,validateSigningIdentity} from './crypto.ts';
import type {SigningIdentityDocument} from './crypto.ts';
import {absolutePath,readPrivate,openPrivateDatabase,NetworkError} from './io.ts';
import {OpenParticipant} from './open-participant.ts';
import {OpenCheckpoints} from './open-state.ts';
import {openTransportState} from './transport-state.ts';
import {writeNewPrivate} from './setup.ts';
import {issueNode,verifyNode,MAX_DESCRIPTOR_SECONDS} from './open-control.ts';
import type {SignedOpen,SignedNode} from './open-control.ts';
import type {IndexOptions} from './open-state.ts';
import type {ContactStateOptions} from './open-contact-state.ts';
import {PROFILE as CONTACT_PROFILE} from './open-contact.ts';
import {RPC_PATH,MAX_RPC_BYTES,NODE_PATH,MAX_NODE_BYTES,endpoint} from './open-transport.ts';

export const OPEN_NODE_CONFIG='memory-vault-open-node-config/v1';
export function openHTTPServer(participant:OpenParticipant):http.Server{
  const rate=new Map<string,[number,number]>();let global:[number,number]=[0,0];
  const used=new WeakSet<object>();
  const server=http.createServer({maxHeaderSize:16384,requestTimeout:3000,headersTimeout:3000,keepAliveTimeout:1},(request,response)=>{
    const reject=(status:number)=>{response.writeHead(status,{'Content-Length':'0','Connection':'close'});response.end();};
    if(used.has(request.socket)){request.socket.destroy();return;}used.add(request.socket);
    const current=Math.floor(performance.now()/1000),address=request.socket.remoteAddress??'';
    global=[current,global[0]===current?global[1]+1:1];
    const previous=rate.get(address),count=previous?.[0]===current?previous[1]+1:1;
    rate.delete(address);rate.set(address,[current,count]);if(rate.size>256)rate.delete(rate.keys().next().value!);
    if(global[1]>128||count>64){reject(429);return;}
    const lengths:string[]=[];
    for(let i=0;i<request.rawHeaders.length;i+=2)if(request.rawHeaders[i].toLowerCase()==='content-length')lengths.push(request.rawHeaders[i+1]);
    if(request.method==='GET'){
      if(request.url!==NODE_PATH){reject(404);return;}
      if((lengths.length>0&&(lengths.length!==1||lengths[0]!=='0'))||
        request.headers['transfer-encoding']!==undefined||request.headers['content-encoding']!==undefined){reject(400);return;}
      try{
        const encoded=canonicalBytes(participant.currentIntroduction(),MAX_NODE_BYTES);
        response.writeHead(200,{'Content-Type':'application/json','Content-Length':String(encoded.length),
          'Cache-Control':'no-store','Connection':'close'});response.end(encoded);
      }catch{reject(503);}
      return;
    }
    if(request.method!=='POST'||request.url!==RPC_PATH||lengths.length!==1||! /^[0-9]+$/.test(lengths[0])||
      Number(lengths[0])<1||Number(lengths[0])>MAX_RPC_BYTES||request.headers['transfer-encoding']!==undefined||request.headers['content-encoding']!==undefined){reject(400);return;}
    let size=0;const parts:Buffer[]=[];
    request.on('error',()=>request.socket.destroy());
    request.on('data',(part:Buffer)=>{size+=part.length;if(size>MAX_RPC_BYTES){request.socket.destroy();return;}parts.push(part);});
    request.on('end',async()=>{
      try{
        if(size!==Number(lengths[0]))throw new NetworkError('open_invalid_http_request');
        const message=document(Buffer.concat(parts),MAX_RPC_BYTES) as unknown as SignedOpen;
        const answer=await Promise.resolve(message.payload?.schema_version===CONTACT_PROFILE?participant.handleContact(message):participant.handle(message));
        const encoded=canonicalBytes(answer,MAX_RPC_BYTES);
        response.writeHead(200,{'Content-Type':'application/json','Content-Length':String(encoded.length),'Connection':'close'});response.end(encoded);
      }catch(error){reject(typeof (error as any)?.code==='string'&&(error as any).code.startsWith('ERR_SQLITE')?503:400);}
    });
  });
  server.maxConnections=8;server.maxRequestsPerSocket=1;
  server.on('connection',socket=>{const deadline=setTimeout(()=>socket.destroy(),3000);socket.once('close',()=>clearTimeout(deadline));});
  server.on('clientError',(_error,socket)=>socket.destroy());
  return server;
}
const samePublic=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(canonicalBytes(b));
/** Called only under the shared lifetime publication ownership lock. */
function replacePublicationFile(file:string,bytes:Uint8Array,maximum:number,expected:Buffer|null):void{
  const previous=readPrivate(file,maximum,true);
  if((previous===null)!==(expected===null)||previous&&expected&&!previous.equals(expected))throw new NetworkError('open_node_configuration_changed');
  const before=previous===null?null:fs.lstatSync(file);
  const temporary=file+'.'+randomBytes(16).toString('hex')+'.tmp';
  const created=writeNewPrivate(temporary,bytes);
  try{
    const current=readPrivate(file,maximum,true),named=current===null?null:fs.lstatSync(file);
    if((before===null)!==(named===null)||before&&named&&(before.ino!==named.ino||before.dev!==named.dev)||
      previous!==null&&current!==null&&!previous.equals(current))throw new NetworkError('open_node_configuration_changed');
    fs.renameSync(temporary,file);
    const directory=fs.openSync(path.dirname(file),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);
    try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
  }finally{
    try{const remaining=fs.lstatSync(temporary);if(remaining.ino===created.ino&&remaining.dev===created.dev)fs.unlinkSync(temporary);}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  }
}
class NodePublication{
  private current:SignedNode|null=null;
  private readonly introduction:string;
  private readonly binding:Record<string,any>;
  private readonly file:string;private readonly config:Record<string,any>;private readonly identity:SigningIdentityDocument;
  constructor(file:string,config:Record<string,any>,identity:SigningIdentityDocument){
    this.file=file;this.config=config;this.identity=identity;
    this.introduction=path.join(path.dirname(file),'node-introduction.json');
    const original=verifyNode(config.node,{allow_expired:true});
    if(original.status!=='active'||!samePublic(original.signing_key,validateSigningIdentity(identity)))throw new NetworkError('open_wrong_node');
    endpoint(original.base_url,config.allow_loopback);
    this.binding=Object.fromEntries(['signing_key','storage_epoch','base_url','roles'].map(name=>[name,(original as any)[name]]));
  }
  private checked(value:SignedNode){
    const raw=verifyNode(value,{allow_expired:true});
    if(raw.status!=='active')throw new NetworkError('open_control_revoked');
    if(Object.entries(this.binding).some(([name,value])=>!samePublic((raw as any)[name],value)))throw new NetworkError('open_node_publication_binding_mismatch');
    return raw;
  }
  refresh():SignedNode{
    const storedBytes=readPrivate(this.file,MAX_RPC_BYTES)!;
    const stored=document(storedBytes,MAX_RPC_BYTES);
    const {node:old,...originalConfig}=this.config,{node:next,...nextConfig}=stored;
    if(!samePublic(originalConfig,nextConfig))throw new NetworkError('open_node_configuration_changed');
    const now=Math.floor(Date.now()/1000);
    if(this.current&&this.current.payload.expires_at>now+300&&samePublic(next,this.current))return this.current;
    const introductionBytes=readPrivate(this.introduction,MAX_NODE_BYTES,true);
    const introduction=introductionBytes===null?null:document(introductionBytes,MAX_NODE_BYTES) as unknown as SignedNode;
    const candidates=[next as unknown as SignedNode,...(introduction?[introduction]:[])];
    const db=openTransportState(absolutePath(this.config.state_directory),{profile:'open-routing-v1',
      signing_key:validateSigningIdentity(this.identity),storage_epoch:this.binding.storage_epoch});
    let latest:SignedNode;
    try{
      const checkpoints=new OpenCheckpoints(db);checkpoints.initialize();
      const row=db.prepare("SELECT revision,digest,record,status,second_record FROM open_control_floors WHERE kind='node' AND key_id=?").get(this.identity.key_id) as any;
      if(row){
        if(row.status==='conflict'||row.second_record!==null)throw new NetworkError('open_control_conflict');
        if(row.status!=='active')throw new NetworkError('open_control_revoked');
        const record=document(row.record,MAX_NODE_BYTES) as unknown as SignedNode,raw=this.checked(record);
        if(raw.revision!==row.revision||documentSha256(record)!==row.digest)throw new NetworkError('open_node_publication_corrupt');
        candidates.push(record);
      }
      const revisions=new Map<number,string>();
      for(const candidate of candidates){
        const raw=this.checked(candidate),digest=documentSha256(candidate),previous=revisions.get(raw.revision);
        if(previous!==undefined&&previous!==digest)throw new NetworkError('open_control_conflict');
        revisions.set(raw.revision,digest);
      }
      latest=candidates.reduce((a,b)=>a.payload.revision>b.payload.revision?a:b);
      const raw=latest.payload;
      if(raw.expires_at<=now+300)latest=issueNode(this.identity,{base_url:raw.base_url,storage_epoch:raw.storage_epoch,
        roles:raw.roles,revision:raw.revision+1,issued_at:now,expires_at:now+MAX_DESCRIPTOR_SECONDS});
      if(!samePublic(next,latest))replacePublicationFile(this.file,Buffer.concat([canonicalBytes({...stored,node:latest}),Buffer.from('\n')]),MAX_RPC_BYTES,storedBytes);
      checkpoints.accept(latest);
      if(!introduction||!samePublic(introduction,latest))replacePublicationFile(this.introduction,canonicalBytes(latest),MAX_NODE_BYTES,introductionBytes);
    }finally{db.close();}
    this.current=latest;return latest;
  }
}
async function startOwnedOpenNode(configPath:string):Promise<{close:()=>Promise<void>}>{
  const parsed=document(readPrivate(absolutePath(configPath),MAX_RPC_BYTES)!,MAX_RPC_BYTES);
  const config=objectFields(parsed,['schema_version','identity_path','state_directory','node','seeds','allow_loopback','index_policy','listen_host','listen_port',
    ...(Object.hasOwn(parsed,'contact_policy')?['contact_policy']:[])]);
  if(config.schema_version!==OPEN_NODE_CONFIG)throw new NetworkError('open_invalid_node_config');
  if(config.listen_host!=='127.0.0.1'||!Number.isSafeInteger(config.listen_port)||Number(config.listen_port)<1024||Number(config.listen_port)>65535)
    throw new NetworkError('open_invalid_listener');
  const identity=document(readPrivate(absolutePath(config.identity_path),4096)!,4096) as unknown as SigningIdentityDocument;
  const publication=new NodePublication(absolutePath(configPath),config,identity);
  const descriptor=publication.refresh();
  const participant=new OpenParticipant(identity,absolutePath(config.state_directory),{descriptor,
    seeds:config.seeds as unknown as SignedNode[],allow_loopback:config.allow_loopback as boolean,index_policy:config.index_policy as IndexOptions,
    contact_policy:config.contact_policy as ContactStateOptions|undefined});
  const server=openHTTPServer(participant);let stopped=false,timer:ReturnType<typeof setTimeout>|undefined;
  try{await new Promise<void>((accept,reject)=>{server.once('error',reject);server.listen({host:'127.0.0.1',port:Number(config.listen_port),backlog:16},()=>{server.removeListener('error',reject);accept();});});}
  catch(error){participant.close();throw error;}
  const maintain=async(first=false)=>{
    try{
      participant.refreshDescriptor(publication.refresh());
      if(first)await participant.join();else await participant.maintain();
    }catch{/* Typed wire errors never become private diagnostic logs. */}
    if(!stopped)timer=setTimeout(()=>{void maintain();},2000);
  };
  void maintain(true);
  return {close:async()=>{if(stopped)return;stopped=true;clearTimeout(timer);participant.close();
    await new Promise<void>(accept=>{server.close(()=>accept());server.closeAllConnections();});}};
}
/** Same lifetime SQLite ownership lock as the Python node, separate from transport. */
export function acquirePublicationLock(configPath:string):()=>void{
  const db=openPrivateDatabase(absolutePath(configPath)+'.publication.sqlite3');
  try{db.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE');}
  catch(error){db.close();throw new NetworkError((error as any)?.errcode===5||
    (error as any)?.errcode===6?'open_node_publication_busy':'open_node_publication_unavailable');}
  let closed=false;return ()=>{if(!closed){closed=true;db.close();}};
}
export async function startOpenNode(configPath:string):Promise<{close:()=>Promise<void>}>{
  const release=acquirePublicationLock(configPath);
  try{
    const running=await startOwnedOpenNode(configPath);
    return {close:async()=>{try{await running.close();}finally{release();}}};
  }catch(error){release();throw error;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    if(process.argv.length!==4||process.argv[2]!=='--config')throw new NetworkError('open_invalid_node_config');
    const running=await startOpenNode(process.argv[3]);
    for(const signal of ['SIGINT','SIGTERM'] as const)process.once(signal,()=>{void running.close();});
  }catch(error){const code=(error as any)?.code;process.stderr.write(JSON.stringify({ok:false,code:typeof code==='string'&&/^[a-z][a-z0-9_]{1,63}$/.test(code)?code:'open_node_unavailable'})+'\n');process.exitCode=1;}
}
