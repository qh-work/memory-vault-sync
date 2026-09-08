/** Standalone finite native HTTP node. Public TLS termination remains owner-run. */
import http from 'node:http';
import {performance} from 'node:perf_hooks';
import {pathToFileURL} from 'node:url';
import {canonicalBytes,document,objectFields} from './crypto.ts';
import type {SigningIdentityDocument} from './crypto.ts';
import {absolutePath,readPrivate,NetworkError} from './io.ts';
import {OpenParticipant} from './open-participant.ts';
import type {SignedOpen,SignedNode} from './open-control.ts';
import type {IndexOptions} from './open-state.ts';
import type {ContactStateOptions} from './open-contact-state.ts';
import {PROFILE as CONTACT_PROFILE} from './open-contact.ts';
import {RPC_PATH,MAX_RPC_BYTES} from './open-transport.ts';

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
export async function startOpenNode(configPath:string):Promise<{close:()=>Promise<void>}>{
  const parsed=document(readPrivate(absolutePath(configPath),MAX_RPC_BYTES)!,MAX_RPC_BYTES);
  const config=objectFields(parsed,['schema_version','identity_path','state_directory','node','seeds','allow_loopback','index_policy','listen_host','listen_port',
    ...(Object.hasOwn(parsed,'contact_policy')?['contact_policy']:[])]);
  if(config.schema_version!==OPEN_NODE_CONFIG)throw new NetworkError('open_invalid_node_config');
  if(config.listen_host!=='127.0.0.1'||!Number.isSafeInteger(config.listen_port)||Number(config.listen_port)<1024||Number(config.listen_port)>65535)
    throw new NetworkError('open_invalid_listener');
  const identity=document(readPrivate(absolutePath(config.identity_path),4096)!,4096) as unknown as SigningIdentityDocument;
  const participant=new OpenParticipant(identity,absolutePath(config.state_directory),{descriptor:config.node as unknown as SignedNode,
    seeds:config.seeds as unknown as SignedNode[],allow_loopback:config.allow_loopback as boolean,index_policy:config.index_policy as IndexOptions,
    contact_policy:config.contact_policy as ContactStateOptions|undefined});
  const server=openHTTPServer(participant);let stopped=false,timer:ReturnType<typeof setTimeout>|undefined;
  try{await new Promise<void>((accept,reject)=>{server.once('error',reject);server.listen({host:'127.0.0.1',port:Number(config.listen_port),backlog:16},()=>{server.removeListener('error',reject);accept();});});}
  catch(error){participant.close();throw error;}
  const maintain=async(first=false)=>{
    try{if(first)await participant.join();else await participant.maintain();}catch{/* Typed wire errors never become private diagnostic logs. */}
    if(!stopped)timer=setTimeout(()=>{void maintain();},2000);
  };
  void maintain(true);
  return {close:async()=>{if(stopped)return;stopped=true;clearTimeout(timer);participant.close();
    await new Promise<void>(accept=>{server.close(()=>accept());server.closeAllConnections();});}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    if(process.argv.length!==4||process.argv[2]!=='--config')throw new NetworkError('open_invalid_node_config');
    const running=await startOpenNode(process.argv[3]);
    for(const signal of ['SIGINT','SIGTERM'] as const)process.once(signal,()=>{void running.close();});
  }catch(error){const code=(error as any)?.code;process.stderr.write(JSON.stringify({ok:false,code:typeof code==='string'&&/^[a-z][a-z0-9_]{1,63}$/.test(code)?code:'open_node_unavailable'})+'\n');process.exitCode=1;}
}
