/** Explicit open-network destinations. All DNS answers are checked once; only
 * a validated literal reaches a socket. No redirects, proxies or ambient auth. */
import dns from 'node:dns';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import {performance} from 'node:perf_hooks';
import {canonicalBytes,document} from './crypto.ts';
import type {DocumentInput} from './crypto.ts';
import {NetworkError} from './io.ts';
import type {RpcReply} from './open-routing.ts';
import {BLOB_PATH,MAX_BLOB_FRAME_BYTES,BLOB_PREFIX_BYTES,encodeBlobFrame,decodeBlobFrame} from './open-blob.ts';
import type {BlobFrame} from './open-blob.ts';

export const MAX_RPC_BYTES=65536, RPC_PATH='/open/v1/rpc';
export const MAX_NODE_BYTES=4096, NODE_PATH='/open/v1/node';
export interface BlobReply extends BlobFrame {
  readonly observed_address:string;
  /** Complete response frame bytes, including framing and the signed header. */
  readonly wire_bytes:number;
}
interface RawReply {raw:Uint8Array;observed_address:string;wire_bytes:number;}
const clock=()=>performance.now()/1000;
function fail(code:string,retryable=false):never{throw new NetworkError(code,retryable);}
const denied=new net.BlockList();
// The existing Python transport's public-address boundary, with multicast and
// shared address space excluded. IPv4-mapped IPv6 is evaluated as IPv4 below.
for(const cidr of ['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
  '172.16.0.0/12','192.0.0.0/29','192.0.0.170/31','192.0.2.0/24','192.168.0.0/16',
  '198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4',
  '::/128','::1/128','100::/64','2001::/23','2001:db8::/32','fc00::/7','fe80::/10','ff00::/8']){
  const [address,prefix]=cidr.split('/');denied.addSubnet(address,Number(prefix),net.isIP(address)===4?'ipv4':'ipv6');
}
function normalized(address:string):string{
  if(net.isIP(address)===4)return address;
  if(net.isIP(address)!==6||address.includes('%'))fail('open_destination_rejected');
  const value=new URL('https://['+address+']').hostname.slice(1,-1);
  const mapped=/^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(value);
  if(!mapped)return value;
  const a=parseInt(mapped[1],16),b=parseInt(mapped[2],16);
  return [a>>>8,a&255,b>>>8,b&255].join('.');
}
function loopback(address:string):boolean{return net.isIP(address)===4?address.split('.')[0]==='127':address==='::1';}
export function permittedAddress(value:string,allowLoopback=false):boolean{
  try{const address=normalized(value);return (allowLoopback&&loopback(address))||
    !denied.check(address,net.isIP(address)===4?'ipv4':'ipv6');}catch{return false;}
}
export function endpoint(value:unknown,allowLoopback=false):{scheme:'http'|'https';host:string;port:number}{
  if(typeof value!=='string'||!value||value.length>512||/[\s\\%?#@]/u.test(value))fail('open_destination_rejected');
  const parts=/^(https?):\/\/(\[[^\]]+\]|[^/:]+)(?::([0-9]+))?\/?$/i.exec(value);
  if(!parts)fail('open_destination_rejected');
  const scheme=parts[1].toLowerCase() as 'http'|'https',bracket=parts[2].startsWith('[');
  const host=(bracket?parts[2].slice(1,-1):parts[2]).toLowerCase();
  const port=parts[3]===undefined?(scheme==='https'?443:80):Number(parts[3]);
  if(!/^[\x00-\x7f]+$/.test(host)||!Number.isSafeInteger(port)||port<1||port>65535||
    (bracket&&net.isIP(host)!==6))fail('open_destination_rejected');
  const kind=net.isIP(host),local=host==='localhost'||(kind!==0&&loopback(normalized(host)));
  if(kind){if(!permittedAddress(host,allowLoopback))fail('open_destination_rejected');}
  else{
    if(host.includes(':')||/^[0-9.]+$/.test(host)||(host!=='localhost'&&(!host.includes('.')||host.endsWith('.'))))fail('open_destination_rejected');
    // Reject WHATWG's octal/hex/numeric IP aliases before any DNS request.
    try{const parsed=new URL(value);if(net.isIP(parsed.hostname.replace(/^\[|\]$/g,'')))fail('open_destination_rejected');}
    catch{fail('open_destination_rejected');}
  }
  if((local&&!allowLoopback)||(scheme!=='https'&&!(allowLoopback&&local)))fail('open_destination_rejected');
  return {scheme,host,port};
}
let resolutions=0;
/** Expiring a caller does not free an OS resolver slot until its callback runs. */
async function resolve(host:string,allowLoopback:boolean,deadline:number):Promise<string[]>{
  if(clock()>=deadline)fail('open_budget_exhausted',true);
  if(net.isIP(host))return [normalized(host)];
  if(resolutions>=3)fail('open_dns_capacity',true);
  resolutions++;
  return new Promise((accept,reject)=>{
    let done=false;
    const finish=(error?:unknown,value?:string[])=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):accept(value!);};
    const timer=setTimeout(()=>finish(new NetworkError('open_budget_exhausted',true)),Math.max(1,(deadline-clock())*1000));
    try{dns.lookup(host,{all:true,verbatim:true},(error,answers)=>{
      resolutions--;if(done)return;
      if(error){finish(new NetworkError('open_dns_unavailable',true));return;}
      try{
        if(!answers.length||answers.length>16||answers.some(a=>!permittedAddress(a.address,allowLoopback)))fail('open_destination_rejected');
        const addresses=[...new Set(answers.map(a=>normalized(a.address)))].sort((a,b)=>Number(a.includes(':'))-Number(b.includes(':'))||a.localeCompare(b,'en'));
        finish(undefined,addresses);
      }catch(error){finish(error);}
    });}catch{resolutions--;finish(new NetworkError('open_dns_unavailable',true));}
  });
}
export class OpenHTTPTransport{
  readonly allow_loopback:boolean;
  private closed=false;private active=0;
  private sockets=new Set<net.Socket>();
  constructor(options:{allow_loopback?:boolean}={}){
    if(options.allow_loopback!==undefined&&typeof options.allow_loopback!=='boolean')fail('open_invalid_local_policy');
    this.allow_loopback=options.allow_loopback??false;
  }
  close():void{this.closed=true;for(const socket of this.sockets)socket.destroy();}
  async request(base:string,value:DocumentInput,deadline:number):Promise<RpcReply>{
    const raw=canonicalBytes(document(value,MAX_RPC_BYTES),MAX_RPC_BYTES);
    const reply=await this.exchange(base,raw,deadline,false);
    return {response:document(reply.raw,MAX_RPC_BYTES) as any,observed_address:reply.observed_address,wire_bytes:reply.wire_bytes};
  }
  async requestBlob(base:string,header:DocumentInput,chunk:Uint8Array,deadline:number):Promise<BlobReply>{
    const raw=encodeBlobFrame(header,chunk);
    const reply=await this.exchange(base,raw,deadline,true);
    return {...decodeBlobFrame(reply.raw),observed_address:reply.observed_address,wire_bytes:reply.wire_bytes};
  }
  async requestNode(base:string,deadline:number):Promise<RpcReply>{
    const reply=await this.exchange(base,new Uint8Array(),deadline,false,true);
    const response=document(reply.raw,MAX_NODE_BYTES);
    if(!Buffer.from(reply.raw).equals(Buffer.from(canonicalBytes(response,MAX_NODE_BYTES))))fail('open_node_response_noncanonical');
    return {response:response as any,observed_address:reply.observed_address,wire_bytes:reply.wire_bytes};
  }
  /** All fixed paths share the same endpoint, DNS, socket and TLS policy. */
  private async exchange(base:string,raw:Uint8Array,deadline:number,blob:boolean,introduction=false):Promise<RawReply>{
    const destination=endpoint(base,this.allow_loopback),maximum=introduction?MAX_NODE_BYTES:blob?MAX_BLOB_FRAME_BYTES:MAX_RPC_BYTES;
    if(this.closed)fail('open_transport_closed');
    if(!Number.isFinite(deadline)||deadline<=clock()||this.active>=3)fail('open_budget_exhausted',true);
    this.active++;let socket:net.Socket|undefined,agent:http.Agent|undefined;
    try{
      const addresses=await resolve(destination.host,this.allow_loopback,deadline);
      if(this.closed)fail('open_transport_closed');
      for(const address of addresses.slice(0,2)){
        if(clock()>=deadline)fail('open_budget_exhausted',true);
        try{socket=await new Promise<net.Socket>((accept,reject)=>{
          const rawSocket=net.createConnection({host:address,port:destination.port});
          this.sockets.add(rawSocket);rawSocket.once('close',()=>this.sockets.delete(rawSocket));
          let current:net.Socket=rawSocket,done=false;
          const finish=(error?:unknown)=>{if(done)return;done=true;clearTimeout(timer);if(error){current.destroy();reject(error);}else accept(current);};
          const timer=setTimeout(()=>finish(new NetworkError('open_network_unavailable',true)),Math.max(1,Math.min(3,deadline-clock())*1000));
          rawSocket.on('error',()=>finish(new NetworkError('open_network_unavailable',true)));
          rawSocket.once('close',()=>{if(!done)finish(new NetworkError('open_network_unavailable',true));});
          rawSocket.once('connect',()=>{
            try{
              const observed=normalized(rawSocket.remoteAddress??'');
              if(observed!==address||!permittedAddress(observed,this.allow_loopback))fail('open_destination_rejected');
              if(destination.scheme==='http'){finish();return;}
              const secure=tls.connect({socket:rawSocket,servername:net.isIP(destination.host)?undefined:destination.host,
                rejectUnauthorized:true,checkServerIdentity:(_name,cert)=>tls.checkServerIdentity(destination.host,cert)});
              current=secure;this.sockets.add(secure);secure.once('close',()=>this.sockets.delete(secure));
              secure.on('error',()=>finish(new NetworkError('open_network_unavailable',true)));
              secure.once('secureConnect',()=>finish());
            }catch(error){finish(error);}
          });
        });break;}catch(error){if((error as any)?.code==='open_destination_rejected')throw error;}
      }
      if(this.closed)fail('open_transport_closed');
      if(clock()>=deadline)fail('open_budget_exhausted',true);
      if(!socket)fail('open_network_unavailable',true);
      const connected=socket,observed=normalized(connected.remoteAddress??'');
      agent=destination.scheme==='https'?new https.Agent({keepAlive:false}):new http.Agent({keepAlive:false});
      agent.createConnection=()=>connected;
      return await new Promise<RawReply>((accept,reject)=>{
        let done=false,bytes=0;const chunks:Buffer[]=[];
        const finish=(error?:unknown,response?:RawReply)=>{if(done)return;done=true;clearTimeout(timer);connected.destroy();error?reject(error):accept(response!);};
        const request=(destination.scheme==='https'?https:http).request({hostname:destination.host,port:destination.port,
          method:introduction?'GET':'POST',path:introduction?NODE_PATH:blob?BLOB_PATH:RPC_PATH,agent,maxHeaderSize:16384,
          headers:{'Content-Type':blob?'application/octet-stream':'application/json','Content-Length':String(raw.length),'Accept-Encoding':'identity','Connection':'close'}},response=>{
          if(response.statusCode!==200){finish(new NetworkError('open_request_rejected',[429,503].includes(response.statusCode??0)));return;}
          const encoding=response.headers['content-encoding'],length=response.headers['content-length'];
          if(blob||introduction){
            const prefix=introduction?'open_node':'open_blob';
            const names=response.rawHeaders.filter((_value,index)=>index%2===0).map(name=>name.toLowerCase());
            if(response.headers['content-type']?.toLowerCase()!==(introduction?'application/json':'application/octet-stream')||
              names.filter(name=>name==='content-type').length!==1||names.filter(name=>name==='content-length').length!==1||
              encoding!==undefined||response.headers['transfer-encoding']!==undefined){
              finish(new NetworkError(prefix+'_response_headers_rejected'));return;
            }
            if(length===undefined||!/^(0|[1-9][0-9]*)$/.test(length)||
              Number(length)<(introduction?1:BLOB_PREFIX_BYTES+1)||Number(length)>maximum){
              finish(new NetworkError(prefix+'_response_length_rejected'));return;
            }
          }
          if(encoding!==undefined&&String(encoding).trim().toLowerCase()!=='identity'){finish(new NetworkError('open_response_encoding_rejected'));return;}
          if(length!==undefined&&(!/^[0-9]+$/.test(length)||Number(length)>maximum)){finish(new NetworkError('open_response_too_large'));return;}
          response.on('data',(part:Buffer)=>{bytes+=part.length;if(bytes>maximum){finish(new NetworkError('open_response_too_large'));return;}chunks.push(part);});
          response.on('error',()=>finish(new NetworkError('open_network_unavailable',true)));
          response.on('aborted',()=>finish(new NetworkError('open_network_unavailable',true)));
          response.on('end',()=>{if(done)return;try{
            if(clock()>=deadline)fail('open_budget_exhausted',true);
            if((blob||introduction)&&bytes!==Number(length))fail((introduction?'open_node':'open_blob')+'_response_length_rejected');
            finish(undefined,{raw:Buffer.concat(chunks),observed_address:observed,wire_bytes:bytes});
          }catch(error){finish(error);}});
        });
        const timer=setTimeout(()=>finish(new NetworkError('open_budget_exhausted',true)),Math.max(1,(deadline-clock())*1000));
        request.setTimeout(Math.max(1,Math.min(3,deadline-clock())*1000),()=>finish(new NetworkError('open_network_unavailable',true)));
        request.on('error',()=>finish(new NetworkError(this.closed?'open_transport_closed':'open_network_unavailable',!this.closed)));
        request.end(raw);
      });
    }finally{socket?.destroy();agent?.destroy();this.active--;}
  }
}
