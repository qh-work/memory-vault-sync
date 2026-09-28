/** Existing Agent open profile: explicit contact approval and encrypted delivery. */
import path from 'node:path';
import {canonicalBytes,document,objectFields,validateSigningIdentity,validateEncryptionIdentity} from './crypto.ts';
import type {DocumentInput,SigningIdentityDocument,EncryptionIdentityDocument} from './crypto.ts';
import {absolutePath,readPrivate,NetworkError} from './io.ts';
import {loadClient} from './client-config.ts';
import type {Client} from './client-config.ts';
import {OpenDeliveryClient} from './open-delivery-client.ts';
import {OpenParticipant} from './open-participant.ts';
import {OpenContactClient,CONNECT_SCHEMA} from './open-contact-client.ts';
import type {SignedNode} from './open-control.ts';
export const OPEN_CLIENT_CONFIG='memory-vault-open-client-config/v1';
function fail(code:string):never{throw new NetworkError(code);}
export class OpenNetworkClient{
  readonly participant:OpenParticipant;
  readonly identity:SigningIdentityDocument;readonly encryption:EncryptionIdentityDocument;
  private readonly clientConfig:Client;private deliveryClient:OpenDeliveryClient|null=null;private closed=false;
  constructor(configPath:string,options:{clientConfigPath?:string;transport?:unknown}={}){
    if(options.transport!==undefined)fail('open_transport_override_unsupported');
    const config=objectFields(document(readPrivate(configPath,65536)!),
      ['schema_version','client_config_path','state_directory','encryption_key_path','seeds','allow_loopback']);
    if(config.schema_version!==OPEN_CLIENT_CONFIG)fail('open_invalid_client_config');
    const client=loadClient(config.client_config_path as string);this.clientConfig=client;
    if(options.clientConfigPath!==undefined&&loadClient(options.clientConfigPath).path!==client.path)fail('network_client_config_mismatch');
    if(!client.identity)fail('network_signing_identity_required');
    this.identity=document(readPrivate(client.identity,4096)!,4096) as unknown as SigningIdentityDocument;
    this.encryption=document(readPrivate(absolutePath(config.encryption_key_path),16384)!,16384) as unknown as EncryptionIdentityDocument;
    validateSigningIdentity(this.identity);validateEncryptionIdentity(this.encryption);
    const directory=absolutePath(config.state_directory);
    if(directory===path.dirname(client.vault))fail('network_separate_state_required');
    this.participant=new OpenParticipant(this.identity,directory,{seeds:config.seeds as unknown as SignedNode[],allow_loopback:config.allow_loopback as boolean});
  }
  close():void{if(this.closed)return;this.closed=true;this.deliveryClient?.close();this.deliveryClient=null;this.participant.close();}
  private delivery():OpenDeliveryClient{if(this.closed)fail('network_transport_closed');return this.deliveryClient??=new OpenDeliveryClient(this.participant,this.encryption,this.clientConfig);}
  private result(value:Record<string,any>):Record<string,any>{if(canonicalBytes(value).length>8192)fail('network_response_too_large');return value;}
  async connect(invitation?:unknown,requestId?:string):Promise<Record<string,any>>{
    if(invitation!=null){
      if(typeof invitation!=='object'||Array.isArray(invitation)||(invitation as any).schema_version!==CONNECT_SCHEMA)fail('open_private_invitation_unsupported');
      const result=await new OpenContactClient(this.participant,this.encryption).dispatch(invitation,requestId);
      return this.result({...result,profile:'open-routing-v1',network_accessed:true,open_messaging_supported:true});
    }
    return this.result({...await this.participant.join(),profile:'open-routing-v1',network_accessed:true,open_messaging_supported:true});
  }
  async discover(keyId?:string):Promise<Record<string,any>>{
    if(keyId===undefined)return {profile:'open-routing-v1',state:'target_key_required',global_member_list:false,network_accessed:false,discovery_grants_access:false};
    const {route,...result}=await this.participant.findContact(keyId);
    return {...result,profile:'open-routing-v1',network_accessed:true};
  }
  async send(requestId:string,recipients:string[],text='',memoryIds:string[]=[],control?:DocumentInput):Promise<Record<string,any>>{return this.result(await this.delivery().send(requestId,recipients,text,memoryIds,control));}
  async receive(limit=4):Promise<Record<string,any>>{return this.result(await this.delivery().receive(limit));}
  readMessage(messageId:string,offset=0):Record<string,any>{return this.result(this.delivery().readMessage(messageId,offset));}
  respondTo(..._args:any[]):never{return fail('open_hint_exchange_unsupported');}
  readReceivedBatch(..._args:any[]):never{return fail('open_hint_exchange_unsupported');}
}
