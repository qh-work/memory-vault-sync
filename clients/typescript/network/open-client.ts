/** Existing Agent open profile: targeted contacts; messaging remains unavailable. */
import path from 'node:path';
import {document,objectFields,validateSigningIdentity,validateEncryptionIdentity} from './crypto.ts';
import type {SigningIdentityDocument,EncryptionIdentityDocument} from './crypto.ts';
import {absolutePath,readPrivate,NetworkError} from './io.ts';
import {loadClient} from './client-config.ts';
import {OpenParticipant} from './open-participant.ts';
import {OpenContactClient,CONNECT_SCHEMA} from './open-contact-client.ts';
import type {SignedNode} from './open-control.ts';
export const OPEN_CLIENT_CONFIG='memory-vault-open-client-config/v1';
function fail(code:string):never{throw new NetworkError(code);}
export class OpenNetworkClient{
  readonly participant:OpenParticipant;
  readonly identity:SigningIdentityDocument;readonly encryption:EncryptionIdentityDocument;
  constructor(configPath:string,options:{clientConfigPath?:string;transport?:unknown}={}){
    if(options.transport!==undefined)fail('open_transport_override_unsupported');
    const config=objectFields(document(readPrivate(configPath,65536)!),
      ['schema_version','client_config_path','state_directory','encryption_key_path','seeds','allow_loopback']);
    if(config.schema_version!==OPEN_CLIENT_CONFIG)fail('open_invalid_client_config');
    const client=loadClient(config.client_config_path as string);
    if(options.clientConfigPath!==undefined&&loadClient(options.clientConfigPath).path!==client.path)fail('network_client_config_mismatch');
    if(!client.identity)fail('network_signing_identity_required');
    this.identity=document(readPrivate(client.identity,4096)!,4096) as unknown as SigningIdentityDocument;
    this.encryption=document(readPrivate(absolutePath(config.encryption_key_path),16384)!,16384) as unknown as EncryptionIdentityDocument;
    validateSigningIdentity(this.identity);validateEncryptionIdentity(this.encryption);
    const directory=absolutePath(config.state_directory);
    if(directory===path.dirname(client.vault))fail('network_separate_state_required');
    this.participant=new OpenParticipant(this.identity,directory,{seeds:config.seeds as unknown as SignedNode[],allow_loopback:config.allow_loopback as boolean});
  }
  close():void{this.participant.close();}
  async connect(invitation?:unknown,requestId?:string):Promise<Record<string,any>>{
    if(invitation!=null){
      if(typeof invitation!=='object'||Array.isArray(invitation)||(invitation as any).schema_version!==CONNECT_SCHEMA)fail('open_private_invitation_unsupported');
      const result=await new OpenContactClient(this.participant,this.encryption).dispatch(invitation,requestId);
      return {...result,profile:'open-routing-v1',network_accessed:true};
    }
    return {...await this.participant.join(),profile:'open-routing-v1',network_accessed:true,open_messaging_supported:false};
  }
  async discover(keyId?:string):Promise<Record<string,any>>{
    if(keyId===undefined)return {profile:'open-routing-v1',state:'target_key_required',global_member_list:false,network_accessed:false,discovery_grants_access:false};
    const {route,...result}=await this.participant.findContact(keyId);
    return {...result,profile:'open-routing-v1',network_accessed:true};
  }
  send(..._args:any[]):never{return fail('open_messaging_unsupported');}
  receive(..._args:any[]):never{return fail('open_messaging_unsupported');}
  readMessage(..._args:any[]):never{return fail('open_messaging_unsupported');}
  respondTo(..._args:any[]):never{return fail('open_messaging_unsupported');}
  readReceivedBatch(..._args:any[]):never{return fail('open_messaging_unsupported');}
}
