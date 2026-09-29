/** Durable same-database reservations shared by native and Python services.
 * These are promised-byte charges, not filesystem usage or physical custody.
 * The caller owns the transaction; no reservation API commits independently.
 */
import {readFileSync} from 'node:fs';
import {isProxy} from 'node:util/types';
import type {DatabaseSync} from 'node:sqlite';
import {document,NetworkCryptoError} from './crypto.ts';

type Obj=Record<string,any>;
export class CapacityError extends NetworkCryptoError {}
function fail(code:string):never{throw new CapacityError('open_capacity_'+code);}
export const CAPACITY_SCHEMA='memory-vault-open-capacity/v1';
function schema():Obj{
  let text:string;
  try{text=readFileSync(new URL('./memory_vault_open_capacity_schema.json',import.meta.url),'utf8');}
  catch(error){
    if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;
    text=readFileSync(new URL('../../../memory_vault_open_capacity_schema.json',import.meta.url),'utf8');
  }
  const value=JSON.parse(text);if(value.schema_version!==CAPACITY_SCHEMA)fail('schema_mismatch');return value;
}
const shared=schema();
export const DEFAULT_CAPACITY_POLICY:Readonly<CapacityPolicy>=Object.freeze({...shared.default_policy});
export const SERVICE_RESERVE_BYTES:number=shared.charges.service_reserve_bytes;
const U53=BigInt(Number.MAX_SAFE_INTEGER);
export interface CapacityPolicy{readonly maximum_reserved_bytes:number;readonly maximum_reservations:number;}
export interface CapacityUsage extends CapacityPolicy{
  readonly reserved_bytes:number|string;readonly reservations:number;readonly oversubscribed:boolean;
}
function number(value:unknown,minimum=0):number{
  if(typeof value!=='number'||!Number.isSafeInteger(value)||value<minimum)fail('invalid_policy');return value;
}
function policy(value:unknown):Readonly<CapacityPolicy>{
  if(value===null||typeof value!=='object'||Array.isArray(value)||isProxy(value))fail('invalid_policy');
  const proto=Object.getPrototypeOf(value);if(proto!==Object.prototype&&proto!==null)fail('invalid_policy');
  const keys=Reflect.ownKeys(value),names=['maximum_reserved_bytes','maximum_reservations'];
  if(keys.length!==names.length||keys.some(key=>typeof key!=='string'||!names.includes(key)))fail('invalid_policy');
  const descriptors=Object.getOwnPropertyDescriptors(value),result:Obj={};
  for(const key of names){const held=descriptors[key];if(!held||!Object.hasOwn(held,'value'))fail('invalid_policy');result[key]=number(held.value,1);}
  return Object.freeze(result) as Readonly<CapacityPolicy>;
}
export function translateCapacityError(error:unknown):unknown{
  if(error instanceof Error&&typeof (error as any).code==='string'&&(error as any).code.startsWith('ERR_SQLITE')&&
      error.message.startsWith('open_capacity_'))return new CapacityError(error.message);
  return error;
}
export function providerCharge(record:Uint8Array):number{
  const budget=(document(record,8192) as Obj).payload.budget;
  for(const name of ['max_live_bytes','max_meta_bytes','max_job_bytes','max_replay_records'])number(budget[name]);
  const charge=BigInt(budget.max_live_bytes)+BigInt(budget.max_meta_bytes)+BigInt(budget.max_job_bytes)+
    BigInt(budget.max_replay_records)*BigInt(shared.charges.provider_replay_bytes)+BigInt(shared.charges.provider_lease_bytes);
  if(charge>U53)fail('invalid_policy');return number(Number(charge),1);
}
export function contactCharge(purpose:unknown,maxItems:number,maxBytes:number):number{
  number(maxItems,1);number(maxBytes,1);if(purpose!=='knock'&&purpose!=='delivery')fail('invalid_reservation');
  const charge=BigInt(maxBytes)+(purpose==='delivery'?BigInt(maxItems)*BigInt(shared.charges.delivery_item_bytes):0n)+BigInt(shared.charges.contact_lease_bytes);
  if(charge>U53)fail('invalid_policy');return number(Number(charge),1);
}

export class CapacityAuthority{
  readonly db:DatabaseSync;private readonly requestedPolicy:Readonly<CapacityPolicy>|undefined;
  constructor(db:DatabaseSync,requestedPolicy?:CapacityPolicy){this.db=db;this.requestedPolicy=requestedPolicy===undefined?undefined:policy(requestedPolicy);}
  private transaction():void{if(!this.db.isTransaction)fail('transaction_required');}
  private boundPolicy():Readonly<CapacityPolicy>{
    const row=this.db.prepare('SELECT schema_version,maximum_reserved_bytes,maximum_reservations FROM open_capacity_policy WHERE singleton=1').get() as Obj|undefined;
    if(!row||row.schema_version!==CAPACITY_SCHEMA)fail('binding_missing');
    const actual=policy({maximum_reserved_bytes:row.maximum_reserved_bytes,maximum_reservations:row.maximum_reservations});
    if(this.requestedPolicy&&Object.keys(actual).some(name=>(this.requestedPolicy as any)[name]!==actual[name as keyof CapacityPolicy]))fail('policy_mismatch');
    return actual;
  }
  private writeLock():Readonly<CapacityPolicy>{
    this.transaction();this.db.exec('UPDATE open_capacity_policy SET singleton=singleton WHERE singleton=1');return this.boundPolicy();
  }
  checkPolicy():Readonly<CapacityPolicy>{return this.writeLock();}
  initialize():void{
    this.transaction();
    for(const sql of [...Object.values(shared.reservation_tables),...shared.capacity_tables])this.db.exec(sql as string);
    if(!this.db.prepare('SELECT 1 FROM open_capacity_policy WHERE singleton=1').get()){
      if(this.db.prepare('SELECT 1 FROM open_capacity_reservations LIMIT 1').get())fail('binding_missing');
      const selected=this.requestedPolicy??DEFAULT_CAPACITY_POLICY;
      this.db.prepare('INSERT INTO open_capacity_policy VALUES(1,?,?,?)').run(CAPACITY_SCHEMA,selected.maximum_reserved_bytes,selected.maximum_reservations);
    }
    this.writeLock();
    for(const row of this.db.prepare('SELECT lease_id,digest,record,retain_until,owner,allocation_id,root_digest FROM open_provider_resources').all() as Obj[])
      this.migrate('provider',row.lease_id,row.digest,providerCharge(row.record),row.retain_until,row.owner,row.allocation_id,row.root_digest);
    for(const row of this.db.prepare('SELECT lease_id,allocation_sha256,purpose,max_items,max_bytes,retain_until,owner,allocation_id FROM open_contact_resource_leases').all() as Obj[])
      this.migrate('contact',row.lease_id,row.allocation_sha256,contactCharge(row.purpose,row.max_items,row.max_bytes),row.retain_until,row.owner,row.allocation_id);
    for(const sql of shared.triggers)this.db.exec(sql);
    // Preserve preexisting promises even when migration reveals oversubscription.
  }
  private migrate(service:string,id:string,digest:string,charge:number,retain:number,owner:string,operation:string,rootDigest=''):void{
    const values=[service,id,digest,charge,number(retain),owner,operation,rootDigest];
    const old=this.db.prepare('SELECT service,reservation_id,digest,charge_bytes,retain_until,owner,operation_id,root_digest FROM open_capacity_reservations WHERE service=? AND reservation_id=?').get(service,id) as Obj|undefined;
    if(old){if(Object.values(old).some((value,index)=>value!==values[index]))fail('reservation_conflict');return;}
    this.db.prepare('INSERT INTO open_capacity_reservations VALUES(?,?,?,?,?,?,?,?)').run(...values);
  }
  usage():Readonly<CapacityUsage>{
    const selected=this.boundPolicy(),rows=this.db.prepare('SELECT charge_bytes FROM open_capacity_reservations').all() as Obj[];
    const reserved=rows.reduce((total,row)=>total+BigInt(number(row.charge_bytes,1)),BigInt(SERVICE_RESERVE_BYTES));
    return Object.freeze({...selected,reserved_bytes:reserved<=U53?Number(reserved):reserved.toString(),reservations:rows.length,
      oversubscribed:reserved>BigInt(selected.maximum_reserved_bytes)||rows.length>selected.maximum_reservations});
  }
  reserve(service:string,reservationId:string,inputDigest:string,chargeBytes:number,retainUntil:number,
    options:{owner:string;operation_id:string}):boolean{
    this.writeLock();if(!['ack','repair_index','contact_directory','mailbox','repair_copy'].includes(service))fail('invalid_service');
    for(const value of [reservationId,options.owner,options.operation_id])if(typeof value!=='string'||/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.exec(value)?.[0]!==value)fail('invalid_reservation');
    if(typeof inputDigest!=='string'||/^[0-9a-f]{64}$/.exec(inputDigest)?.[0]!==inputDigest)fail('invalid_reservation');
    number(chargeBytes,1);number(retainUntil);
    const old=this.db.prepare('SELECT 1 FROM open_capacity_reservations WHERE service=? AND reservation_id=?').get(service,reservationId);
    this.db.exec('SAVEPOINT open_capacity_reserve');
    try{
      this.migrate(service,reservationId,inputDigest,chargeBytes,retainUntil,options.owner,options.operation_id);
      if(!old&&this.usage().oversubscribed)fail('exhausted');
      this.db.exec('RELEASE open_capacity_reserve');return !old;
    }catch(error){this.db.exec('ROLLBACK TO open_capacity_reserve');this.db.exec('RELEASE open_capacity_reserve');throw error;}
  }
  private has(table:string,column:string,value:string):boolean{
    if(!this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table))return false;
    return !!this.db.prepare('SELECT 1 FROM '+table+' WHERE '+column+'=? LIMIT 1').get(value);
  }
  collectReleased(service:string,options:{now:number;limit?:number}):number{
    this.writeLock();const now=number(options.now),limit=options.limit??128;
    if(!['provider','contact','contact_directory'].includes(service)||!Number.isInteger(limit)||limit<1||limit>128)fail('invalid_collection');
    const rows=this.db.prepare('SELECT reservation_id,owner,operation_id,root_digest FROM open_capacity_reservations WHERE service=? AND retain_until<=? ORDER BY retain_until,reservation_id LIMIT ?').all(service,now,limit) as Obj[];
    let released=0;
    for(const row of rows){
      if(service==='contact_directory'){
        if(this.has('open_contact_directory_jobs','job_id',row.reservation_id))continue;
        this.db.prepare('DELETE FROM open_capacity_reservations WHERE service=? AND reservation_id=?').run(service,row.reservation_id);released++;
        continue;
      }
      const table=service==='provider'?'open_provider_resources':'open_contact_resource_leases';
      if(this.has(table,'lease_id',row.reservation_id))continue;
      if(service==='provider'){
        if(this.has('open_provider_facts','resource_id',row.reservation_id))continue;
        if(this.has('open_provider_status','root_digest',row.root_digest))continue;
        if(this.has('open_provider_replay','caller',row.owner)&&this.db.prepare('SELECT 1 FROM open_provider_replay WHERE caller=? AND allocation_id=? LIMIT 1').get(row.owner,row.operation_id))continue;
      }else if(['open_contact_policies','open_contact_requests','open_delivery_handles','open_delivery_messages'].some(name=>this.has(name,'lease_id',row.reservation_id)))continue;
      this.db.prepare('DELETE FROM open_capacity_reservations WHERE service=? AND reservation_id=?').run(service,row.reservation_id);released++;
    }
    return released;
  }
}
