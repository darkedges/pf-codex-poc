import {DatabaseSync} from 'node:sqlite';
import {createHash,createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {lstatSync,realpathSync,openSync,closeSync,chmodSync} from 'node:fs';
import {isAbsolute,dirname,resolve} from 'node:path';
import {ProviderRelayError} from './provider-tool-relay.ts';

type Proof={providerToken?:string;brokerToken:string;agentToken:string;login:{idToken:string;nonce:string}};
type RecordValue={proof:Proof;claims:unknown;expiresAt:number};
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const denied=()=>new ProviderRelayError('binding_denied');
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=16000&&!/\s/.test(v);

// Dedicated single-host custody database. Its parent must be operator-protected
// (Windows owner/SYSTEM ACL); the encryption key comes from the secret manager.
export class RelayProofStore{
 private db:DatabaseSync;private key:Buffer;private max:number;
 constructor(c:{path:string;key:Uint8Array;maxEntries:number}){
  if(!isAbsolute(c.path)||resolve(c.path)!==c.path||!c.key||c.key.length!==32||!Number.isInteger(c.maxEntries)||c.maxEntries<1||c.maxEntries>10000)throw denied();
  const canonical=(v:string)=>process.platform==='win32'?v.toLowerCase():v;
  if(canonical(realpathSync(dirname(c.path)))!==canonical(dirname(c.path)))throw denied();
  try{const fd=openSync(c.path,'wx',0o600);closeSync(fd);}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw denied();}
  for(const path of [c.path,c.path+'-journal',c.path+'-wal',c.path+'-shm']){
   try{const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1)throw denied();}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw denied();}
  }
  chmodSync(c.path,0o600);this.key=Buffer.from(c.key);this.max=c.maxEntries;
  this.db=new DatabaseSync(c.path,{timeout:1000,allowExtension:false});
  this.db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
   CREATE TABLE IF NOT EXISTS relay_replay(id TEXT PRIMARY KEY,expires INTEGER NOT NULL) STRICT;
   CREATE TABLE IF NOT EXISTS relay_proofs(id TEXT PRIMARY KEY,expires INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('staged','active','cancelled','consumed')),sealed TEXT) STRICT;`);
 }
 close(){this.db.close();this.key.fill(0);}
 private transaction<T>(fn:()=>T):T{
  try{this.db.exec('BEGIN IMMEDIATE');try{const v=fn();this.db.exec('COMMIT');return v;}catch{this.db.exec('ROLLBACK');throw denied();}}catch{throw denied();}
 }
 private prune(){const now=Date.now();this.db.prepare('DELETE FROM relay_replay WHERE expires<=?').run(now);this.db.prepare('DELETE FROM relay_proofs WHERE expires<=?').run(now);}
 private room(table:'relay_replay'|'relay_proofs'){if(Number(this.db.prepare(`SELECT count(*) AS n FROM ${table}`).get()?.n)>=this.max)throw denied();}
 reserveReplay(issuer:string,jti:string,expires:number):boolean{
  if(!text(issuer)||!text(jti)||!Number.isSafeInteger(expires)||expires<=Date.now()||expires>Date.now()+60000)return false;
  return this.transaction(()=>{this.prune();const id=hash(JSON.stringify([issuer,jti]));if(this.db.prepare('SELECT id FROM relay_replay WHERE id=?').get(id))return false;this.room('relay_replay');this.db.prepare('INSERT INTO relay_replay VALUES(?,?)').run(id,expires);return true;});
 }
 accept(proof:Proof,claims:unknown,expires:number,signal:AbortSignal):void{
  if(signal.aborted||!text(proof?.brokerToken)||!text(proof.agentToken)||!text(proof.login?.idToken)||!text(proof.login.nonce)||!Number.isSafeInteger(expires)||expires<=Date.now()||expires>Date.now()+120000)throw denied();
  const id=hash(proof.brokerToken),raw=Buffer.from(JSON.stringify({proof,claims}));if(raw.length>64000)throw denied();
  const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.key,nonce);cipher.setAAD(Buffer.from(`relay-proof-v1:${id}:${expires}`));
  const sealed=Buffer.concat([nonce,cipher.update(raw),cipher.final(),cipher.getAuthTag()]).toString('base64');raw.fill(0);
  this.transaction(()=>{this.prune();this.room('relay_proofs');if(signal.aborted||expires<=Date.now())throw denied();this.db.prepare("INSERT INTO relay_proofs VALUES(?,?,'staged',?)").run(id,expires,sealed);});
 }
 commit(brokerToken:string,signal:AbortSignal):void{
  this.transaction(()=>{if(signal.aborted)throw denied();const result=this.db.prepare("UPDATE relay_proofs SET state='active' WHERE id=? AND state='staged' AND expires>?").run(hash(brokerToken),Date.now());if(result.changes!==1)throw denied();});
 }
 discard(brokerToken:string):void{
  if(!text(brokerToken))throw denied();
  this.transaction(()=>{this.prune();const id=hash(brokerToken);if(!this.db.prepare('SELECT id FROM relay_proofs WHERE id=?').get(id))this.room('relay_proofs');this.db.prepare("INSERT INTO relay_proofs VALUES(?,?,'cancelled',NULL) ON CONFLICT(id) DO UPDATE SET state='cancelled',sealed=NULL,expires=max(expires,excluded.expires)").run(id,Date.now()+300000);});
 }
 take(brokerToken:string):RecordValue{
  if(!text(brokerToken))throw denied();const id=hash(brokerToken);
  // Consume durably before decryption/return; corruption never restores authority.
  const row=this.transaction(()=>{const r=this.db.prepare("SELECT expires,sealed FROM relay_proofs WHERE id=? AND state='active' AND expires>?").get(id,Date.now());if(!r)throw denied();this.db.prepare("UPDATE relay_proofs SET state='consumed',sealed=NULL,expires=max(expires,?) WHERE id=?").run(Date.now()+300000,id);return r;});
  try{const sealed=Buffer.from(String(row.sealed),'base64'),decipher=createDecipheriv('aes-256-gcm',this.key,sealed.subarray(0,12));decipher.setAAD(Buffer.from(`relay-proof-v1:${id}:${row.expires}`));decipher.setAuthTag(sealed.subarray(-16));const raw=Buffer.concat([decipher.update(sealed.subarray(12,-16)),decipher.final()]);try{const value=JSON.parse(raw.toString()) as RecordValue;if(value.proof.brokerToken!==brokerToken)throw denied();return{...value,expiresAt:Number(row.expires)};}finally{raw.fill(0);}}catch{throw denied();}
 }
}
