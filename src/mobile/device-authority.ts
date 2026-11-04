import { createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { isAbsolute } from 'node:path';
import { existsSync, lstatSync } from 'node:fs';
import { jwtVerify } from 'jose';
import { bodyHash } from '../policy/protocol.ts';
import type { VerifiedLogin } from '../policy/contracts.ts';

// This protocol is deliberately separate from the APK's local device-test key/purpose.
export const mobileDeviceDomain = 'federated-copilot/mobile-presence/v1\n';
type Profile = { origin:string; agent:{issuer:string;subject:string}; organisation:string;
 capabilities:{scope:string;resource:string}[]; termsVersion:string;executionLeaseSeconds?:60|180 };
type Human = Pick<VerifiedLogin,'issuer'|'subject'|'audience'|'authTime'>;
type Binding = {human:Human;agent:Profile['agent'];organisation:string;capabilities:Profile['capabilities']};
export type MobileRequestEvidence=Binding&{type:'registered-device-key';hardwareAttestation:'UNVERIFIED';enrollmentId:string;enrollmentExpiresAt:number;consentId:string;sessionId:string;verifiedAt:number;expiresAt:number;requestPath:string;requestBodyHash:string};
type Options = {database:string;profile:Profile;loginVerifier:{verify(token:string,nonce:string):Promise<VerifiedLogin>};
 current(binding:Binding):Promise<void>;now?:()=>number};
type Enrollment = {id:string;key:string;human:Human;expires:number;version:string;consentId:string;revoked:boolean};
type Challenge = {id:string;value:string;kind:'enroll'|'resume';key:string;sessionKey:string;human:Human;
 enrollmentId:string;version:string;expires:number};
type Session = {id:string;enrollmentId:string;version:string;key:string;expires:number};
type Proof = {idToken:string;nonce:string};
type Completion = {challengeId:string;signature:string};
const DAY=86400000,deny=()=>new Error('mobile_authorization_denied');
function immutable<T>(value:T):T{if(value&&typeof value==='object'){for(const child of Object.values(value))immutable(child);Object.freeze(value);}return value;}
function exact(value:unknown,keys:string[]){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join()!==[...keys].sort().join())throw deny();
}
function b64(value:unknown,max=2048):Buffer{
 if(typeof value!=='string'||!value||value.length>max||!/^[\w-]+$/.test(value))throw deny();
 const result=Buffer.from(value,'base64url');if(result.toString('base64url')!==value)throw deny();return result;
}
function key(value:string){
 const der=b64(value),result=createPublicKey({key:der,format:'der',type:'spki'});
 if(result.asymmetricKeyType!=='ec'||result.asymmetricKeyDetails?.namedCurve!=='prime256v1'||!result.export({type:'spki',format:'der'}).equals(der))throw deny();
 return result;
}
function sameHuman(a:Human,b:Human){return a.issuer===b.issuer&&a.subject===b.subject&&a.audience===b.audience;}

/** Internal BFF component, not an HTTP endpoint or a PF grant issuer.
 * Registered-key evidence MUST NOT be substituted for a fresh VerifiedLogin.
 * The deployment must protect this database and inject authoritative registry checks.
 */
export class MobileDeviceAuthority {
 #evidence=new WeakMap<object,MobileRequestEvidence>();
 readonly termsHash:string;
 private db:DatabaseSync;
 private profile:Profile;
 private options:Options;
 constructor(options:Options){
  const p=structuredClone(options.profile),url=new URL(p.origin);
  if(url.protocol!=='https:'||url.origin!==p.origin||!isAbsolute(options.database)||!p.agent?.issuer||!p.agent.subject||!p.organisation||!p.termsVersion||!p.capabilities?.length||p.capabilities.length>16||p.capabilities.some(c=>!c.scope||!c.resource)||typeof options.current!=='function')throw deny();
  if(p.executionLeaseSeconds!==undefined&&![60,180].includes(p.executionLeaseSeconds))throw deny();
  this.profile=p;this.options=options;this.termsHash=bodyHash(JSON.stringify(p));
  const existed=existsSync(options.database);if(existed&&(lstatSync(options.database).isSymbolicLink()||!lstatSync(options.database).isFile()||lstatSync(options.database).size>2*1024*1024))throw deny();
  this.db=new DatabaseSync(options.database);
  try{
   this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=512;');
   if(existed){
    const row=this.db.prepare('SELECT seal FROM mobile_meta WHERE id=1').get();if(row?.seal!==this.termsHash)throw deny();
   }else{
    this.db.exec('BEGIN IMMEDIATE; CREATE TABLE mobile_meta(id INTEGER PRIMARY KEY,seal TEXT NOT NULL); CREATE TABLE mobile_records(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(kind,id));');
    this.db.prepare('INSERT INTO mobile_meta VALUES(1,?)').run(this.termsHash);this.db.exec('COMMIT');
   }
  }catch{this.db.close();throw deny();}
 }
 private now(){const n=(this.options.now??Date.now)();if(!Number.isSafeInteger(n)||n<0)throw deny();return n;}
 private get<T>(kind:string,id:string):T|undefined{
  if(this.db.prepare('SELECT seal FROM mobile_meta WHERE id=1').get()?.seal!==this.termsHash)throw deny();
  if(typeof id!=='string'||!id||id.length>256)throw deny();
  const row=this.db.prepare('SELECT data FROM mobile_records WHERE kind=? AND id=?').get(kind,id);return row?JSON.parse(String(row.data)):undefined;
 }
 private put(kind:string,id:string,data:unknown,expires:number){this.db.prepare('INSERT INTO mobile_records VALUES(?,?,?,?)').run(kind,id,JSON.stringify(data),expires);}
 private replace(kind:string,id:string,data:unknown,expires:number){this.db.prepare('UPDATE mobile_records SET data=?,expires=? WHERE kind=? AND id=?').run(JSON.stringify(data),expires,kind,id);}
 private transaction<T>(fn:()=>T):T{
  this.db.exec('BEGIN IMMEDIATE');try{const result=fn();this.db.exec('COMMIT');return result;}catch(error){this.db.exec('ROLLBACK');throw error;}
 }
 private prune(){this.db.prepare("DELETE FROM mobile_records WHERE kind IN ('challenge','replay','login') AND expires<?").run(this.now()-DAY);}
 private capacity(kind:string,max:number){const row=this.db.prepare('SELECT COUNT(*) AS n FROM mobile_records WHERE kind=?').get(kind);if(Number(row?.n)>=max)throw deny();}
 private binding(human:Human):Binding{return structuredClone({human,agent:this.profile.agent,organisation:this.profile.organisation,capabilities:this.profile.capabilities});}
 private async current(human:Human){try{await this.options.current(this.binding(human));}catch{throw deny();}}
 private enrollment(id:string,version?:string){const e=this.get<Enrollment>('enrollment',id);if(!e||e.revoked||e.expires<=this.now()||(version!==undefined&&e.version!==version))throw deny();return e;}
 private session(id:string){const s=this.get<Session>('session',id);if(!s||s.expires<=this.now())throw deny();const e=this.enrollment(s.enrollmentId,s.version);return{s,e};}
 private async login(proof:Proof){
  exact(proof,['idToken','nonce']);const login=await this.options.loginVerifier.verify(proof.idToken,proof.nonce);
  const now=this.now();if(login.expiresAt<=now||login.authTime>now+5000||login.authTime<now-300000)throw deny();return login;
 }
 async beginEnrollment(proof:Proof,input:{devicePublicKeySpki:string;sessionPublicKeySpki:string;termsHash:string}){
  try{
   exact(input,['devicePublicKeySpki','sessionPublicKeySpki','termsHash']);key(input.devicePublicKeySpki);key(input.sessionPublicKeySpki);
   if(input.devicePublicKeySpki===input.sessionPublicKeySpki||input.termsHash!==this.termsHash)throw deny();
   const login=await this.login(proof),human:Human={issuer:login.issuer,subject:login.subject,audience:login.audience,authTime:login.authTime};await this.current(human);
   return this.transaction(()=>{
    this.prune();this.capacity('challenge',128);this.capacity('login',4096);
    if(this.get('login',login.tokenHash)||this.get('login',login.nonceHash))throw deny();
    const id=bodyHash(input.devicePublicKeySpki),old=this.get<Enrollment>('enrollment',id);
    if(old&&!sameHuman(old.human,human))throw deny();
    if(!old)this.capacity('enrollment',128);
    this.put('login',login.tokenHash,{},this.now()+DAY);
    this.put('login',login.nonceHash,{},this.now()+DAY);
    return this.challenge({kind:'enroll',key:input.devicePublicKeySpki,sessionKey:input.sessionPublicKeySpki,human,enrollmentId:id,version:old?.version??'',expires:Math.min(this.now()+120000,login.expiresAt)});
   });
  }catch{throw deny();}
 }
 private challenge(data:Omit<Challenge,'id'|'value'>){
  const c:Challenge={...data,id:randomUUID(),value:`${data.kind}:${randomBytes(32).toString('base64url')}`};
  this.put('challenge',c.id,c,c.expires);return{challengeId:c.id,challenge:c.value,expiresAt:c.expires};
 }
 async beginResume(input:{enrollmentId:string;sessionPublicKeySpki:string}){
  try{
   exact(input,['enrollmentId','sessionPublicKeySpki']);key(input.sessionPublicKeySpki);
   const e=this.enrollment(input.enrollmentId);if(e.key===input.sessionPublicKeySpki)throw deny();await this.current(e.human);
   return this.transaction(()=>{
    this.enrollment(e.id,e.version);this.prune();this.capacity('challenge',128);
    return this.challenge({kind:'resume',key:e.key,sessionKey:input.sessionPublicKeySpki,human:e.human,enrollmentId:e.id,version:e.version,expires:Math.min(this.now()+60000,e.expires)});
   });
  }catch{throw deny();}
 }
 async completeEnrollment(input:Completion){return this.complete(input,'enroll');}
 async completeResume(input:Completion){return this.complete(input,'resume');}
 private async complete(input:Completion,kind:Challenge['kind']){
  try{
   exact(input,['challengeId','signature']);
   // Persist consumption before any asynchronous check, including failed signature checks.
   const c=this.transaction(()=>{const c=this.get<Challenge>('challenge',input.challengeId);if(!c)throw deny();this.db.prepare("DELETE FROM mobile_records WHERE kind='challenge' AND id=?").run(c.id);return c;});
   if(c.kind!==kind||c.expires<=this.now()||!verify('sha256',Buffer.from(mobileDeviceDomain+c.value),key(c.key),b64(input.signature,256)))throw deny();
   await this.current(c.human);
   return this.transaction(()=>{
    if(c.expires<=this.now())throw deny();
    let e:Enrollment;
    if(kind==='resume')e=this.enrollment(c.enrollmentId,c.version);
    else{
     const old=this.get<Enrollment>('enrollment',c.enrollmentId);if((old?.version??'')!==c.version)throw deny();
     e={id:c.enrollmentId,key:c.key,human:c.human,expires:this.now()+30*DAY,version:randomUUID(),consentId:randomUUID(),revoked:false};
     if(old)this.replace('enrollment',e.id,e,e.expires);else this.put('enrollment',e.id,e,e.expires);
    }
    // One foreground session per device; new unlock invalidates the old one.
    for(const row of this.db.prepare("SELECT id,data FROM mobile_records WHERE kind='session'").all()){
     if(JSON.parse(String(row.data)).enrollmentId===e.id)this.db.prepare("DELETE FROM mobile_records WHERE kind='session' AND id=?").run(String(row.id));
    }
    this.capacity('session',128);
    const serverTime=this.now(),s:Session={id:randomUUID(),enrollmentId:e.id,version:e.version,key:c.sessionKey,expires:Math.min(serverTime+15*60000,e.expires)};
    this.put('session',s.id,s,s.expires);return{enrollmentId:e.id,enrollmentExpiresAt:e.expires,sessionId:s.id,sessionExpiresAt:s.expires,serverTime};
   });
  }catch{throw deny();}
 }
 async authorize(sessionId:string,proof:string,request:{method:string;path:string;body:string}){
  try{
   exact(request,['method','path','body']);if(request.method!=='POST'||!['/v1/mobile/chat/messages','/v1/mobile/chat/result','/v1/mobile/chat/cancel','/v1/mobile/access/approve','/v1/mobile/access/status','/v1/mobile/access/revoke'].includes(request.path)||typeof request.body!=='string'||Buffer.byteLength(request.body)>16000||typeof proof!=='string'||proof.length>4096)throw deny();
   const {s,e}=this.session(sessionId);
   const {payload:p,protectedHeader:h}=await jwtVerify(proof,key(s.key),{algorithms:['ES256'],typ:'fc-mobile-request+jwt',issuer:s.id,subject:s.id,audience:this.profile.origin,currentDate:new Date(this.now()),clockTolerance:0,maxTokenAge:60,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti','htm','htu','body_hash']});
   exact(h,['alg','typ']);exact(p,['iss','sub','aud','iat','nbf','exp','jti','htm','htu','body_hash']);
   if(p.aud!==this.profile.origin||![p.iat,p.nbf,p.exp].every(Number.isSafeInteger)||Number(p.exp)-Number(p.iat)>60||Number(p.exp)<=Number(p.iat)||p.nbf!==p.iat||typeof p.jti!=='string'||!/^[\w-]{16,128}$/.test(p.jti)||p.htm!==request.method||p.htu!==this.profile.origin+request.path||p.body_hash!==bodyHash(request.body))throw deny();
   this.transaction(()=>{this.session(s.id);this.prune();this.capacity('replay',8192);this.put('replay',bodyHash(s.id+'\n'+p.jti),{},Number(p.exp)*1000);});
   await this.current(e.human);
   this.session(s.id);
   const evidence:MobileRequestEvidence=immutable({type:'registered-device-key',hardwareAttestation:'UNVERIFIED',...this.binding(e.human),enrollmentId:e.id,enrollmentExpiresAt:e.expires,consentId:e.consentId,sessionId:s.id,verifiedAt:this.now(),expiresAt:Math.min(this.now()+(this.profile.executionLeaseSeconds??60)*1000,s.expires,e.expires),requestPath:request.path,requestBodyHash:bodyHash(request.body)});
   this.#evidence.set(evidence,structuredClone(evidence));return evidence;
  }catch{throw deny();}
 }
 async revalidateEvidence(value:unknown):Promise<MobileRequestEvidence>{
  try{
   if(!value||typeof value!=='object')throw deny();const record=this.#evidence.get(value);if(!record||record.expiresAt<=this.now())throw deny();
   const {e}=this.session(record.sessionId);if(e.id!==record.enrollmentId||e.consentId!==record.consentId)throw deny();
   await this.current(e.human);this.session(record.sessionId);if(record.expiresAt<=this.now())throw deny();
   return immutable(structuredClone(record));
  }catch{throw deny();}
 }
 async revokeEnrollment(proof:Proof,id:string){
  try{const login=await this.login(proof);this.transaction(()=>{
   const e=this.get<Enrollment>('enrollment',id);if(!e||!sameHuman(e.human,login))throw deny();
   e.revoked=true;e.version=randomUUID();this.replace('enrollment',e.id,e,e.expires);
  });}catch{throw deny();}
 }
 // Trusted server startup only: a new process cannot restore a prior foreground
 // conversation. Enrollment, absolute expiry, replay and login history survive.
 resetForegroundSessions(){this.transaction(()=>{this.db.prepare("DELETE FROM mobile_records WHERE kind IN ('session','challenge')").run();});}
 close(){this.db.close();}
}
