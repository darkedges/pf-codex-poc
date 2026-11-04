import {DatabaseSync} from 'node:sqlite';import {isAbsolute,dirname,resolve} from 'node:path';import {lstatSync,realpathSync,chmodSync} from 'node:fs';
export type ChatConsentKind='chat'|'document';
const caps=Object.freeze({chatLogin:1,documentLogin:1,providerLogin:1,providerRedeem:1,documentRead:1,conversation:1,tokenPost:1,question:1,graphToken:1,graphRequest:2,sharepointDownload:1,pfTokenPost:12,directLineToken:1,conversationPost:1,activityPost:2,directLineGet:50});
export type ChatOperation=keyof typeof caps;
const proof=(s:string)=>/^[-_A-Za-z0-9]{43}$/.test(s),grant=(s:string)=>/^[A-Za-z0-9:_-]{1,160}$/.test(s),kind=(s:string)=>['chat','document'].includes(s);
// Dedicated one-session journal. Never a migration/reset of diagnostic budgets.
// Only verified login hashes and owned grant IDs are stored; no tokens or text.
export class DocumentChatJournal{
 #db:DatabaseSync;
 constructor(path:string,profile:{hash:string;expiresAt:number}){
  if(!isAbsolute(path)||!/^[a-f0-9]{64}$/.test(profile.hash)||!Number.isSafeInteger(profile.expiresAt)||profile.expiresAt<1||lstatSync(dirname(path)).isSymbolicLink()||realpathSync(dirname(path)).toLowerCase()!==resolve(dirname(path)).toLowerCase())throw Error('chat_journal_configuration');
  try{const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>2097152)throw Error('chat_journal_configuration');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  this.#db=new DatabaseSync(path,{timeout:1000,allowExtension:false});chmodSync(path,0o600);
  try{
   const db=this.#db,version=Number(db.prepare('PRAGMA user_version').get()?.user_version),names=db.prepare("SELECT name FROM sqlite_master WHERE type IN('table','view','trigger') AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(r=>r.name);
   if(version===0){if(names.length||profile.expiresAt<=Date.now()||profile.expiresAt>Date.now()+3600000)throw Error();}
   else if(version===1){if(names.join()!=='chat_consents,chat_operations,chat_profile'||db.prepare('SELECT COUNT(*) n FROM chat_profile').get()?.n!==1)throw Error();const old=db.prepare('SELECT hash,deadline FROM chat_profile WHERE singleton=1').get();if(old?.hash!==profile.hash||old.deadline!==profile.expiresAt)throw Error();}else throw Error();
   db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS chat_profile(singleton INTEGER PRIMARY KEY CHECK(singleton=1),hash TEXT NOT NULL,deadline INTEGER NOT NULL,phase INTEGER NOT NULL CHECK(phase IN(0,1,2))) STRICT; CREATE TABLE IF NOT EXISTS chat_consents(kind TEXT PRIMARY KEY CHECK(kind IN('chat','document')),proof_hash TEXT UNIQUE,grant_id TEXT UNIQUE,state TEXT NOT NULL CHECK(state IN('pending','recovered')),at INTEGER NOT NULL) STRICT; CREATE TABLE IF NOT EXISTS chat_operations(kind TEXT PRIMARY KEY,count INTEGER NOT NULL CHECK(count>=0)) STRICT; PRAGMA user_version=1;");
   if(version===0)db.prepare('INSERT INTO chat_profile VALUES(1,?,?,0)').run(profile.hash,profile.expiresAt);
  }catch{this.#db.close();throw Error('chat_journal_unavailable');}
 }
 #transaction<T>(fn:()=>T){this.#db.exec('BEGIN IMMEDIATE');try{const result=fn();this.#db.exec('COMMIT');return result;}catch{this.#db.exec('ROLLBACK');throw Error('chat_journal_denied');}}
 #live(){const p=this.#db.prepare('SELECT deadline,phase FROM chat_profile WHERE singleton=1').get();if(!p||Number(p.deadline)<=Date.now()||p.phase===2)throw Error();return p;}
 consentChoice(){const r=this.#db.prepare("SELECT count FROM chat_operations WHERE kind='consentChoice'").get();if(!r)return null;if(r.count!==0&&r.count!==1)throw Error('chat_journal_denied');return r.count===1;}
 recordConsentChoice(automatic:boolean){this.#transaction(()=>{if(typeof automatic!=='boolean'||this.#live().phase!==0||this.consentChoice()!==null||this.consent('chat')||this.#db.prepare("SELECT count FROM chat_operations WHERE kind='chatLogin'").get())throw Error();this.#db.prepare("INSERT INTO chat_operations VALUES('consentChoice',?)").run(automatic?1:0);});}
 consent(type:ChatConsentKind){if(!kind(type))throw Error('chat_journal_denied');const r=this.#db.prepare('SELECT * FROM chat_consents WHERE kind=?').get(type);return r?{kind:type,proofHash:r.proof_hash===null?null:String(r.proof_hash),grantId:r.grant_id===null?null:String(r.grant_id),state:String(r.state),createdAt:Number(r.at)}:null;}
 beginConsent(type:ChatConsentKind,hash:string){this.#transaction(()=>{const p=this.#live();if(p.phase!==0||!kind(type)||!proof(hash)||this.consent(type))throw Error();if(type==='document'){const chat=this.consent('chat');if(!chat?.grantId||chat.state!=='pending')throw Error();}this.#db.prepare("INSERT INTO chat_consents VALUES(?,?,NULL,'pending',?)").run(type,hash,Date.now());});}
 attachGrant(type:ChatConsentKind,hash:string,id:string){this.#transaction(()=>{this.#live();const c=this.consent(type);if(!proof(hash)||!grant(id)||!c||c.proofHash!==hash||c.grantId||c.state!=='pending')throw Error();this.#db.prepare('UPDATE chat_consents SET grant_id=? WHERE kind=?').run(id,type);});}
 // Authority-decreasing recovery only, after independently checking the exact
 // persisted consent ownership. May run after the live window expires.
 attachGrantForRecovery(type:ChatConsentKind,hash:string,id:string){this.#transaction(()=>{const c=this.consent(type);if(!proof(hash)||!grant(id)||!c||c.proofHash!==hash||c.grantId||c.state!=='pending')throw Error();this.#db.prepare('UPDATE chat_consents SET grant_id=? WHERE kind=?').run(id,type);});}
 beginTurn(){this.#transaction(()=>{if(this.#live().phase!==0||!['chat','document'].every(k=>{const c=this.consent(k as ChatConsentKind);return !!c?.grantId&&c.state==='pending';}))throw Error();this.#db.prepare('UPDATE chat_profile SET phase=1 WHERE singleton=1').run();});}
 consume(operation:ChatOperation){this.#transaction(()=>{const p=this.#live();if(!Object.hasOwn(caps,operation)||p.phase===1&&['chatLogin','documentLogin','providerLogin','providerRedeem'].includes(operation))throw Error();if(p.phase===0&&!['chatLogin','documentLogin','providerLogin','providerRedeem','pfTokenPost'].includes(operation))throw Error();const count=Number(this.#db.prepare('SELECT count FROM chat_operations WHERE kind=?').get(operation)?.count??0);if(count>=caps[operation])throw Error();this.#db.prepare('INSERT INTO chat_operations VALUES(?,?) ON CONFLICT(kind) DO UPDATE SET count=excluded.count').run(operation,count+1);});}
 pending(){return(['chat','document'] as const).map(k=>this.consent(k)).filter((c):c is NonNullable<typeof c>=>!!c&&c.state==='pending');}
 // Call only after independent persisted-policy revocation confirmation.
 markRevoked(type:ChatConsentKind,id:string){this.#transaction(()=>{const c=this.consent(type);if(!c||c.grantId!==id||!grant(id))throw Error();this.#db.prepare("UPDATE chat_consents SET state='recovered' WHERE kind=?").run(type);});}
 finish(){this.#transaction(()=>{if(this.pending().length||this.#db.prepare('SELECT COUNT(*) n FROM chat_consents').get()?.n===0)throw Error();this.#db.prepare('UPDATE chat_profile SET phase=2 WHERE singleton=1').run();});}
 snapshot(){const p=this.#db.prepare('SELECT deadline,phase FROM chat_profile WHERE singleton=1').get();return{closed:p?.phase===2,executing:p?.phase===1,expired:Number(p?.deadline)<=Date.now(),pending:this.pending().length,counts:Object.fromEntries(this.#db.prepare('SELECT kind,count FROM chat_operations').all().map(r=>[String(r.kind),Number(r.count)]))};}
 pruneRecovered(now=Date.now()){if(!Number.isSafeInteger(now)||now<1)throw Error('chat_journal_denied');return Number(this.#db.prepare("UPDATE chat_consents SET proof_hash=NULL,grant_id=NULL WHERE state='recovered' AND proof_hash IS NOT NULL AND at<?").run(now-86400000).changes);}
 close(){this.#db.close();}
}
