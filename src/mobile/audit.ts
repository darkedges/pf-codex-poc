import {DatabaseSync} from 'node:sqlite';import {createHmac,createHash} from 'node:crypto';import {existsSync,lstatSync} from 'node:fs';import {isAbsolute} from 'node:path';
const fields={
 'mobile.assertion.authorized':['action','grantId','grantVersion','scope','resource','organisation','humanRef','actorRef','issuer','audience','authenticationBasis','hardwareAttestation'],
 'mobile.pf.exchange.authorized':['action','grantId','scope','resource','issuerA','issuerB','audience']
};
const fail=()=>Error('mobile_audit_unavailable');
/** Private bounded metadata journal, never a transcript. The deployment owns
 * directory ACLs. One-day retention and a 2 MiB SQLite page ceiling are fixed. */
export class MobileAudit {
 #db:DatabaseSync;#key:Buffer;#now:()=>number;
 constructor(path:string,key:Buffer,now=Date.now){
  if(!isAbsolute(path)||!Buffer.isBuffer(key)||key.length!==32)throw fail();const existed=existsSync(path);if(existed){const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>2*1024*1024)throw fail();}
  this.#key=Buffer.from(key);this.#now=now;this.#db=new DatabaseSync(path);try{this.#db.exec('PRAGMA busy_timeout=1000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=512;');const hash=createHash('sha256').update(key).digest('hex');if(existed){if(this.#db.prepare('SELECT key_hash FROM meta WHERE id=1').get()?.key_hash!==hash)throw fail();}else{this.#db.exec('CREATE TABLE meta(id INTEGER PRIMARY KEY,key_hash TEXT NOT NULL); CREATE TABLE events(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,phase TEXT NOT NULL,scope TEXT NOT NULL,grant_ref TEXT NOT NULL,human_ref TEXT,actor_ref TEXT);');this.#db.prepare('INSERT INTO meta VALUES(1,?)').run(hash);}this.maintain();}catch{this.#db.close();throw fail();}
 }
 maintain(){try{this.#db.prepare('DELETE FROM events WHERE at<=?').run(this.#now()-86400000);if(this.#db.prepare('PRAGMA quick_check').get()?.quick_check!=='ok')throw fail();}catch{throw fail();}}
 write(value:unknown){
  try{const e=value as Record<string,unknown>,allowed=fields[e?.action as keyof typeof fields];if(!allowed||!e||Object.keys(e).sort().join()!==[...allowed].sort().join()||!['copilot.invoke','m365.document.read'].includes(String(e.scope))||e.resource!=='sharepoint:approved-research'||typeof e.grantId!=='string'||!e.grantId||e.grantId.length>160)throw fail();for(const key of allowed)if(typeof e[key]==='string'&&(String(e[key]).length>2048||/[\u0000-\u001f]/.test(String(e[key]))))throw fail();
   const ref=(name:string,v:unknown)=>v===undefined?null:createHmac('sha256',this.#key).update(JSON.stringify([name,v])).digest('hex');this.maintain();this.#db.exec('BEGIN IMMEDIATE');try{this.#db.prepare('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT max(0,(SELECT count(*) FROM events)-4094))').run();this.#db.prepare('INSERT INTO events(at,phase,scope,grant_ref,human_ref,actor_ref) VALUES(?,?,?,?,?,?)').run(this.#now(),String(e.action),String(e.scope),ref('grant',e.grantId),ref('human',e.humanRef),ref('actor',e.actorRef));this.#db.exec('COMMIT');}catch{this.#db.exec('ROLLBACK');throw fail();}
  }catch{throw fail();}
 }
 close(){this.#db.close();this.#key.fill(0);}
}
