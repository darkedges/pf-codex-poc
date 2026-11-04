import {DatabaseSync} from 'node:sqlite';import {createHash,randomUUID} from 'node:crypto';import {isAbsolute,dirname,resolve} from 'node:path';import {lstatSync,realpathSync,chmodSync} from 'node:fs';
export class DocumentJournalError extends Error{constructor(){super('document_read_unavailable');this.name='DocumentJournalError';}}
export class DocumentReadJournal{
 #db:DatabaseSync;
 constructor(path:string,profileHash:string){
  if(!isAbsolute(path)||!/^[a-f0-9]{64}$/.test(profileHash)||lstatSync(dirname(path)).isSymbolicLink()||realpathSync(dirname(path)).toLowerCase()!==resolve(dirname(path)).toLowerCase())throw new DocumentJournalError();
  try{const s=lstatSync(path);if(s.isSymbolicLink()||!s.isFile()||s.nlink!==1||s.size>2097152)throw new DocumentJournalError();}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  this.#db=new DatabaseSync(path,{timeout:1000,allowExtension:false});chmodSync(path,0o600);
  try{const db=this.#db,version=Number(db.prepare('PRAGMA user_version').get()?.user_version);if(![0,1].includes(version))throw Error();if(version===0&&db.prepare("SELECT COUNT(*) n FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").get()?.n!==0)throw Error();
   if(version===1){const names=db.prepare("SELECT name FROM sqlite_master WHERE type IN('table','view','trigger') AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(r=>r.name);if(names.join()!=='document_profile,document_reads'||db.prepare('SELECT COUNT(*) n FROM document_profile').get()?.n!==1||db.prepare('SELECT hash FROM document_profile WHERE singleton=1').get()?.hash!==profileHash)throw Error();}
   db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS document_profile(singleton INTEGER PRIMARY KEY CHECK(singleton=1),hash TEXT NOT NULL) STRICT; CREATE TABLE IF NOT EXISTS document_reads(handle TEXT PRIMARY KEY,grant_digest TEXT NOT NULL UNIQUE,grant_id TEXT,proof_hash TEXT UNIQUE,created_at INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN('pending','recovered'))) STRICT; PRAGMA user_version=1;");
   const old=db.prepare('SELECT hash FROM document_profile WHERE singleton=1').get();if(old&&old.hash!==profileHash)throw Error();if(!old)db.prepare('INSERT INTO document_profile VALUES(1,?)').run(profileHash);
  }catch{this.#db.close();throw new DocumentJournalError();}
 }
 claim(grantId:string,proofHash:string){
  if(!/^[A-Za-z0-9:_-]{1,160}$/.test(grantId)||!/^[-_A-Za-z0-9]{43}$/.test(proofHash))throw new DocumentJournalError();const db=this.#db;db.exec('BEGIN IMMEDIATE');try{if(db.prepare("SELECT COUNT(*) n FROM document_reads WHERE state='pending'").get()?.n!==0)throw Error();const handle=randomUUID();db.prepare("INSERT INTO document_reads VALUES(?,?,?,?,?,'pending')").run(handle,createHash('sha256').update(grantId).digest('hex'),grantId,proofHash,Date.now());db.exec('COMMIT');return handle;}catch{db.exec('ROLLBACK');throw new DocumentJournalError();}
 }
 pending(){return this.#db.prepare("SELECT handle,grant_id,proof_hash FROM document_reads WHERE state='pending' ORDER BY created_at").all().map(r=>({handle:String(r.handle),grantId:String(r.grant_id),tokenHash:String(r.proof_hash)}));}
 complete(handle:string){if(this.#db.prepare("UPDATE document_reads SET state='recovered' WHERE handle=?").run(handle).changes!==1)throw new DocumentJournalError();}
 pruneRecovered(now=Date.now()){if(!Number.isSafeInteger(now)||now<1)throw new DocumentJournalError();return Number(this.#db.prepare("UPDATE document_reads SET grant_id=NULL,proof_hash=NULL WHERE state='recovered' AND grant_id IS NOT NULL AND created_at<?").run(now-86400000).changes);}
 close(){this.#db.close();}
}
