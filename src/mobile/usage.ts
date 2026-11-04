import {DatabaseSync} from 'node:sqlite';import {createHash} from 'node:crypto';import {existsSync,lstatSync} from 'node:fs';import {isAbsolute} from 'node:path';
export const mobileUsageKinds=['question','conversation','pf_token','provider_token','graph_token','graph_get','download','directline_token','activity_post','activity_get','token_post'] as const;
export type MobileUsageKind=typeof mobileUsageKinds[number];
const fail=()=>Error('mobile_demo_allowance_exhausted');
/** Aggregate operational ceilings, not a currency meter. No message, token,
 * identity or session IDs are stored. Counters never reset on service restart. */
export class MobileUsage {
 #db:DatabaseSync;
 constructor(path:string,limits:Partial<Record<MobileUsageKind,number>>){
  if(!isAbsolute(path)||!Object.keys(limits).length||Object.entries(limits).some(([k,v])=>!mobileUsageKinds.includes(k as MobileUsageKind)||!Number.isSafeInteger(v)||Number(v)<1||Number(v)>100000))throw fail();const existed=existsSync(path);if(existed){const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>1024*1024)throw fail();}this.#db=new DatabaseSync(path);try{this.#db.exec('PRAGMA busy_timeout=1000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=256;');const hash=createHash('sha256').update(JSON.stringify(Object.entries(limits).sort(([a],[b])=>a.localeCompare(b)))).digest('hex');if(existed){if(this.#db.prepare('SELECT hash FROM meta WHERE id=1').get()?.hash!==hash)throw fail();}else{this.#db.exec('BEGIN IMMEDIATE; CREATE TABLE meta(id INTEGER PRIMARY KEY,hash TEXT NOT NULL); CREATE TABLE usage(kind TEXT PRIMARY KEY,used INTEGER NOT NULL,ceiling INTEGER NOT NULL);');this.#db.prepare('INSERT INTO meta VALUES(1,?)').run(hash);for(const [kind,limit]of Object.entries(limits))this.#db.prepare('INSERT INTO usage VALUES(?,0,?)').run(kind,limit!);this.#db.exec('COMMIT');}}catch{this.#db.close();throw fail();}
 }
 reserve(kind:MobileUsageKind){try{this.#db.exec('BEGIN IMMEDIATE');const row=this.#db.prepare('SELECT used,ceiling FROM usage WHERE kind=?').get(kind);if(!row||Number(row.used)>=Number(row.ceiling))throw fail();this.#db.prepare('UPDATE usage SET used=used+1 WHERE kind=?').run(kind);this.#db.exec('COMMIT');}catch{try{this.#db.exec('ROLLBACK');}catch{}throw fail();}}
 snapshot(){return Object.fromEntries(this.#db.prepare('SELECT kind,used,ceiling FROM usage ORDER BY kind').all().map(r=>[r.kind,{used:Number(r.used),ceiling:Number(r.ceiling)}]));}
 close(){this.#db.close();}
}
