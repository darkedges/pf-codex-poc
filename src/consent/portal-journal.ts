import {DatabaseSync} from 'node:sqlite';
import {randomUUID} from 'node:crypto';
import {chmodSync,lstatSync} from 'node:fs';
import {dirname,isAbsolute} from 'node:path';
import {PolicyError} from '../policy/contracts.ts';
export type PortalTrialApproval={reviewSha256:string;approved:true;expiresAt:number;maxConversations:number;maxTokenPosts:number;maxSuccessfulToolOperations:number};
export type PortalRecoveryIntent={attempt:string;tokenHash:string;grantId:string|null;createdAt:number;recoverAfter:number};
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
const grant=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9:_-]{1,160}$/.test(v);

// Controller-owned, credential-free durable state. Host must protect its directory
// and keep this object outside the web worker. No public route can authorize a trial.
export class PortalJournal{
 private db:DatabaseSync;private review:string;private active=new Set<string>();
 constructor(path:string,reviewSha256:string){
  if(!isAbsolute(path)||!/^[a-f0-9]{64}$/.test(reviewSha256)||lstatSync(dirname(path)).isSymbolicLink())throw new PolicyError('configuration');
  try{if(lstatSync(path).isSymbolicLink()||!lstatSync(path).isFile())throw new PolicyError('configuration');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  this.review=reviewSha256;this.db=new DatabaseSync(path,{timeout:1000,allowExtension:false});chmodSync(path,0o600);
  const version=Number(this.db.prepare('PRAGMA user_version').get()?.user_version);if(version>1){this.db.close();throw new PolicyError('configuration');}
  this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
   CREATE TABLE IF NOT EXISTS portal_trial(singleton INTEGER PRIMARY KEY CHECK(singleton=1),review TEXT NOT NULL,expires_at INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('approved','reserved','executing','finished')),attempt TEXT UNIQUE,conversations INTEGER NOT NULL DEFAULT 0 CHECK(conversations IN (0,1)),token_posts INTEGER NOT NULL DEFAULT 0 CHECK(token_posts IN (0,1)),successful_tools INTEGER NOT NULL DEFAULT 0 CHECK(successful_tools IN (0,1))) STRICT;
   CREATE TABLE IF NOT EXISTS portal_intents(attempt TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,grant_id TEXT UNIQUE,created_at INTEGER NOT NULL,recover_after INTEGER NOT NULL,recovered INTEGER NOT NULL DEFAULT 0 CHECK(recovered IN (0,1))) STRICT;
   PRAGMA user_version=1;`);
 }
 close(){this.active.clear();this.db.close();}
 private transaction<T>(fn:()=>T):T{this.db.exec('BEGIN IMMEDIATE');try{const value=fn();this.db.exec('COMMIT');return value;}catch(e){this.db.exec('ROLLBACK');throw e;}}
 authorizeTrial(approval:PortalTrialApproval){
  if(!approval||approval.approved!==true||approval.reviewSha256!==this.review||!Number.isSafeInteger(approval.expiresAt)||approval.expiresAt<=Date.now()||approval.expiresAt>Date.now()+86400000||approval.maxConversations!==1||approval.maxTokenPosts!==1||approval.maxSuccessfulToolOperations!==1)throw new PolicyError();
  this.transaction(()=>{if(this.db.prepare('SELECT 1 FROM portal_trial').get())throw new PolicyError('conflict');this.db.prepare("INSERT INTO portal_trial(singleton,review,expires_at,state) VALUES(1,?,?,'approved')").run(this.review,approval.expiresAt);});
 }
 beginConsent(tokenHash:string):string{
  if(!hash(tokenHash))throw new PolicyError('invalid_request');
  const attempt=this.transaction(()=>{
   const trial=this.db.prepare('SELECT * FROM portal_trial WHERE singleton=1').get();
   if(!trial||trial.review!==this.review||trial.state!=='approved'||Number(trial.expires_at)<=Date.now())throw new PolicyError();
   const id=randomUUID(),now=Date.now();
   this.db.prepare("UPDATE portal_trial SET state='reserved',attempt=? WHERE singleton=1").run(id);
   // Written before the remote consent POST, including when its response is lost.
   this.db.prepare('INSERT INTO portal_intents(attempt,token_hash,created_at,recover_after) VALUES(?,?,?,?)').run(id,tokenHash,now,now+300000);return id;
  });this.active.add(attempt);return attempt;
 }
 attachGrant(attempt:string,grantId:string){
  if(!grant(grantId)||!this.active.has(attempt))throw new PolicyError();
  this.transaction(()=>{const row=this.db.prepare('SELECT * FROM portal_intents WHERE attempt=? AND recovered=0').get(attempt);if(!row||row.grant_id&&row.grant_id!==grantId)throw new PolicyError();this.db.prepare('UPDATE portal_intents SET grant_id=? WHERE attempt=?').run(grantId,attempt);});
 }
 consume(attempt:string,event:'conversation'|'tokenPost'|'successfulTool'){
  if(!this.active.has(attempt)||!['conversation','tokenPost','successfulTool'].includes(event))throw new PolicyError();
  this.transaction(()=>{
   const row=this.db.prepare('SELECT * FROM portal_trial WHERE singleton=1').get(),intent=this.db.prepare('SELECT * FROM portal_intents WHERE attempt=?').get(attempt);
   if(!row||row.review!==this.review||row.state!=='executing'||row.attempt!==attempt||!intent?.grant_id||intent.recovered!==0||Number(intent.recover_after)<=Date.now()||Number(row.expires_at)<=Date.now())throw new PolicyError();
   const field=event==='conversation'?'conversations':event==='tokenPost'?'token_posts':'successful_tools';
   if(row[field]!==0||(event!=='conversation'&&row.conversations!==1)||(event==='successfulTool'&&row.token_posts!==1))throw new PolicyError();
   this.db.prepare(`UPDATE portal_trial SET ${field}=1 WHERE singleton=1`).run();
  });
 }
 beginExecution(attempt:string){
  if(!this.active.has(attempt))throw new PolicyError();
  this.transaction(()=>{const row=this.db.prepare('SELECT * FROM portal_trial WHERE singleton=1').get(),intent=this.db.prepare('SELECT * FROM portal_intents WHERE attempt=?').get(attempt);
   if(!row||row.review!==this.review||row.state!=='reserved'||row.attempt!==attempt||!intent?.grant_id||intent.recovered!==0||Number(intent.recover_after)<=Date.now()||Number(row.expires_at)<=Date.now())throw new PolicyError();
   this.db.prepare("UPDATE portal_trial SET state='executing' WHERE singleton=1").run();
  });
 }
 finish(attempt:string){this.transaction(()=>{const row=this.db.prepare('SELECT attempt FROM portal_trial WHERE singleton=1').get();if(row?.attempt!==attempt)throw new PolicyError();this.db.prepare("UPDATE portal_trial SET state='finished' WHERE singleton=1").run();this.db.prepare('UPDATE portal_intents SET recover_after=MIN(recover_after,?) WHERE attempt=?').run(Date.now(),attempt);});this.active.delete(attempt);}
 trialEnabled(){const row=this.db.prepare('SELECT review,state,expires_at,attempt FROM portal_trial WHERE singleton=1').get();return!!row&&row.review===this.review&&Number(row.expires_at)>Date.now()&&(row.state==='approved'||(row.state==='reserved'||row.state==='executing')&&this.active.has(String(row.attempt)));}
 canStartSignIn(){return this.trialSnapshot()?.state==='approved'&&this.trialEnabled();}
 trialSnapshot(){const row=this.db.prepare('SELECT review,state,expires_at,conversations,token_posts,successful_tools FROM portal_trial WHERE singleton=1').get();return row?{reviewSha256:String(row.review),state:String(row.state),expiresAt:Number(row.expires_at),conversations:Number(row.conversations),tokenPosts:Number(row.token_posts),successfulTools:Number(row.successful_tools)}:null;}
 pruneRecovered(){this.db.prepare('DELETE FROM portal_intents WHERE recovered=1 AND recover_after<?').run(Date.now()-86400000);}
 recoveryIntents():PortalRecoveryIntent[]{return this.db.prepare('SELECT attempt,token_hash,grant_id,created_at,recover_after FROM portal_intents WHERE recovered=0 ORDER BY created_at').all().map(r=>({attempt:String(r.attempt),tokenHash:String(r.token_hash),grantId:r.grant_id===null?null:String(r.grant_id),createdAt:Number(r.created_at),recoverAfter:Number(r.recover_after)}));}
 markRecovered(attempt:string){this.transaction(()=>{if(!this.db.prepare('SELECT 1 FROM portal_intents WHERE attempt=?').get(attempt))throw new PolicyError();this.db.prepare('UPDATE portal_intents SET recovered=1 WHERE attempt=?').run(attempt);this.db.prepare("UPDATE portal_trial SET state='finished' WHERE singleton=1 AND attempt=?").run(attempt);});this.active.delete(attempt);}
}
