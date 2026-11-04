import {DatabaseSync} from 'node:sqlite';import {readdirSync,lstatSync,realpathSync} from 'node:fs';import {isAbsolute,resolve} from 'node:path';import {PolicyError} from '../policy/contracts.ts';import {PortalSessionJournal} from './portal-session-journal.ts';import {portalSessionPolicy} from './portal-session-policy.ts';
// Stopped-owner maintenance only. No record/file deletion, renewal or allowance reset.
export function maintainPortalSessions(directory:string,options:{workerStopped:boolean;apply:boolean}){
 const same=(a:string,b:string)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
 if(options.workerStopped!==true||typeof options.apply!=='boolean'||!isAbsolute(directory)||lstatSync(directory).isSymbolicLink()||!same(realpathSync(directory),resolve(directory)))throw new PolicyError('configuration');
 const result={scanned:0,expired:0,eligible:0,pending:0,metadataRemoved:0,applied:options.apply};const now=Date.now();
 for(const name of readdirSync(directory)){
  if(!/^sessions\.[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\.sqlite$/.test(name))continue;
  const path=resolve(directory,name),stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.size>262144)throw new PolicyError('configuration');
  const db=new DatabaseSync(path,{readOnly:true,allowExtension:false,timeout:1000});let review='',policy,eligible=0;
  try{if(db.prepare('PRAGMA user_version').get()?.user_version!==2)throw new PolicyError('configuration');const d=db.prepare('SELECT * FROM session_deployment WHERE singleton=1').get();if(!d||typeof d.review!=='string'||!/^[a-f0-9]{64}$/.test(d.review)||!Number.isSafeInteger(d.expires_at))throw new PolicyError('configuration');review=d.review;policy=portalSessionPolicy({maxSessions:Number(d.max_sessions),maxConcurrent:Number(d.max_concurrent)});result.scanned++;result.pending+=Number(db.prepare('SELECT count(*) AS n FROM session_attempts WHERE recovered=0').get()!.n);if(Number(d.expires_at)>now)continue;result.expired++;eligible=Number(db.prepare('SELECT count(*) AS n FROM session_attempts WHERE recovered=1 AND recover_after>0 AND recover_after<? AND (token_hash IS NOT NULL OR grant_id IS NOT NULL)').get(now-86400000)!.n);result.eligible+=eligible;}finally{db.close();}
  if(options.apply&&eligible){const journal=new PortalSessionJournal(path,review,policy!);try{journal.pruneRecovered();result.metadataRemoved+=eligible;}finally{journal.close();}}
 }
 return result;
}
