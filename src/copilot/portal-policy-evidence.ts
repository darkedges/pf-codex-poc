import {DatabaseSync} from 'node:sqlite';
import {lstatSync,realpathSync} from 'node:fs';
import {isAbsolute,resolve} from 'node:path';
import type {DelegatedClaims} from '../adapters/token-exchange.ts';
// Read-only local PoC evidence gate. It emits no rows, identifiers or token data.
// The controller supplies the pinned DB, tool issuer, scope and resource.
export function verifyPortalToolAudit(options:{database:string;toolIssuer:string;toolAudience:string;scope:string;resource:string;claims:Readonly<DelegatedClaims>;startedAt:number}):boolean{
 let db:DatabaseSync|undefined;
 try{
  const file=lstatSync(options.database),canonical=realpathSync(options.database),expected=resolve(options.database);
  if(!isAbsolute(options.database)||!file.isFile()||file.isSymbolicLink()||file.nlink!==1||(process.platform==='win32'?canonical.toLowerCase()!==expected.toLowerCase():canonical!==expected)||!Number.isSafeInteger(options.startedAt)||options.startedAt>Date.now())return false;
  db=new DatabaseSync(options.database,{readOnly:true,timeout:1000,allowExtension:false});
  const c=options.claims;
  if(c.execution_mode!=='interactive'||c.scope!==options.scope)return false;
  const rows=db.prepare("SELECT outcome,subject,actor,actor_issuer,organisation,mode,scope,resource,token_issuer,audience,grant_version FROM audit WHERE grant_id=? AND action='decision' AND workload='policy-tool' AND at>=? ORDER BY at,id LIMIT 3").all(c.delegation_id,options.startedAt);
  return rows.length===2&&rows.every(row=>row.outcome==='permit'&&row.subject===c.sub&&row.actor===c.act.sub&&row.actor_issuer===c.act.iss&&row.organisation===c.org_id&&row.mode==='interactive'&&row.scope===options.scope&&row.resource===options.resource&&row.token_issuer===options.toolIssuer&&row.audience===options.toolAudience&&Number.isSafeInteger(row.grant_version)&&Number(row.grant_version)>0&&row.grant_version===rows[0].grant_version);
 }catch{return false;}finally{db?.close();}
}
