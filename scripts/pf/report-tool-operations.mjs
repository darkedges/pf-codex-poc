// Host-operator, read-only report for the latest completed isolated test run.
// No user/grant identifiers, credentials or audit row bodies are printed.
import {readdirSync,readFileSync,statSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
try{
 if(process.argv.length!==2)throw Error();
 const base=resolve(fileURLToPath(new URL('../../.local/pingfederate/tool-container-tests/',import.meta.url)));
 const candidates=readdirSync(base).map(n=>resolve(base,n)).filter(p=>statSync(p).isDirectory()).sort((a,b)=>statSync(b).mtimeMs-statSync(a).mtimeMs);
 let run,receipt;
 for(const candidate of candidates){const r=JSON.parse(readFileSync(resolve(candidate,'run.json'),'utf8'));if(r.status==='completed'){run=candidate;receipt=r;break;}}
 if(!run)throw Error();
 const db=new DatabaseSync(resolve(run,'policy.sqlite'),{readOnly:true});let policy;
 try{
  const revocations=db.prepare("SELECT COUNT(*) AS count FROM audit WHERE action='grant.revoke'").get().count;
  const denied=db.prepare("SELECT COUNT(*) AS count FROM audit WHERE action='decision' AND outcome='deny'").get().count;
  const active=db.prepare("SELECT COUNT(*) AS count FROM grants g JOIN consents c ON c.grant_id=g.id WHERE g.state!='revoked'").get().count;
  policy={authoritativeRevocationRecords:revocations,deniedDecisionRecords:denied,remainingActiveTestConsents:active};
 }finally{db.close();}
 const audit={available:false,attempts:0,successes:0,denials:0};
 for(const name of ['tool-access.jsonl','tool-access.jsonl.1']){
  const path=resolve(run,'audit',name);if(!existsSync(path))continue;if(statSync(path).size>1048576)throw Error();audit.available=true;
  for(const line of readFileSync(path,'utf8').trim().split('\n').filter(Boolean)){
   const event=JSON.parse(line);if(event.event!=='tool_access')throw Error();
   if(event.outcome==='attempt')audit.attempts++;else if(event.outcome==='success')audit.successes++;else if(event.outcome==='denied')audit.denials++;else throw Error();
  }
 }
 const evidence=JSON.parse(readFileSync(resolve(run,'result.json'),'utf8'));let boundedLoad;
 if(evidence.loadEvidence){boundedLoad={};for(const key of ['requests','completed','accepted','rateLimited','overloaded','unexpected','networkErrors','durationMs','p95Ms']){const n=evidence.loadEvidence[key];if(typeof n!=='number'||!Number.isFinite(n)||n<0)throw Error();boundedLoad[key]=n;}}
 console.log(JSON.stringify({...(boundedLoad?{boundedLoad}:{}),source:'latest-completed-isolated-Docker-test',policy,restrictedAudit:audit,cleanupVerified:receipt.clientsRestored===true&&receipt.grantsRevoked===true&&receipt.temporaryCredentialsRemoved===true&&receipt.containersRemoved===true,externalAlertsConfigured:false},null,2));
}catch{console.error('Restricted operations report unavailable');process.exitCode=1;}
