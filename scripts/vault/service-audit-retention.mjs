import {readdirSync,lstatSync,readFileSync,unlinkSync} from 'node:fs';
import {resolve} from 'node:path';
export function inspectServiceAudit(directory){
 const records=[];
 for(const name of readdirSync(directory)){
  if(!['tool-access.jsonl','tool-access.jsonl.1'].includes(name))throw Error('Unexpected service audit artifact');
  const path=resolve(directory,name),s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>1048576)throw Error('Service audit unavailable');
  const raw=readFileSync(path,'utf8');if(raw&&!raw.endsWith('\n'))throw Error('Service audit incomplete');
  let oldest=Infinity;
  for(const line of raw.trim().split('\n').filter(Boolean)){const r=JSON.parse(line),at=Date.parse(r.at);if(r.version!==1||r.event!=='tool_access'||!Number.isFinite(at)||at>Date.now()+5000)throw Error('Service audit invalid');oldest=Math.min(oldest,at);}
  records.push({name,oldest});
 }
 return{files:records.length,oldest:Math.min(Infinity,...records.map(r=>r.oldest)),records};
}
export function pruneStoppedAudit(directory,days,stopped,now=Date.now()){
 if(stopped!==true||![1,7].includes(days))throw Error('Stopped audit maintenance required');
 const state=inspectServiceAudit(directory);let removed=0;
 for(const r of state.records)if(r.oldest<=now-days*86400000){unlinkSync(resolve(directory,r.name));removed++;}
 return removed;
}
