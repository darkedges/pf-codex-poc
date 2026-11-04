import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {root,admin} from './common.mjs';
import {documentStageHash} from './document-stage-step.mjs';
import {assertMobileActivation} from '../vault/mobile-activation-guard.mjs';

export function addMobileRefreshScope(settings){
 if(!settings||!Array.isArray(settings.scopes)||settings.scopes.some(s=>s.name==='offline_access')||!['copilot.invoke','copilot.login','m365.document.read'].every(n=>settings.scopes.some(s=>s.name===n&&s.dynamic===false)))throw Error('mobile_refresh_scope_baseline');
 return {...structuredClone(settings),scopes:[...structuredClone(settings.scopes),{name:'offline_access',description:'Explicit mobile OIDC offline session renewal; no resource access',dynamic:false}]};
}
export async function applyMobileRefreshScope(){
 assertMobileActivation();
 const dir=resolve(root,'.local/mobile/activation-review'),read=n=>JSON.parse(readFileSync(resolve(dir,n),'utf8'));
 const packet=read('refresh-scope-amendment.json'),approval=read('refresh-scope-approval.json');
 if(approval.approved!==true||approval.packetHash!==documentStageHash(packet)||packet.purpose!=='mobile-refresh-scope-amendment')throw Error('mobile_scope_approval_required');
 for(const [name,hash]of Object.entries(packet.files)){if(documentStageHash(readFileSync(resolve(root,name),'utf8'))!==hash)throw Error('mobile_scope_source_drift');}
 const before=read('pf-a-settings-before.json'),current=await admin('a','oauth/authServerSettings');
 if(documentStageHash(current)!==packet.beforeHash||documentStageHash(before)!==packet.beforeHash)throw Error('mobile_scope_settings_drift');
 const next=addMobileRefreshScope(before),receipt=resolve(dir,'refresh-scope-intent.json');
 if(existsSync(receipt))throw Error('mobile_scope_attempt_exists');
 let absent=false;try{await admin('a','oauth/clients/mobile-copilot-login');}catch(e){if(e.status===404)absent=true;else throw e;}if(!absent)throw Error('mobile_scope_client_exists');
 const journalPath=resolve(root,'.local/tool-vault/mobile/activation-journal.json'),journal=JSON.parse(readFileSync(journalPath,'utf8'));
 if(Object.keys(journal.steps).join()!=='login-initial'||journal.steps['login-initial'].state!=='pending')throw Error('mobile_scope_journal_changed');
 writeFileSync(receipt,JSON.stringify({state:'pending',beforeHash:packet.beforeHash,afterHash:documentStageHash(next)},null,2)+'\n',{flag:'wx',mode:0o600});
 await admin('a','oauth/authServerSettings','PUT',next);
 if(documentStageHash(await admin('a','oauth/authServerSettings'))!==documentStageHash(next))throw Error('mobile_scope_readback');
 writeFileSync(resolve(dir,'rejected-login-journal.json'),JSON.stringify(journal,null,2)+'\n',{flag:'wx',mode:0o600});
 writeFileSync(journalPath,JSON.stringify({...journal,steps:{}},null,2)+'\n',{mode:0o600});
 writeFileSync(receipt,JSON.stringify({state:'confirmed',beforeHash:packet.beforeHash,afterHash:documentStageHash(next),reconciledAbsentClient:true},null,2)+'\n',{mode:0o600});
 return {scopeAdded:'offline_access',existingSettingsPreserved:true,rejectedClientAbsent:true,tokenRequests:0,microsoftRequests:0};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{if(process.argv.slice(2).join()!=='--apply')throw Error();console.log(JSON.stringify(await applyMobileRefreshScope()));}catch{console.error('Mobile refresh-scope amendment stopped; retain intent for reconciliation.');process.exitCode=1;}}
