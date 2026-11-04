import {readFileSync,writeFileSync,existsSync,openSync,closeSync,unlinkSync} from 'node:fs';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
import {admin,root} from './common.mjs';import {documentStageHash,documentStageStep} from './document-stage-step.mjs';import {documentChatPfFingerprint} from './document-chat-pf-lease.mjs';import {assertMobileActivation} from '../vault/mobile-activation-guard.mjs';
const normalize=value=>{const v=structuredClone(value);delete v.lastModified;delete v.sequenceNumber;return v;};
export function repairMobileAudience(manager,kind,node){
 if(!['chat','document'].includes(kind)||!['a','b'].includes(node)||manager?.id!==`mobile${kind==='chat'?'Chat':'Document'}${node.toUpperCase()}JWT`)throw Error('mobile_audience_identity');
 const next=structuredClone(manager),fields=next.configuration?.fields?.filter(f=>f.name==='Audience Claim Value'),target=node==='a'?`api://gateway-2/mobile-${kind}`:kind==='chat'?'api://copilot-broker':'api://federated-copilot/mobile-documents',old=node==='a'?'api://gateway-2/documents':'api://federated-copilot/documents';
 if(fields?.length!==1||![old,target].includes(fields[0].value))throw Error('mobile_audience_baseline');fields[0].value=target;return next;
}
export async function applyAudienceRepair(plan,journal,save,control){
 const items=plan.items;if(items?.length!==4||new Set(items.map(i=>i.kind+':'+i.node)).size!==4||!journal.steps||Object.values(journal.steps).some(s=>s.state==='pending'))throw Error('mobile_audience_uncertain');
 for(const i of items){if(documentStageHash(normalize(repairMobileAudience(i.before,i.kind,i.node)))!==documentStageHash(normalize(i.after))||i.id!==i.before.id||i.clientId!==`mobile-${i.kind}-gateway-${i.node==='a'?'1':'2'}`||i.client.clientId!==i.clientId||i.client.enabled!==true||i.client.clientAuth?.type!=='PRIVATE_KEY_JWT')throw Error('mobile_audience_plan');}
 const readManager=i=>control(i.node,'oauth/accessTokenManagers/'+i.id).then(normalize),clientPrint=(i,enabled)=>documentChatPfFingerprint({...i.client,enabled}),readClient=i=>control(i.node,'oauth/clients/'+i.clientId).then(documentChatPfFingerprint);
 if(journal.complete){for(const i of items)if(documentStageHash(await readManager(i))!==documentStageHash(normalize(i.after))||await readClient(i)!==clientPrint(i,true))throw Error('mobile_audience_drift');return{alreadyApplied:true,clientsRestored:4,tokenRequests:0,microsoftRequests:0};}
 const step=(id,read,expected,write,previousHash)=>documentStageStep({id,journal,save,read,expected,write,previousHash});
 for(const i of items)await step('disable-'+i.node+'-'+i.kind,()=>readClient(i),clientPrint(i,false),()=>control(i.node,'oauth/clients/'+i.clientId,'PUT',{...i.client,enabled:false}),documentStageHash(clientPrint(i,true)));
 for(const i of items)await step('audience-'+i.node+'-'+i.kind,()=>readManager(i),normalize(i.after),()=>control(i.node,'oauth/accessTokenManagers/'+i.id,'PUT',i.after),documentStageHash(normalize(i.before)));
 for(const i of items)await step('restore-'+i.node+'-'+i.kind,()=>readClient(i),clientPrint(i,true),()=>control(i.node,'oauth/clients/'+i.clientId,'PUT',i.client),documentStageHash(clientPrint(i,false)));
 journal.complete=true;save(journal);return{clientsRestored:4,audiencesCorrected:4,tokenRequests:0,microsoftRequests:0};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 let fd,path;try{
  if(process.argv.slice(2).join()!=='--apply')throw Error();assertMobileActivation();const dir=resolve(root,'.local/mobile/audience-repair'),json=name=>JSON.parse(readFileSync(resolve(dir,name),'utf8')),plan=json('plan.json'),manifest=json('manifest.json'),approval=json('approval.json'),digest=value=>createHash('sha256').update(value).digest('hex');
  if(approval.approved!==true||approval.manifestSha256!==digest(readFileSync(resolve(dir,'manifest.json')))||manifest.purpose!=='mobile-pf-audience-repair'||manifest.planHash!==documentStageHash(plan))throw Error('mobile_audience_approval_required');
  for(const [name,hash]of Object.entries(manifest.files)){const p=resolve(root,name);if(!p.startsWith(root+'\\')||digest(readFileSync(p))!==hash)throw Error('mobile_audience_source_drift');}
  path=resolve(dir,'apply.lock');fd=openSync(path,'wx',0o600);const journalPath=resolve(dir,'journal.json'),journal=existsSync(journalPath)?json('journal.json'):{purpose:'mobile-pf-audience-repair',planHash:manifest.planHash,steps:{}};
  if(journal.planHash!==manifest.planHash)throw Error('mobile_audience_journal_drift');const allowed=new Set(plan.items.flatMap(i=>[i.node+':oauth/clients/'+i.clientId,i.node+':oauth/accessTokenManagers/'+i.id]));
  const control=(node,target,method='GET',body)=>{assertMobileActivation();if(!allowed.has(node+':'+target)||!['GET','PUT'].includes(method))throw Error('mobile_audience_path');return admin(node,target,method,body);};
  const result=await applyAudienceRepair(plan,journal,j=>writeFileSync(journalPath,JSON.stringify(j,null,2)+'\n',{mode:0o600}),control);writeFileSync(resolve(dir,'receipt.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(result));
 }catch{console.error('Mobile audience repair stopped; preserve journal and reconcile owned configuration before repeating.');process.exitCode=1;}finally{if(fd!==undefined){closeSync(fd);unlinkSync(path);}}
}
