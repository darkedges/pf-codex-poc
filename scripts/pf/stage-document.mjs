import {readFileSync,writeFileSync,mkdirSync,existsSync,openSync,closeSync,unlinkSync} from 'node:fs';import {resolve} from 'node:path';
import {admin,call,nodes,load,root} from './common.mjs';import {documentPfProfile} from './document-profile.mjs';import {documentStageStep,documentStageHash} from './document-stage-step.mjs';
const dir=resolve(root,'.local/tool-vault/document-deployment'),json=p=>JSON.parse(readFileSync(p,'utf8')),custody=resolve(root,'.local/tool-vault');
if(process.argv.length===2)console.log(JSON.stringify({action:'preview',scope:'m365.document.read',dedicatedClients:['document-gateway-1','document-gateway-2'],clientsEnabled:false,signingKeys:['document-a-signing','document-b-signing'],pfTokenRequests:0,microsoftRequests:0}));
else if(process.argv.slice(2).join()==='--stage'){
 let lock;const lockPath=resolve(dir,'stage.lock');
 try{
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.NODE_OPTIONS||process.env.SSLKEYLOGFILE)throw Error();mkdirSync(dir,{recursive:true,mode:0o700});lock=openSync(lockPath,'wx',0o600);
  const exchange=json(resolve(custody,'document-exchange-trust.json')),transit=json(resolve(custody,'document-authority-transit.json'));
  const input={clientA:{keys:[exchange.clientA]},clientB:{keys:[exchange.clientB]},authority:{keys:[transit.publicJwk]},agent:load('agent.jwks.json'),upstream:load('agent.jwks.json')};
  const journalPath=resolve(dir,'stage-journal.json'),hash=documentStageHash({...input,upstream:undefined});
  const journal=existsSync(journalPath)?json(journalPath):{schemaVersion:1,profileHash:hash,steps:{}};if(journal.schemaVersion!==1||journal.profileHash!==hash||Object.values(journal.steps).some(s=>s.state==='pending'))throw Error('Uncertain or foreign stage journal');
  const save=j=>writeFileSync(journalPath,JSON.stringify(j,null,2),{mode:0o600});
  const get=async(n,path)=>{try{return await admin(n,path);}catch(e){if(e.status===404)return null;throw e;}};
  const step=(id,n,path,body,method='POST',readPath,previousHash)=>documentStageStep({id,journal,save,expected:body,previousHash,read:()=>get(n,readPath??path+'/'+(body.id??body.clientId)),write:()=>admin(n,path,method,body)});
  let profile=documentPfProfile(input);
  for(const n of ['a','b']){
   const scopeId=n+'-scope',settings=await admin(n,'oauth/authServerSettings');
   if(journal.steps[scopeId]){if(journal.steps[scopeId].state!=='confirmed'||documentStageHash(settings)!==journal.steps[scopeId].hash)throw Error('Scope configuration drift');}
   else{
    if(settings.scopes.some(s=>s.name==='m365.document.read'))throw Error('Unowned document scope');
    const expected={...settings,scopes:[...settings.scopes,{name:'m365.document.read',description:'Document-specific five-minute consent; selected synthetic sample only',dynamic:false}]};
    await step(scopeId,n,'oauth/authServerSettings',expected,'PUT','oauth/authServerSettings',documentStageHash(settings));
   }
   const p=profile[n],keyRead='keyPairs/signing/'+p.signingId;
   await documentStageStep({id:n+'-key',journal,save,expected:{id:p.signingId,keyAlgorithm:'RSA',keySize:4096},read:()=>get(n,keyRead),write:()=>admin(n,'keyPairs/signing/generate','POST',{id:p.signingId,keyAlgorithm:'RSA',keySize:4096,validDays:30,commonName:p.signingId,organization:'Local document PoC',country:'AU'})});
   await step(n+'-subject',n,'idp/tokenProcessors',p.subjectProcessor);if(p.actorProcessor)await step(n+'-actor',n,'idp/tokenProcessors',p.actorProcessor);
   await step(n+'-policy',n,'oauth/tokenExchange/processor/policies',p.policy);
   const initial={...p.client,restrictToDefaultAccessTokenManager:false};delete initial.defaultAccessTokenManagerRef;
   if(!journal.steps[n+'-client-final'])await step(n+'-client-initial',n,'oauth/clients',initial);
   await step(n+'-manager',n,'oauth/accessTokenManagers',p.tokenManager);
   const mappingRead=async()=>{const all=await admin(n,'oauth/accessTokenMappings'),items=all.items??all,found=items.filter(m=>m.context?.type===p.mapping.context.type&&m.context?.contextRef?.id===p.policy.id&&m.accessTokenManagerRef?.id===p.tokenManager.id);if(found.length>1)throw Error();return found[0]??null;};
   await documentStageStep({id:n+'-mapping',journal,save,expected:p.mapping,read:mappingRead,write:()=>admin(n,'oauth/accessTokenMappings','POST',p.mapping)});
   await step(n+'-client-final',n,'oauth/clients/'+p.client.clientId,p.client,'PUT','oauth/clients/'+p.client.clientId,journal.steps[n+'-client-initial'].hash);
   const published=await call(nodes[n].issuer+'/pf/JWKS');if(published.status!==200)throw Error();const key=published.value.keys.filter(k=>k.kid===p.signingId);if(key.length!==1)throw Error();
   const pin={keys:key.map(k=>Object.fromEntries(['kty','n','e','kid','alg','use'].map(f=>[f,k[f]??(f==='alg'?'RS256':f==='use'?'sig':undefined)])))};
   const pinPath=resolve(dir,'pf-'+n+'-jwks.json');if(existsSync(pinPath)){if(documentStageHash(json(pinPath))!==documentStageHash(pin))throw Error('Signing pin drift');}else writeFileSync(pinPath,JSON.stringify(pin,null,2),{flag:'wx',mode:0o600});
   if(n==='a'){input.upstream=pin;profile=documentPfProfile(input);}
  }
  const output=resolve(dir,'exchange-config.json');if(existsSync(output)){if(documentStageHash(json(output))!==documentStageHash(profile.exchange))throw Error();}else writeFileSync(output,JSON.stringify(profile.exchange,null,2),{mode:0o600,flag:'wx'});
  writeFileSync(resolve(dir,'stage-confirmed.json'),JSON.stringify({status:'STAGED_DISABLED',completedAt:new Date().toISOString(),confirmedSteps:Object.keys(journal.steps).length,pfTokenRequests:0,microsoftRequests:0,clientsEnabled:false},null,2),{mode:0o600});
  console.log(JSON.stringify({status:'STAGED_DISABLED',confirmedSteps:Object.keys(journal.steps).length,clientsEnabled:false,pfTokenRequests:0,microsoftRequests:0}));
 }catch{console.error('Document PF staging incomplete; retain journal and reconcile pending/foreign/drifted objects before any repeat.');process.exitCode=1;}
 finally{if(lock!==undefined){closeSync(lock);unlinkSync(lockPath);}}
}else{console.error('Use preview or --stage only');process.exitCode=1;}
