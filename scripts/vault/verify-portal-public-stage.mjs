import {writeFileSync} from 'node:fs';import {resolve} from 'node:path';import {readPortalActivation,activationDirectory} from './portal-activation.mjs';
try{
 if(process.argv.slice(2).join()!=='--verify')throw Error();readPortalActivation({requireCandidate:true});
 const origin='https://agent.copilot.darkedges.com';
 const get=async path=>{const response=await fetch(origin+path,{redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Cache-Control':'no-cache'}});let body='';for await(const chunk of response.body??[]){body+=Buffer.from(chunk).toString('utf8');if(body.length>65536)throw Error();}return{status:response.status,disabled:body.includes('Live testing is not enabled'),noStore:response.headers.get('cache-control')?.includes('no-store')};};
 const home=await get('/');if(home.status!==200||!home.disabled||!home.noStore)throw Error();for(const path of ['/admin','/v1/health','/metrics'])if((await get(path)).status!==404)throw Error();
 const receipt={verifiedAt:new Date().toISOString(),hostname:'agent.copilot.darkedges.com',stageVerified:true,https:true,noStore:true,unknownPathsDenied:true,microsoftRequests:0};writeFileSync(resolve(activationDirectory,'public-stage-verified.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
}catch{console.error('Public disabled portal stage is not verified; do not enable sign-in.');process.exitCode=1;}
