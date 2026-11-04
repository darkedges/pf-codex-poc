import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,writeFileSync,unlinkSync,rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { directLineFromEnvironment } from '../../src/adapters/copilot-env.ts';
const config={endpoint:'https://directline.botframework.com/v3/directline',brokerAudience:'api://broker',ssoAudience:'api://copilot-tools',scope:'copilot.invoke',botId:'approved-bot',trustedOrigins:['https://portal.test'],tokenPostRules:[{origin:'https://token.botframework.com',pathPrefix:'/approved/token-post/',requiredQueryParameters:['sig']}],timeoutMs:100,maxSessions:10,sessionLifetimeSeconds:300,maxActivities:100};
const dependencies={verifier:{verify:async()=>{throw Error('not configured');}},ssoVerifier:{verify:async()=>{throw Error('not configured');}},authorise:async()=>{throw Error('not configured');},issueSsoToken:async()=>{throw Error('not configured');}};
test('Direct Line production selection has no mock fallback and requires secure credentials',async()=>{for(const env of [{},{COPILOT_MODE:'mock'},{COPILOT_MODE:'directline'},{COPILOT_MODE:'directline',COPILOT_DIRECT_LINE_CONFIG:JSON.stringify(config),COPILOT_DIRECT_LINE_SECRET_FILE:'relative-secret'}])await assert.rejects(directLineFromEnvironment(dependencies,env));});
test('secret-manager mounted file is injected without putting credential values in config',async()=>{
 const directory=mkdtempSync(join(tmpdir(),'copilot-secret-test-')),path=join(directory,'secret');writeFileSync(path,'test-only-credential',{mode:0o600});
 try{const adapter=await directLineFromEnvironment(dependencies,{COPILOT_MODE:'directline',COPILOT_DIRECT_LINE_CONFIG:JSON.stringify(config),COPILOT_DIRECT_LINE_SECRET_FILE:path});assert.equal(typeof adapter.open,'function');await assert.rejects(adapter.open('invalid'),e=>!String(e).includes('test-only-credential'));}finally{unlinkSync(path);rmdirSync(directory);}
});
test('rotating a mounted Direct Line credential changes only subsequent token-generation requests',async()=>{
 const directory=mkdtempSync(join(tmpdir(),'copilot-rotation-test-')),path=join(directory,'secret');writeFileSync(path,'test-only-first',{mode:0o600});let sequence=0;const credentials:string[]=[];
 const claims={iss:'https://pf-b.test',aud:config.brokerAudience,sub:'human',act:{iss:'https://agents.test',sub:'agent'},org_id:'org',delegation_id:'grant',execution_mode:'interactive' as const,scope:config.scope,iat:Math.floor(Date.now()/1000),nbf:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+60,jti:'test-jti'};
 try{
  const adapter=await directLineFromEnvironment({...dependencies,verifier:{verify:async()=>claims},authorise:async()=>{},fetch:async(url,init)=>{if(String(url).endsWith('/tokens/generate')){credentials.push((init?.headers as Record<string,string>).Authorization);sequence++;}return Response.json({conversationId:'test-'+sequence,token:'test-only-channel-'+sequence,expires_in:120});}},{COPILOT_MODE:'directline',COPILOT_DIRECT_LINE_CONFIG:JSON.stringify(config),COPILOT_DIRECT_LINE_SECRET_FILE:path});
  const first=await adapter.open('test-input-proof');writeFileSync(path,'test-only-second',{mode:0o600});const second=await adapter.open('test-input-proof');assert.deepEqual(credentials,['Bearer test-only-first','Bearer test-only-second']);assert.ok(!JSON.stringify([first,second]).includes('test-only-first'));assert.ok(!JSON.stringify([first,second]).includes('test-only-second'));
 }finally{unlinkSync(path);rmdirSync(directory);}
});
