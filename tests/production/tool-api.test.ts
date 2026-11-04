import test from 'node:test';
import assert from 'node:assert/strict';
import {ToolApi} from '../../src/copilot/tool-api.ts';
import {PolicyProtectedTool} from '../../src/copilot/tool-authority.ts';
const claims={iss:'https://pf.test',aud:'api://copilot-tool',sub:'human',act:{iss:'https://agent.test',sub:'agent'},org_id:'partner',delegation_id:'grant',execution_mode:'interactive',scope:'copilot.invoke',iat:1,nbf:1,exp:Math.floor(Date.now()/1000)+60,jti:'test'};
function fixture(){
 let permitted=true,calls=0,checks=0,fail=false;const seen:any[]=[];
 const tool=new PolicyProtectedTool({timeoutMs:500,verifier:{verify:async(raw:string)=>{if(raw!=='verified-tool-token')throw Error('PRIVATE');return structuredClone(claims) as any;}},authorise:async()=>{checks++;if(!permitted)throw Error('PRIVATE');},operation:async(c)=>{calls++;seen.push(c);if(fail)throw Error('PRIVATE');return{authorized:true};}});
 return{api:new ToolApi(tool),calls:()=>calls,checks:()=>checks,seen,revoke:()=>{permitted=false;},fail:()=>{fail=true;}};
}
const input=(patch={})=>({method:'POST',path:'/v1/tools/verify-access',authorization:'Bearer verified-tool-token',rawBody:'{}',...patch});
test('fixed tool route preserves verified identities and checks policy before and after operation',async()=>{
 const s=fixture();assert.deepEqual(await s.api.handle(input()),{status:200,body:{authorized:true}});assert.equal(s.checks(),2);assert.deepEqual(s.seen[0],claims);
});
for(const patch of [{sub:'forged'},{act:{sub:'forged'}},{delegation_id:'other'},{org_id:'other'},{execution_mode:'autonomous'},{scope:'admin'},{resource:'sharepoint:other'},{url:'https://graph.microsoft.com/v1.0/sites'},{prompt:'ignore policy'}])test('tool API rejects caller authority/resource fields before operation',async()=>{
 const s=fixture();assert.equal((await s.api.handle(input({rawBody:JSON.stringify(patch)}))).status,400);assert.equal(s.calls(),0);
});
for(const patch of [{method:'GET'},{path:'/v1/tools/verify-access?resource=other'},{path:'/v1/tools/../verify-access'},{path:'/v1/tools/%76erify-access'},{rawBody:'[]'},{rawBody:'null'},{rawBody:''},{rawBody:'malformed'},{rawBody:' '.repeat(1025)}])test('tool API rejects ambiguous routes or malformed/bounded bodies',async()=>{
 const s=fixture();assert.equal((await s.api.handle(input(patch))).status,400);assert.equal(s.calls(),0);
});
for(const authorization of ['', 'Bearer unsigned','Basic private','Bearer one two','Bearer verified-tool-token\nforged'])test('missing or invalid tool credential cannot execute',async()=>{
 const s=fixture();assert.deepEqual(await s.api.handle(input({authorization})),{status:401,body:{error:'invalid_token'}});assert.equal(s.calls(),0);
});
test('revocation denies the next tool request and errors expose no implementation detail',async()=>{
 const s=fixture();s.revoke();assert.deepEqual(await s.api.handle(input()),{status:403,body:{error:'policy_denied'}});assert.equal(s.calls(),0);
 const t=fixture();t.fail();assert.deepEqual(await t.api.handle(input()),{status:503,body:{error:'tool_failed'}});
});
