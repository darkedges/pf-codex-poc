import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {PolicyStore} from '../../src/policy/store.ts';
import {verifyPortalToolAudit} from '../../src/copilot/portal-policy-evidence.ts';
const capability={scope:'copilot.invoke',resource:'sharepoint:approved-research'};
function fixture(){
 const directory=mkdtempSync(join(tmpdir(),'portal-evidence-')),database=join(directory,'policy.sqlite'),store=new PolicyStore(database,[capability]);
 store.registerOrganisation('partner','admin');store.registerPrincipal({id:'human',kind:'human',issuer:'https://pf-a.test',subject:'partner:user',organisation:'partner',tokenIssuers:['https://pf-b.test']},'admin');store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agents.test',subject:'partner:agent',organisation:'partner'},'admin');
 const now=Date.now();store.createGrant({id:'owned-grant',humanId:'human',agentId:'agent',organisation:'partner',modes:['interactive'],scopes:[capability.scope],resources:[capability.resource],expiresAt:now+60000,consent:{reference:'consent',approvedAt:now,expiresAt:now+60000}},'policy-consent');
 const claims={iss:'https://pf-b.test',aud:'api://copilot-tool',sub:'partner:user',act:{iss:'https://agents.test',sub:'partner:agent'},org_id:'partner',delegation_id:'owned-grant',execution_mode:'interactive',scope:capability.scope};
 const options={database,toolIssuer:claims.iss,toolAudience:claims.aud,scope:capability.scope,resource:capability.resource,claims:claims as any,startedAt:now};
 return{store,claims,options,close:()=>{store.close();rmSync(directory,{recursive:true,force:true});}};
}
test('audit evidence requires exactly two identity-preserving tool decisions',()=>{
 const f=fixture();try{assert.equal(verifyPortalToolAudit(f.options),false);f.store.decide(f.claims,capability,'policy-tool');assert.equal(verifyPortalToolAudit(f.options),false);f.store.decide(f.claims,capability,'policy-tool');assert.equal(verifyPortalToolAudit(f.options),true);f.store.decide(f.claims,capability,'policy-tool');assert.equal(verifyPortalToolAudit(f.options),false);}finally{f.close();}
});
test('different identity, resource, tool issuer/audience and older decisions cannot satisfy evidence',()=>{
 const f=fixture();try{f.store.decide(f.claims,capability,'policy-tool');f.store.decide(f.claims,capability,'policy-tool');
  for(const patch of [{resource:'other'},{toolIssuer:'https://other.test'},{toolAudience:'other'},{startedAt:Date.now()+1},{claims:{...f.claims,sub:'foreign'}},{claims:{...f.claims,act:{...f.claims.act,sub:'foreign'}}},{claims:{...f.claims,org_id:'foreign'}}])assert.equal(verifyPortalToolAudit({...f.options,...patch}),false);
 }finally{f.close();}
});
test('denied policy decisions and other workloads are not positive evidence',()=>{
 const f=fixture();try{f.store.decide(f.claims,capability,'policy-gateway');f.store.decide(f.claims,capability,'policy-gateway');assert.equal(verifyPortalToolAudit(f.options),false);f.store.revokeGrant('owned-grant','admin');f.store.decide(f.claims,capability,'policy-tool');f.store.decide(f.claims,capability,'policy-tool');assert.equal(verifyPortalToolAudit(f.options),false);}finally{f.close();}
});
