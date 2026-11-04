import test from 'node:test';
import assert from 'node:assert/strict';
import { PolicyStore } from '../src/policy/store.ts';
const capability={scope:'copilot.invoke',resource:'sharepoint:approved-research'};
const login={issuer:'https://pf-a.test',subject:'partner:user',audience:'consent-portal',issuedAt:Date.now(),authTime:Date.now(),expiresAt:Date.now()+60000,tokenHash:'a'.repeat(43),nonceHash:'b'.repeat(43)};
function setup(){const s=new PolicyStore(':memory:',[capability]);s.registerOrganisation('partner','admin');s.registerPrincipal({id:'human',kind:'human',issuer:login.issuer,subject:login.subject,organisation:'partner',tokenIssuers:['https://pf-a.test','https://pf-b.test']},'admin');s.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agents.test',subject:'partner:agent',organisation:'partner'},'admin');return s;}
test('verified human consent atomically creates a grant and replay-proof evidence',()=>{
 const s=setup();try{const result=s.createConsentedGrant(login,'agent',['interactive','autonomous'],3600,capability,'portal');const g=s.grant(result.grantId)!;assert.equal(g.human_id,'human');assert.equal(g.approved_by,login.subject);assert.ok(s.consentForGrant(result.grantId));assert.throws(()=>s.createConsentedGrant(login,'agent',['interactive'],3600,capability,'portal'));assert.equal(s.ownedGrants(login).length,1);}finally{s.close();}
});
test('unknown human and expired login cannot create authority',()=>{
 const s=setup();try{for(const patch of [{subject:'other'},{issuer:'https://evil.test'},{expiresAt:1}])assert.throws(()=>s.createConsentedGrant({...login,...patch},'agent',['interactive'],3600,capability,'portal'));assert.equal(s.ownedGrants(login).length,0);}finally{s.close();}
});
test('only the authenticated owner can revoke a consented grant',()=>{
 const s=setup();try{const {grantId}=s.createConsentedGrant(login,'agent',['interactive'],3600,capability,'portal');assert.throws(()=>s.revokeOwnedGrant(grantId,{...login,subject:'other'},'portal'));s.revokeOwnedGrant(grantId,login,'portal');assert.equal(s.grant(grantId)?.state,'revoked');}finally{s.close();}
});
test('consent-backed authority derives human identity and denies revoked or unbound actors',()=>{
 const s=setup();try{const {grantId}=s.createConsentedGrant(login,'agent',['interactive','autonomous'],3600,capability,'portal');const actor={issuer:'https://agents.test',subject:'partner:agent'};assert.equal(s.authoriseConsentedGrant(grantId,actor,'autonomous',capability,'authority').sub,login.subject);assert.throws(()=>s.authoriseConsentedGrant(grantId,{...actor,subject:'other'},'autonomous',capability,'authority'));assert.throws(()=>s.authoriseConsentedGrant(grantId,actor,'interactive',capability,'authority'));assert.equal(s.authoriseConsentedGrant(grantId,actor,'interactive',capability,'authority',login).sub,login.subject);s.revokeOwnedGrant(grantId,login,'portal');assert.throws(()=>s.authoriseConsentedGrant(grantId,actor,'autonomous',capability,'authority'));}finally{s.close();}
});
