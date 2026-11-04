import test from 'node:test';import assert from 'node:assert/strict';import {generateKeyPairSync,sign} from 'node:crypto';import {mkdtempSync,rmSync,readFileSync} from 'node:fs';import {DatabaseSync} from 'node:sqlite';import {join,dirname,basename} from 'node:path';import {tmpdir} from 'node:os';import {exportJWK,generateKeyPair,SignJWT} from 'jose';
import {OidcVerifier} from '../../src/identity/oidc.ts';import {bodyHash} from '../../src/policy/protocol.ts';import {MobileDeviceAuthority,mobileDeviceDomain} from '../../src/mobile/device-authority.ts';
import {LiveDeviceSession} from '../../apps/mobile/src/live-device-session.ts';
import {MobileLoginHandoff} from '../../src/mobile/login-handoff.ts';
import {MobileHttpApi} from '../../src/mobile/http-api.ts';
import {MobileHttpsTransport,parseMobileReturn} from '../../apps/mobile/src/http-transport.ts';
import {MobileAppController} from '../../apps/mobile/src/mobile-controller.ts';
import {PolicyStore} from '../../src/policy/store.ts';
import {MobileExecutionAuthority,createMobileRegistryCheck} from '../../src/mobile/execution-authority.ts';
import {DevelopmentSigner} from '../../src/identity/assertion-signer.ts';
import {jwtVerify} from 'jose';
import {MobileResourceConsent} from '../../src/mobile/resource-consent.ts';
import {MobileChatJobs} from '../../src/mobile/chat-jobs.ts';
import {OidcClient} from '../../src/identity/oidc.ts';
import {MobileProviderEnrollment} from '../../src/mobile/provider-enrollment.ts';
import {MobileProviderSessions,VaultMobileProviderStore} from '../../src/mobile/provider-sessions.ts';

const oidc=await generateKeyPair('RS256'),nonce='n'.repeat(43),origin='https://agent.example.test';
const device=()=>{const k=generateKeyPairSync('ec',{namedCurve:'prime256v1'});return{...k,spki:k.publicKey.export({type:'spki',format:'der'}).toString('base64url')};};
async function fixture(realTime=false,executionLeaseSeconds?:60|180){const directory=mkdtempSync(join(tmpdir(),'mobile-device-authority-')),path=join(directory,'devices.sqlite'),d=device(),f=device();let clock=Date.now(),active=true;
 const profile={origin,agent:{issuer:'https://agents.example.test',subject:'research-agent'},organisation:'partner',capabilities:[{scope:'copilot.invoke',resource:'sharepoint:approved-research'},{scope:'m365.document.read',resource:'sharepoint:approved-research'}],termsVersion:'mobile-consent-v1',...(executionLeaseSeconds?{executionLeaseSeconds}:{})};
 const verifier=new OidcVerifier({issuer:'https://pf.example.test',jwksUri:'https://pf.example.test/pf/JWKS',clientId:'mobile-bff',keyIds:['fixture-oidc'],fetch:async()=>Response.json({keys:[{...await exportJWK(oidc.publicKey),kid:'fixture-oidc',alg:'RS256',use:'sig'}]})});
 const options={database:path,profile,loginVerifier:verifier,now:()=>realTime?Date.now():clock,current:async b=>{assert.equal(b.human.subject,'external-human');assert.equal(b.agent.subject,'research-agent');if(!active)throw Error('PRIVATE');}};
 const a=new MobileDeviceAuthority(options),proof=async(patch={},n=nonce)=>{const now=Math.floor(Date.now()/1000);return{idToken:await new SignJWT({iss:'https://pf.example.test',sub:'external-human',aud:'mobile-bff',iat:now,auth_time:now,exp:now+120,nonce:n,...patch}).setProtectedHeader({alg:'RS256',kid:'fixture-oidc'}).sign(oidc.privateKey),nonce:n};};
 const native=(c,key=d)=>sign('sha256',Buffer.from(mobileDeviceDomain+c.challenge),key.privateKey).toString('base64url');
 const enroll=async()=>{const p=await proof(),c=await a.beginEnrollment(p,{devicePublicKeySpki:d.spki,sessionPublicKeySpki:f.spki,termsHash:a.termsHash});return a.completeEnrollment({challengeId:c.challengeId,signature:native(c)});};
 const request=async(sessionId,patch={},key=f)=>new SignJWT({iss:sessionId,sub:sessionId,aud:origin,iat:Math.floor(clock/1000),nbf:Math.floor(clock/1000),exp:Math.floor(clock/1000)+60,jti:crypto.randomUUID(),htm:'POST',htu:origin+'/v1/mobile/chat/messages',body_hash:bodyHash('{"question":"Hello"}'),...patch}).setProtectedHeader({alg:'ES256',typ:'fc-mobile-request+jwt'}).sign(key.privateKey);
 return{a,options,d,f,path,proof,native,enroll,request,clock:()=>clock,advance:ms=>clock+=ms,suspend:()=>active=false,close:()=>{a.close();assert.equal(dirname(directory),tmpdir());assert.ok(basename(directory).startsWith('mobile-device-authority-'));rmSync(directory,{recursive:true,force:true});}};
}
const req={method:'POST',path:'/v1/mobile/chat/messages',body:'{"question":"Hello"}'};
function resourceFixture(f,file=false){
 const store=new PolicyStore(file?f.path+'.resource-policy':':memory:',f.options.profile.capabilities);
 store.registerOrganisation('partner','setup');store.registerPrincipal({id:'human',kind:'human',issuer:'https://pf.example.test',subject:'external-human',organisation:'partner',tokenIssuers:['https://pf.example.test']},'setup');store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agents.example.test',subject:'research-agent',organisation:'partner'},'setup');
 const config={store,mobile:f.a,humanBindings:[{issuer:'https://pf.example.test',subject:'external-human',audience:'mobile-bff',principalId:'human'}],agentId:'agent',organisation:'partner',capabilities:f.options.profile.capabilities,description:'Approve the fixed Copilot and SharePoint resources.',workload:'mobile-resource-consent'};
 const service=new MobileResourceConsent(config);return{store,service,config};
}

test('resource consent persists separate narrow grants and revocation cannot be silently reapproved',async()=>{
 const f=await fixture(true);let store=new PolicyStore(f.path+'.resources',f.options.profile.capabilities),consent;try{
  store.registerOrganisation('partner','setup');store.registerPrincipal({id:'human',kind:'human',issuer:'https://pf.example.test',subject:'external-human',organisation:'partner',tokenIssuers:['https://pf.example.test']},'setup');store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agents.example.test',subject:'research-agent',organisation:'partner'},'setup');
  const config={store,mobile:f.a,humanBindings:[{issuer:'https://pf.example.test',subject:'external-human',audience:'mobile-bff',principalId:'human'}],agentId:'agent',organisation:'partner',capabilities:f.options.profile.capabilities,description:'Allow the registered agent to invoke Copilot and read the approved SharePoint site.',workload:'mobile-resource-consent'};
  consent=new MobileResourceConsent(config);const e=await f.enroll(),terms=consent.terms(),approvalBody=JSON.stringify({termsHash:terms.termsHash,mode:'auto'});
  const evidenceFor=async(path,body)=>f.a.authorize(e.sessionId,await f.request(e.sessionId,{htu:origin+path,body_hash:bodyHash(body)}),{method:'POST',path,body});
  const chatEvidence=await evidenceFor(req.path,req.body);await assert.rejects(consent.approve(chatEvidence,approvalBody));
  const wrongTerms=JSON.stringify({termsHash:'unknown',mode:'auto'});await assert.rejects(consent.approve(await evidenceFor('/v1/mobile/access/approve',wrongTerms),wrongTerms));
  const proof=await evidenceFor('/v1/mobile/access/approve',approvalBody),first=await consent.approve(proof,approvalBody);assert.equal(first.approved,true);
  await assert.rejects(consent.approve(JSON.parse(JSON.stringify(proof)),approvalBody));await assert.rejects(consent.approve(proof,JSON.stringify({termsHash:terms.termsHash,mode:'manual'})));
  const bindings=consent.bindings(proof);assert.equal(bindings.length,2);assert.notEqual(bindings[0].grantId,bindings[1].grantId);
  for(const b of bindings){const g=store.grant(b.grantId);assert.deepEqual(JSON.parse(g.scopes),[b.scope]);assert.deepEqual(JSON.parse(g.resources),[b.resource]);assert.deepEqual(JSON.parse(g.modes),['interactive']);assert.equal(Number(g.expires_at),e.enrollmentExpiresAt);assert.notEqual(g.consent_reference,proof.consentId);}
  store.close();store=new PolicyStore(f.path+'.resources',f.options.profile.capabilities);
  const second=new MobileResourceConsent({...config,store});assert.deepEqual(second.bindings(proof),bindings);
  const again=await evidenceFor('/v1/mobile/access/approve',approvalBody);await second.approve(again,approvalBody);assert.deepEqual(second.bindings(proof),bindings);
  const statusProof=await evidenceFor('/v1/mobile/access/status','{}');assert.equal((await second.status(statusProof)).approved,true);
  const signer=await generateKeyPair('RS256'),actor=await generateKeyPair('RS256'),capability=f.options.profile.capabilities.find(c=>c.scope==='m365.document.read');
  const execution=new MobileExecutionAuthority({...config,store,mobile:f.a,capability,grantBindings:second,issuer:'https://mobile-authority.example.test',audience:'api://document-gateway',signer:new DevelopmentSigner(signer.privateKey,'authority'),keyId:'authority',publicKey:signer.publicKey,agentIssuer:'https://agents.example.test',agentAudience:'api://mobile-actor',agentKeyId:'actor',agentKey:actor.publicKey,workload:'mobile-document-authority',grantWorkload:config.workload,deviceAssurance:'allow-unattested-poc',audit:async()=>{}});
  const actorToken=async()=>new SignJWT({iss:'https://agents.example.test',sub:'research-agent',aud:'api://mobile-actor',scope:capability.scope,iat:Math.floor(Date.now()/1000),nbf:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+60,jti:crypto.randomUUID()}).setProtectedHeader({alg:'RS256',kid:'actor',typ:'JWT'}).sign(actor.privateKey);
  const actorBinding={issuer:'https://agents.example.test',subject:'research-agent',organisation:'partner',operation:capability.scope,workload:'mobile-document-authority'};
  const issued=await execution.issue(chatEvidence,await actorToken(),actorBinding);assert.equal((await jwtVerify(issued,signer.publicKey)).payload.delegation_id,second.resolve(chatEvidence,capability).grantId);
  await second.revoke(await evidenceFor('/v1/mobile/access/revoke','{}'));assert.equal((await second.status(statusProof)).revoked,true);
  await assert.rejects(execution.issue(chatEvidence,await actorToken(),actorBinding));
  for(const b of bindings)assert.equal(store.grant(b.grantId).state,'revoked');
  await assert.rejects(second.approve(await evidenceFor('/v1/mobile/access/approve',approvalBody),approvalBody));
  const manual=JSON.stringify({termsHash:terms.termsHash,mode:'manual'});await assert.rejects(second.approve(await evidenceFor('/v1/mobile/access/approve',manual),manual));
 }finally{store.close();f.close();}
});

test('partial resource grant creation rolls back atomically and failed post-check revokes committed grants',async()=>{
 for(const mode of ['rollback','postcheck','cancel']){const f=await fixture(true),r=resourceFixture(f);try{
  const e=await f.enroll(),body=JSON.stringify({termsHash:r.service.terms().termsHash,mode:'manual'}),path='/v1/mobile/access/approve';
  const proof=await f.a.authorize(e.sessionId,await f.request(e.sessionId,{htu:origin+path,body_hash:bodyHash(body)}),{method:'POST',path,body});
  const cancelled=new AbortController();let calls=0;const original=r.store.createGrant.bind(r.store);r.store.createGrant=(g,w)=>{calls++;if(mode==='rollback'&&calls===2)throw Error('private-storage-failure');original(g,w);if(mode==='postcheck'&&calls===2){r.store.suspend('agent','agent','setup');f.suspend();}if(mode==='cancel'&&calls===2)cancelled.abort();};
  await assert.rejects(r.service.approve(proof,body,cancelled.signal),error=>!error.message.includes('private-storage-failure'));
  const created=r.store.audit().filter(event=>event.action==='grant.create');assert.equal(created.length,mode==='rollback'?0:2);for(const event of created)assert.equal(r.store.grant(String(event.grant_id)).state,'revoked');assert.deepEqual(r.service.bindings(proof),[]);
 }finally{r.store.close();f.close();}}
});

test('mobile resource profile drift or seal removal fails closed without resetting state',async()=>{const f=await fixture(true),r=resourceFixture(f,true);let raw;try{
 assert.throws(()=>new MobileResourceConsent({...r.config,description:'Different permission terms'}));
 raw=new DatabaseSync(f.path+'.resource-policy');raw.exec('DELETE FROM mobile_resource_meta');assert.throws(()=>new MobileResourceConsent(r.config));
}finally{raw?.close();r.store.close();f.close();}});

test('revoking before first resource approval records a tombstone and prevents later auto approval',async()=>{const f=await fixture(true),r=resourceFixture(f);try{
 const e=await f.enroll(),path='/v1/mobile/access/revoke',proof=await f.a.authorize(e.sessionId,await f.request(e.sessionId,{htu:origin+path,body_hash:bodyHash('{}')}),{method:'POST',path,body:'{}'});
 await r.service.revoke(proof);assert.equal(r.store.audit().filter(event=>event.action==='mobile.consent.revoke').length,1);assert.equal(r.store.audit().filter(event=>event.action==='grant.create').length,0);
 const body=JSON.stringify({termsHash:r.service.terms().termsHash,mode:'auto'}),approvePath='/v1/mobile/access/approve',approval=await f.a.authorize(e.sessionId,await f.request(e.sessionId,{htu:origin+approvePath,body_hash:bodyHash(body)}),{method:'POST',path:approvePath,body});await assert.rejects(r.service.approve(approval,body));
}finally{r.store.close();f.close();}});

test('mobile request evidence cannot be reconstructed, extended or reused after lock/revocation',async()=>{const f=await fixture();try{const e=await f.enroll(),proof=await f.a.authorize(e.sessionId,await f.request(e.sessionId),req);assert.ok(Object.isFrozen(proof.human));await assert.rejects(f.a.revalidateEvidence(JSON.parse(JSON.stringify(proof))));assert.equal((await f.a.revalidateEvidence(proof)).human.authTime,proof.human.authTime);await f.a.revokeEnrollment(await f.proof({},'b'.repeat(43)),e.enrollmentId);await assert.rejects(f.a.revalidateEvidence(proof));}finally{f.close();}});

test('registered device presence plus separate current resource grant and authenticated actor issue bounded assertion',async()=>{
 const f=await fixture(true),store=new PolicyStore(':memory:',f.options.profile.capabilities);let registeredMobile;try{
  store.registerOrganisation('partner','setup');store.registerPrincipal({id:'human',kind:'human',issuer:'https://pf.example.test',subject:'external-human',organisation:'partner',tokenIssuers:['https://pf.example.test']},'setup');store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agents.example.test',subject:'research-agent',organisation:'partner'},'setup');
  const registry={store,humanBindings:[{issuer:'https://pf.example.test',subject:'external-human',audience:'mobile-bff',principalId:'human'}],agentId:'agent',organisation:'partner',capabilities:f.options.profile.capabilities};
  registeredMobile=new MobileDeviceAuthority({...f.options,current:createMobileRegistryCheck(registry)});
  const challenge=await registeredMobile.beginEnrollment(await f.proof(),{devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:registeredMobile.termsHash});
  const enrolled=await registeredMobile.completeEnrollment({challengeId:challenge.challengeId,signature:f.native(challenge)}),evidence=await registeredMobile.authorize(enrolled.sessionId,await f.request(enrolled.sessionId),req),capability={scope:'m365.document.read',resource:'sharepoint:approved-research'};
  store.createGrant({id:'mobile-document-grant',humanId:'human',agentId:'agent',organisation:'partner',modes:['interactive'],scopes:[capability.scope],resources:[capability.resource],expiresAt:Date.now()+60000,consent:{reference:'separate-resource-approval',approvedAt:Date.now(),expiresAt:Date.now()+60000}},'mobile-resource-consent');
  const signer=await generateKeyPair('RS256'),actor=await generateKeyPair('RS256'),auditEvents=[];
  const options={...registry,mobile:registeredMobile,capability,issuer:'https://mobile-authority.example.test',audience:'api://document-gateway',signer:new DevelopmentSigner(signer.privateKey,'mobile-authority'),keyId:'mobile-authority',publicKey:signer.publicKey,agentIssuer:'https://agents.example.test',agentAudience:'api://mobile-actor',agentKeyId:'actor',agentKey:actor.publicKey,workload:'mobile-document-authority',grantWorkload:'mobile-resource-consent',deviceAssurance:'allow-unattested-poc',audit:async event=>{auditEvents.push(event);},grants:[{enrollmentId:enrolled.enrollmentId,deviceConsentId:evidence.consentId,grantId:'mobile-document-grant',grantVersion:1,resourceConsentReference:'separate-resource-approval'}]};
  const binding={issuer:options.agentIssuer,subject:'research-agent',organisation:'partner',operation:capability.scope,workload:options.workload};
  const token=async(patch={})=>new SignJWT({iss:options.agentIssuer,sub:binding.subject,aud:options.agentAudience,iat:Math.floor(Date.now()/1000),nbf:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+60,jti:crypto.randomUUID(),scope:capability.scope,...patch}).setProtectedHeader({alg:'RS256',kid:'actor',typ:'JWT'}).sign(actor.privateKey);
  const check=createMobileRegistryCheck(registry);await check(evidence);await assert.rejects(check({...evidence,human:{...evidence.human,issuer:'https://evil.test'}}));
  const authority=new MobileExecutionAuthority(options);const agentToken=await token(),issued=await authority.issue(evidence,agentToken,binding),claims=(await jwtVerify(issued,signer.publicKey,{issuer:options.issuer,audience:options.audience})).payload;
  assert.equal(claims.sub,'external-human');assert.deepEqual(claims.act,evidence.agent&&{iss:evidence.agent.issuer,sub:evidence.agent.subject});assert.equal(claims.execution_mode,'interactive');assert.equal(claims.delegation_id,'mobile-document-grant');assert.equal(claims.authentication_basis,'registered-device-key');assert.equal(claims.hardware_attestation,'UNVERIFIED');assert.equal(claims.original_auth_time,Math.floor(evidence.human.authTime/1000));assert.ok(Number(claims.exp)-Number(claims.iat)<=60);
  assert.equal(auditEvents.length,1);assert.ok(!JSON.stringify(auditEvents).includes('eyJ'));assert.ok(!JSON.stringify(auditEvents).includes('external-human'));
  await assert.rejects(authority.issue(evidence,agentToken,binding));await assert.rejects(authority.issue(JSON.parse(JSON.stringify(evidence)),await token(),binding));await assert.rejects(authority.issue(evidence,await token({sub:'other'}),binding));await assert.rejects(authority.issue(evidence,await token(),{...binding,operation:'other'}));
  await assert.rejects(authority.issue(evidence,await token({exp:Math.floor(Date.now()/1000)+120}),binding));
  await assert.rejects(authority.issue(evidence,await token({aud:'other-audience'}),binding));
  const statusPath='/v1/mobile/access/status',statusEvidence=await registeredMobile.authorize(enrolled.sessionId,await f.request(enrolled.sessionId,{htu:origin+statusPath,body_hash:bodyHash('{}')}),{method:'POST',path:statusPath,body:'{}'});
  await assert.rejects(authority.issue(statusEvidence,await token(),binding));
  store.createGrant({id:'mobile-overbroad',humanId:'human',agentId:'agent',organisation:'partner',modes:['interactive','autonomous'],scopes:[capability.scope,'copilot.invoke'],resources:[capability.resource],expiresAt:Date.now()+30000,consent:{reference:'separate-resource-approval',approvedAt:Date.now(),expiresAt:Date.now()+30000}},'mobile-resource-consent');
  await assert.rejects(new MobileExecutionAuthority({...options,grants:[{...options.grants[0],grantId:'mobile-overbroad'}]}).issue(evidence,await token(),binding));
  assert.throws(()=>new MobileExecutionAuthority({...options,grants:[{...options.grants[0],resourceConsentReference:evidence.consentId}]}));
  await assert.rejects(new MobileExecutionAuthority({...options,signer:{sign:async payload=>new DevelopmentSigner(signer.privateKey,'mobile-authority').sign({...payload,sub:'substituted-human'})}}).issue(evidence,await token(),binding));
  await assert.rejects(new MobileExecutionAuthority({...options,audit:async()=>{throw Error('private-audit-detail');}}).issue(evidence,await token(),binding),error=>!error.message.includes('private-audit-detail'));
  await assert.rejects(new MobileExecutionAuthority({...options,timeoutMs:100,signer:{sign:async payload=>{await new Promise(resolve=>setTimeout(resolve,250));return options.signer.sign(payload);}}}).issue(evidence,await token(),binding));
  await assert.rejects(new MobileExecutionAuthority({...options,deviceAssurance:'require-hardware-attestation'}).issue(evidence,await token(),binding));
  await assert.rejects(new MobileExecutionAuthority({...options,signer:{sign:async payload=>{const result=await options.signer.sign(payload);store.revokeGrant('mobile-document-grant','setup');return result;}}}).issue(evidence,await token(),binding));
  store.revokeGrant('mobile-document-grant','setup');await assert.rejects(authority.issue(evidence,await token(),binding));
  store.suspend('agent','agent','setup');await assert.rejects(check(evidence));
 }finally{registeredMobile?.close();store.close();f.close();}
});
test('fresh verified PF login plus independent device signature enrolls for exactly thirty days',async()=>{const f=await fixture();try{const e=await f.enroll();assert.equal(e.enrollmentExpiresAt-f.clock(),30*86400000);const evidence=await f.a.authorize(e.sessionId,await f.request(e.sessionId),req);assert.equal(evidence.type,'registered-device-key');assert.equal(evidence.human.subject,'external-human');assert.equal(evidence.agent.subject,'research-agent');assert.equal(evidence.hardwareAttestation,'UNVERIFIED');assert.ok(!JSON.stringify(evidence).includes('idToken'));assert.ok(!readFileSync(f.path).includes(Buffer.from('eyJ')));}finally{f.close();}});
test('unknown PF issuer, wrong nonce and request-supplied authority never enroll',async()=>{const f=await fixture();try{const input={devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:f.a.termsHash};await assert.rejects(f.a.beginEnrollment(await f.proof({iss:'https://evil.test'}),input));await assert.rejects(f.a.beginEnrollment({...await f.proof(),nonce:'x'.repeat(43)},input));await assert.rejects(f.a.beginEnrollment(await f.proof(),{...input,subject:'other'}));await assert.rejects(f.a.beginEnrollment(await f.proof(),{...input,termsHash:'other'}));await assert.rejects(f.a.beginEnrollment(await f.proof(),{...input,sessionPublicKeySpki:f.d.spki}));}finally{f.close();}});
test('challenge replay, wrong device signature and expired enrollment challenge fail closed',async()=>{const f=await fixture();try{const input={devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:f.a.termsHash},c=await f.a.beginEnrollment(await f.proof(),input);await assert.rejects(f.a.completeEnrollment({challengeId:c.challengeId,signature:f.native(c,f.f)}));await assert.rejects(f.a.completeEnrollment({challengeId:c.challengeId,signature:f.native(c)}));const next=await f.a.beginEnrollment(await f.proof({},'z'.repeat(43)),input);f.advance(121000);await assert.rejects(f.a.completeEnrollment({challengeId:next.challengeId,signature:f.native(next)}));}finally{f.close();}});
test('resumption after original PF token expiry retains provenance and never extends absolute enrollment',async()=>{const f=await fixture();try{const e=await f.enroll();f.advance(2*3600000);const key=device(),c=await f.a.beginResume({enrollmentId:e.enrollmentId,sessionPublicKeySpki:key.spki}),r=await f.a.completeResume({challengeId:c.challengeId,signature:f.native(c)});assert.equal(r.enrollmentExpiresAt,e.enrollmentExpiresAt);assert.notEqual(r.sessionId,e.sessionId);await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId),req));const evidence=await f.a.authorize(r.sessionId,await f.request(r.sessionId,{},key),req);assert.ok(evidence.human.authTime<f.clock()-3600000);assert.equal(evidence.verifiedAt,f.clock());}finally{f.close();}});
test('session ID alone, another key, wrong route/body/audience and proof replay grant no access',async()=>{const f=await fixture();try{const e=await f.enroll();await assert.rejects(f.a.authorize(e.sessionId,'',req));for(const patch of [{aud:'https://other.test'},{htu:origin+'/admin'},{body_hash:bodyHash('other')},{sub:'other'},{exp:Math.floor(f.clock()/1000)+600}])await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId,patch),req));await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId,{},f.d),req));const p=await f.request(e.sessionId);await f.a.authorize(e.sessionId,p,req);await assert.rejects(f.a.authorize(e.sessionId,p,req));await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId),{...req,path:'/admin'}));}finally{f.close();}});
test('persistent replay, session expiry, registry suspension and device revocation deny resumption/use',async()=>{const f=await fixture();let second;try{const e=await f.enroll(),p=await f.request(e.sessionId);await f.a.authorize(e.sessionId,p,req);second=new MobileDeviceAuthority(f.options);await assert.rejects(second.authorize(e.sessionId,p,req));await f.a.revokeEnrollment(await f.proof({},'r'.repeat(43)),e.enrollmentId);await assert.rejects(second.beginResume({enrollmentId:e.enrollmentId,sessionPublicKeySpki:device().spki}));await assert.rejects(second.authorize(e.sessionId,await f.request(e.sessionId),req));}finally{second?.close();f.close();}});
test('current-policy failure and expired thirty-day enrollment never return new authority',async()=>{for(const expired of [false,true]){const f=await fixture();try{const e=await f.enroll();if(expired)f.advance(30*86400000+1);else f.suspend();await assert.rejects(f.a.beginResume({enrollmentId:e.enrollmentId,sessionPublicKeySpki:device().spki}),error=>!error.message.includes('PRIVATE'));}finally{f.close();}}});

test('a new ID token cannot reuse an already consumed login nonce',async()=>{const f=await fixture();try{await f.enroll();await assert.rejects(f.a.beginEnrollment(await f.proof({jti:'different-token'}),{devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:f.a.termsHash}));}finally{f.close();}});

test('profile drift and a removed profile seal cannot reopen or use existing state',async()=>{const f=await fixture();let db;try{const e=await f.enroll();assert.throws(()=>new MobileDeviceAuthority({...f.options,profile:{...f.options.profile,organisation:'other'}}));db=new DatabaseSync(f.path);db.exec('DELETE FROM mobile_meta');await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId),req));assert.throws(()=>new MobileDeviceAuthority(f.options));}finally{db?.close();f.close();}});

test('one challenge cannot create two sessions across separate authorities',async()=>{const f=await fixture();let other;try{const c=await f.a.beginEnrollment(await f.proof(),{devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:f.a.termsHash});other=new MobileDeviceAuthority(f.options);const input={challengeId:c.challengeId,signature:f.native(c)},results=await Promise.allSettled([f.a.completeEnrollment(input),other.completeEnrollment(input)]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(results.filter(r=>r.status==='rejected').length,1);}finally{other?.close();f.close();}});

test('fresh explicit enrollment renews only its owner and invalidates old foreground sessions',async()=>{const f=await fixture();try{const e=await f.enroll(),input={devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:f.a.termsHash};await assert.rejects(f.a.beginEnrollment(await f.proof({sub:'different-human'},'o'.repeat(43)),input));await assert.rejects(f.a.revokeEnrollment(await f.proof({sub:'different-human'},'q'.repeat(43)),e.enrollmentId));const c=await f.a.beginEnrollment(await f.proof({},'s'.repeat(43)),input),r=await f.a.completeEnrollment({challengeId:c.challengeId,signature:f.native(c)});assert.notEqual(e.sessionId,r.sessionId);await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId),req));await f.a.authorize(r.sessionId,await f.request(r.sessionId),req);}finally{f.close();}});

test('revocation during an awaited policy check prevents release of request authority',async()=>{const f=await fixture();let other;try{const e=await f.enroll();let started,release;const waiting=new Promise<void>(resolve=>started=resolve),barrier=new Promise<void>(resolve=>release=resolve);other=new MobileDeviceAuthority({...f.options,current:async()=>{started();await barrier;}});const result=other.authorize(e.sessionId,await f.request(e.sessionId),req);await waiting;await f.a.revokeEnrollment(await f.proof({},'v'.repeat(43)),e.enrollmentId);release();await assert.rejects(result);}finally{other?.close();f.close();}});

test('foreground expiry requires a new signed unlock and pending unlock cannot undo revocation',async()=>{const f=await fixture();try{const e=await f.enroll();f.advance(15*60000+1);await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId),req));const c=await f.a.beginResume({enrollmentId:e.enrollmentId,sessionPublicKeySpki:device().spki});f.advance(-15*60000-1);await f.a.revokeEnrollment(await f.proof({},'w'.repeat(43)),e.enrollmentId);await assert.rejects(f.a.completeResume({challengeId:c.challengeId,signature:f.native(c)}));}finally{f.close();}});

test('local-spike signatures and non-P256 device keys cannot enroll live authority',async()=>{const f=await fixture();try{const input={devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:f.a.termsHash},rsa=generateKeyPairSync('rsa',{modulusLength:2048});await assert.rejects(f.a.beginEnrollment(await f.proof(),{...input,devicePublicKeySpki:rsa.publicKey.export({type:'spki',format:'der'}).toString('base64url')}));const c=await f.a.beginEnrollment(await f.proof(),input);await assert.rejects(f.a.completeEnrollment({challengeId:c.challengeId,signature:sign('sha256',Buffer.from('federated-copilot/device-test/v1\n'+c.challenge),f.d.privateKey).toString('base64url')}));}finally{f.close();}});

test('actual mobile WebCrypto controller enrolls and resumes against durable server authority',async()=>{
 const f=await fixture(true),resources=resourceFixture(f);let app;try{
  const native={getStatus:async()=>({available:true,hasKey:true,securityLevel:'tee'}),createKey:async()=>({publicKeySpki:f.d.spki,securityLevel:'tee'}),signChallenge:async({challenge})=>({challenge,publicKeySpki:f.d.spki,signature:f.native({challenge}),algorithm:'SHA256withECDSA-DER'}),lock:async()=>{}};
  // The fixture's OIDC token remains server-side; the app receives only a challenge.
  let state='',nonce='';const secret=Buffer.alloc(32,19).toString('base64url');
  const login=new MobileLoginHandoff({origin,authorizationEndpoint:'https://pf.example.test/as/authorization.oauth2',authority:f.a,oidc:{
   start:async(s,n)=>{state=s;nonce=n;return'https://pf.example.test/as/authorization.oauth2?request_uri=urn:test';},
   redeem:async()=>({idToken:(await f.proof({},nonce)).idToken})
  }});
  let evidence;const api=new MobileHttpApi({origin,authority:f.a,handoff:login,resourceConsent:resources.service,execute:async input=>{evidence=input.evidence;return{answer:'Fixture authority diagnostic; not Copilot'};}});
  const transport=new MobileHttpsTransport(origin,'https://pf.example.test/as/authorization.oauth2',async(url,init)=>api.handle(new Request(String(url),{...init,headers:{...Object.fromEntries(new Headers(init?.headers)),Origin:'https://localhost'}})));
  app=new LiveDeviceSession(origin,native,transport);
  const config=await transport.config();assert.equal(config.termsHash,f.a.termsHash);
  await transport.startLogin({devicePublicKeySpki:f.d.spki,claimHash:bodyHash(secret)});
  const callback=await api.handle(new Request(origin+'/mobile/callback?state='+state+'&code=fixture-code'));assert.equal(callback.status,303);
  const handoff=parseMobileReturn(callback.headers.get('location')!,origin);
  const enrollment=await app.enroll(keys=>transport.claim({handoff,claimSecret:secret,sessionPublicKeySpki:keys.sessionPublicKeySpki,termsHash:config.termsHash}));login.close();
  const resourceTerms=await transport.resourceTerms(),approvalBody=JSON.stringify({termsHash:resourceTerms.termsHash,mode:'manual'});
  assert.equal((await transport.resourceStatus(await app.request('{}','/v1/mobile/access/status'))).approved,false);
  await transport.approveResources(await app.request(approvalBody,'/v1/mobile/access/approve'));
  const body='{"question":"Hello"}',first=await app.request(body);assert.equal((await transport.chat(first)).answer,'Fixture authority diagnostic; not Copilot');
  assert.equal(evidence.human.subject,'external-human');assert.equal(evidence.agent.subject,'research-agent');assert.equal(evidence.hardwareAttestation,'UNVERIFIED');
  await assert.rejects(transport.chat(first));await app.lock();await assert.rejects(app.request(body));
  const resumed=await app.resume(enrollment.enrollmentId);assert.equal(resumed.enrollmentExpiresAt,enrollment.enrollmentExpiresAt);
  const second=await app.request(body);assert.notEqual(second.sessionId,first.sessionId);await transport.chat(second);
  await f.a.revokeEnrollment(await f.proof({},'k'.repeat(43)),enrollment.enrollmentId);const revoked=await app.request(body);await assert.rejects(transport.chat(revoked));
 }finally{await app?.lock();resources.store.close();f.close();}
});

test('live app controller traverses browser handoff, HTTP enrollment, new-chat resume and revocation',async()=>{
 for(const autoApprove of [true,false]){
 const f=await fixture(true),resources=resourceFixture(f);let controller;try{
  let state='',nonce='',pending=false,reference={enrolled:false},executions=0;
  const secret=Buffer.alloc(32,29).toString('base64url'),attemptId=crypto.randomUUID();
  const device={getStatus:async()=>({available:true,hasKey:true,securityLevel:'tee'}),createKey:async()=>({publicKeySpki:f.d.spki,securityLevel:'tee'}),signChallenge:async({challenge})=>({challenge,publicKeySpki:f.d.spki,signature:f.native({challenge}),algorithm:'SHA256withECDSA-DER'}),lock:async()=>{}};
  const login=new MobileLoginHandoff({origin,authorizationEndpoint:'https://pf.example.test/as/authorization.oauth2',authority:f.a,oidc:{start:async(s,n)=>{state=s;nonce=n;return'https://pf.example.test/as/authorization.oauth2?client_id=fixture&request_uri=urn:test';},redeem:async()=>({idToken:(await f.proof({},nonce)).idToken})}});
  const api=new MobileHttpApi({origin,authority:f.a,handoff:login,resourceConsent:resources.service,execute:async input=>{assert.equal(input.evidence.human.subject,'external-human');assert.equal(input.evidence.agent.subject,'research-agent');executions++;return{answer:'Test-only execution; not Microsoft'};}});
  const transport=new MobileHttpsTransport(origin,'https://pf.example.test/as/authorization.oauth2',async(url,init)=>api.handle(new Request(String(url),{...init,headers:{...Object.fromEntries(new Headers(init?.headers)),Origin:'https://localhost'}})));
  const status=()=>pending?{pending:true,attemptId,devicePublicKeySpki:f.d.spki,claimHash:bodyHash(secret),expiresInMs:300000}:{pending:false};
  const browser={beginLogin:async()=>{pending=true;return status();},getPendingLogin:async()=>status(),openLogin:async()=>{},consumeReturn:async input=>{assert.equal(pending,true);pending=false;return{handoff:parseMobileReturn(input.returnUrl,origin),claimSecret:secret,devicePublicKeySpki:f.d.spki};},cancelLogin:async()=>{pending=false;},getEnrollmentReference:async()=>reference,saveEnrollmentReference:async value=>{reference={enrolled:true,...value};},forgetLocalEnrollment:async()=>{reference={enrolled:false};}};
  browser.getConsentPreference=async()=>({enabled:autoApprove});browser.setConsentPreference=async()=>{};
  const session=new LiveDeviceSession(origin,device,transport);controller=new MobileAppController({origin,device,browser,transport,session});
  await controller.initialize();await controller.signIn();assert.equal(controller.snapshot().phase,'browser');await controller.background();
  const response=await api.handle(new Request(origin+'/mobile/callback?state='+state+'&code=fixture-code'));
  await controller.handleReturn(response.headers.get('location')!);assert.equal(controller.snapshot().phase,autoApprove?'chat':'consent');
  if(!autoApprove){await assert.rejects(controller.send('not yet approved'));await controller.approveAccess();}
  assert.equal(controller.snapshot().phase,'chat');const firstChat=controller.snapshot().chatId;
  await controller.send('Hello');assert.equal(executions,1);assert.equal(controller.snapshot().messages.length,2);
  await controller.background();assert.equal(controller.snapshot().messages.length,0);await controller.unlock();assert.equal(controller.snapshot().phase,'chat');assert.notEqual(controller.snapshot().chatId,firstChat);
  const stale=await session.request(JSON.stringify({question:'After revocation'}));await controller.revokeAccess();assert.equal(controller.snapshot().resourceRevoked,true);await assert.rejects(transport.chat(stale));assert.equal(executions,1);assert.equal(controller.snapshot().messages.length,0);
  await controller.unlock();assert.equal(controller.snapshot().phase,'consent');assert.equal(controller.snapshot().resourceRevoked,true);await assert.rejects(controller.approveAccess());
  login.close();
 }finally{await controller?.cancelSignIn();resources.store.close();f.close();}
 }
});

test('signed chat result proofs cannot substitute a different route, replay or resume into an old job',async()=>{
 const f=await fixture(true);let jobs;try{
  const enrolled=await f.enroll(),original=await f.a.authorize(enrolled.sessionId,await f.request(enrolled.sessionId),req);
  jobs=new MobileChatJobs({timeoutMs:1000,capacity:2,revalidate:v=>f.a.revalidateEvidence(v),authorise:async()=>{},execute:async()=>({answer:'explicit executor fixture'})});
  const started=await jobs.start(original,'Hello'),path='/v1/mobile/chat/result',body=JSON.stringify({jobId:started.jobId});
  const signed=await f.request(enrolled.sessionId,{htu:origin+path,body_hash:bodyHash(body)});
  await assert.rejects(f.a.authorize(enrolled.sessionId,signed,{method:'POST',path:'/v1/mobile/chat/cancel',body}));
  const reader=await f.a.authorize(enrolled.sessionId,signed,{method:'POST',path,body});
  await assert.rejects(f.a.authorize(enrolled.sessionId,signed,{method:'POST',path,body}));
  await new Promise(r=>setTimeout(r,5));assert.deepEqual(await jobs.result(reader,started.jobId),{status:'complete',answer:'explicit executor fixture'});
  const cancelPath='/v1/mobile/chat/cancel',cancel=await f.a.authorize(enrolled.sessionId,await f.request(enrolled.sessionId,{htu:origin+cancelPath,body_hash:bodyHash(body)}),{method:'POST',path:cancelPath,body});
  assert.equal(cancel.requestPath,cancelPath);
  const second=await jobs.start(await f.a.authorize(enrolled.sessionId,await f.request(enrolled.sessionId),req),'Hello');
  const challenge=await f.a.beginResume({enrollmentId:enrolled.enrollmentId,sessionPublicKeySpki:f.f.spki}),resumed=await f.a.completeResume({challengeId:challenge.challengeId,signature:f.native(challenge)});
  const newBody=JSON.stringify({jobId:second.jobId}),newReader=await f.a.authorize(resumed.sessionId,await f.request(resumed.sessionId,{htu:origin+path,body_hash:bodyHash(newBody)}),{method:'POST',path,body:newBody});
  await assert.rejects(jobs.result(newReader,second.jobId));
 }finally{jobs?.close();f.close();}
});

test('actual mobile HTTPS client polls signed jobs through durable device and resource consent checks',async()=>{
 const f=await fixture(true),r=resourceFixture(f);let jobs;try{
  const enrolled=await f.enroll(),approvalPath='/v1/mobile/access/approve',approvalBody=JSON.stringify({termsHash:r.service.terms().termsHash,mode:'manual'});
  await r.service.approve(await f.a.authorize(enrolled.sessionId,await f.request(enrolled.sessionId,{htu:origin+approvalPath,body_hash:bodyHash(approvalBody)}),{method:'POST',path:approvalPath,body:approvalBody}),approvalBody);
  let executions=0;const paths=[];
  jobs=new MobileChatJobs({timeoutMs:5000,capacity:2,revalidate:e=>f.a.revalidateEvidence(e),authorise:e=>r.service.authoriseChat(e),execute:async({evidence,question})=>{executions++;await f.a.revalidateEvidence(evidence);assert.equal(question,'Hello');return{answer:'explicit local executor fixture; not Copilot'};}});
  const api=new MobileHttpApi({origin,authority:f.a,handoff:{},resourceConsent:r.service,jobs});
  const t=new MobileHttpsTransport(origin,'https://pf.example.test/as/authorization.oauth2',async(url,init)=>{paths.push(new URL(url).pathname);return api.handle(new Request(url,{...init,headers:{...init.headers,Origin:'https://localhost'}}));});
  const signed=async(body,path='/v1/mobile/chat/messages')=>({body,sessionId:enrolled.sessionId,proof:await f.request(enrolled.sessionId,{htu:origin+path,body_hash:bodyHash(body)})});
  assert.deepEqual(await t.chat(await signed(req.body),signed),{answer:'explicit local executor fixture; not Copilot'});
  assert.equal(executions,1);assert.deepEqual(paths,['/v1/mobile/chat/messages','/v1/mobile/chat/result']);
 }finally{jobs?.close();r.store.close();f.close();}
});


test('explicit three-minute execution lease does not extend request proof acceptance and is sealed into device terms',async()=>{
 const f=await fixture(false,180);try{const e=await f.enroll(),unused=await f.request(e.sessionId),evidence=await f.a.authorize(e.sessionId,await f.request(e.sessionId),req);assert.equal(evidence.expiresAt-f.clock(),180000);f.advance(70000);await assert.rejects(f.a.authorize(e.sessionId,unused,req));await f.a.revalidateEvidence(evidence);assert.throws(()=>new MobileDeviceAuthority({...f.options,profile:{...f.options.profile,executionLeaseSeconds:60}}));f.advance(111000);await assert.rejects(f.a.revalidateEvidence(evidence));}finally{f.close();}
});
test('server lifecycle reset invalidates foreground proofs and challenges while preserving thirty-day enrollment',async()=>{const f=await fixture();try{const e=await f.enroll(),evidence=await f.a.authorize(e.sessionId,await f.request(e.sessionId),req),old=await f.a.beginResume({enrollmentId:e.enrollmentId,sessionPublicKeySpki:f.f.spki});f.a.resetForegroundSessions();await assert.rejects(f.a.revalidateEvidence(evidence));await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId),req));await assert.rejects(f.a.completeResume({challengeId:old.challengeId,signature:f.native(old)}));const fresh=await f.a.beginResume({enrollmentId:e.enrollmentId,sessionPublicKeySpki:f.f.spki}),resumed=await f.a.completeResume({challengeId:fresh.challengeId,signature:f.native(fresh)});assert.equal(resumed.enrollmentExpiresAt,e.enrollmentExpiresAt);assert.notEqual(resumed.sessionId,e.sessionId);}finally{f.close();}});
test('enrollment and resume return a server timestamp within the issued foreground session',async()=>{const f=await fixture();try{const e=await f.enroll();assert.ok(Number.isSafeInteger(e.serverTime));assert.equal(e.sessionExpiresAt-e.serverTime,900000);const c=await f.a.beginResume({enrollmentId:e.enrollmentId,sessionPublicKeySpki:f.f.spki}),r=await f.a.completeResume({challengeId:c.challengeId,signature:f.native(c)});assert.ok(Number.isSafeInteger(r.serverTime));assert.equal(r.sessionExpiresAt-r.serverTime,900000);assert.equal(r.enrollmentExpiresAt,e.enrollmentExpiresAt);}finally{f.close();}});
test('server still rejects unadjusted future phone proofs with zero clock tolerance',async()=>{const f=await fixture();try{const e=await f.enroll(),now=Math.floor(f.clock()/1000);await assert.rejects(f.a.authorize(e.sessionId,await f.request(e.sessionId,{iat:now+6,nbf:now+6,exp:now+60}),req));assert.ok(await f.a.authorize(e.sessionId,await f.request(e.sessionId),req));}finally{f.close();}});

test('provider credentials enter Vault only after actual OIDC and device signature completion',async()=>{
 const f=await fixture(true),resources=resourceFixture(f);let enrollment,provider;try{
  let nonce='',record,version=0,writes=0;const transport=async(url,init)=>{
   if(String(url).startsWith('https://vault.example.test/v1/mobile-provider/data/')){if(init.method==='POST'){const b=JSON.parse(init.body);assert.equal(b.options.cas,version);record=b.data;version++;writes++;return Response.json({data:{version}});}return record?Response.json({data:{metadata:{version},data:record}}):Response.json({},{status:404});}
   if(String(url)==='https://pf.example.test/pf/JWKS')return Response.json({keys:[{...await exportJWK(oidc.publicKey),kid:'fixture-oidc',alg:'RS256',use:'sig'}]});
   const b=new URLSearchParams(init.body);if(String(url).endsWith('/par.oauth2')){nonce=b.get('nonce');return Response.json({request_uri:'urn:fixture',expires_in:60});}
   assert.equal(b.get('grant_type'),'authorization_code');const now=Math.floor(Date.now()/1000),access=await new SignJWT({iss:'https://pf.example.test',aud:'api://copilot-login',sub:'external-human',scope:'copilot.login',iat:now,nbf:now,exp:now+3600,jti:crypto.randomUUID()}).setProtectedHeader({alg:'RS256',kid:'fixture-oidc'}).sign(oidc.privateKey);return Response.json({id_token:(await f.proof({},nonce)).idToken,access_token:access,refresh_token:'synthetic-refresh-fixture',token_type:'Bearer'});
  };
  const client=new OidcClient({issuer:'https://pf.example.test',jwksUri:'https://pf.example.test/pf/JWKS',clientId:'mobile-bff',keyIds:['fixture-oidc'],callbackPath:'/mobile/callback',providerAuthorization:{scope:'copilot.login',resource:'urn:copilot:login'},authorizationEndpoint:'https://pf.example.test/as/authorization.oauth2',parEndpoint:'https://pf.example.test/as/par.oauth2',tokenEndpoint:'https://pf.example.test/as/token.oauth2',redirectUri:origin+'/mobile/callback',keyId:'client',clientKey:oidc.privateKey,adapterId:'fixture',fetch:transport});
  provider=new MobileProviderSessions({trust:{issuer:'https://pf.example.test',jwksUri:'https://pf.example.test/pf/JWKS',audience:'api://copilot-login',scope:'copilot.login',keyIds:['fixture-oidc'],maxLifetimeSeconds:3600},tokenEndpoint:'https://pf.example.test/as/token.oauth2',clientId:'mobile-bff',keyId:'client',clientKey:oidc.privateKey,timeoutMs:2000},{store:new VaultMobileProviderStore({origin:'https://vault.example.test',mount:'mobile-provider',token:()=> 'synthetic-vault-token',timeoutMs:1000,fetch:transport}),revalidate:e=>f.a.revalidateEvidence(e),authorise:e=>resources.service.authoriseChat(e),fetch:transport});
  enrollment=new MobileProviderEnrollment(client,f.a,provider);const state='s'.repeat(43),verifier='v'.repeat(43),n='n'.repeat(43);await enrollment.oidc.start(state,n,verifier);const result=await enrollment.oidc.redeem('fixture-code',verifier,n);assert.deepEqual(Object.keys(result),['idToken']);assert.equal(writes,0);
  const challenge=await enrollment.authority.beginEnrollment({idToken:result.idToken,nonce:n},{devicePublicKeySpki:f.d.spki,sessionPublicKeySpki:f.f.spki,termsHash:f.a.termsHash});assert.equal(writes,0);
  const completion=await enrollment.authority.completeEnrollment({challengeId:challenge.challengeId,signature:f.native(challenge)});assert.equal(writes,1);assert.equal(record.enrollmentId,completion.enrollmentId);assert.equal(record.enrollmentExpiresAt,completion.enrollmentExpiresAt);await assert.rejects(enrollment.authority.completeEnrollment({challengeId:challenge.challengeId,signature:f.native(challenge)}));assert.equal(writes,1);
  const evidenceFor=async(path,body)=>f.a.authorize(completion.sessionId,await f.request(completion.sessionId,{htu:origin+path,body_hash:bodyHash(body)}),{method:'POST',path,body});const body=JSON.stringify({termsHash:resources.service.terms().termsHash,mode:'manual'});await resources.service.approve(await evidenceFor('/v1/mobile/access/approve',body),body);assert.equal(typeof await provider.get(await evidenceFor(req.path,req.body),new AbortController().signal),'string');
  const revoke=await evidenceFor('/v1/mobile/access/revoke','{}');await resources.service.revoke(revoke);await provider.retire(revoke);assert.equal(record.state,'revoked');assert.equal(record.refreshToken,'');assert.equal(record.accessToken,'');
 }finally{enrollment?.close();provider?.close();resources.store.close();f.close();}
});
