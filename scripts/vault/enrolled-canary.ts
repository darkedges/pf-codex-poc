import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {importPKCS8} from 'jose';
import {OidcClient} from '../../src/identity/oidc.ts';
import {LocalBrowser,forms} from '../../tests/live/local-browser.mjs';
import {read,load,admin} from '../pf/common.mjs';
import {profile} from '../pf/config.mjs';
import {startConsent} from '../pf/run-consent.mjs';
import {localToolAuthority} from '../pf/consent-tool-exchange.ts';
import {issueConsentedUpstream} from '../pf/consent-exchange.ts';
import {revokeOwnedToolConsent} from '../pf/revoke-owned-tool-consent.mjs';
import {withToolClient} from '../pf/tool-client-lease.mjs';
import {custody} from './tool-custody.mjs';
import {validateCanaryClaims,canaryTerminalState,revokeOwnedCanaryGrant} from './enrolled-canary-checks.mjs';

const query=(sql:string,...params:any[])=>{const db=new DatabaseSync(resolve(custody,'policy.sqlite'),{readOnly:true});try{return db.prepare(sql).all(...params);}finally{db.close();}};
export const canaryGrantState=()=>query('SELECT id,state,version FROM grants ORDER BY id');
export async function enrolledCanary(options:{run:string;origin:string;call:(input:any)=>any;check:(name:string,value:any)=>void}){
 const {run,origin,call,check}=options,before=canaryGrantState(),owned:string[]=[],tokens:string[]=[],issued:any[]=[];
 const record=()=>writeFileSync(resolve(run,'canary-grants.json'),JSON.stringify({before,owned}),{mode:0o600});record();
 let portal:any,clean=false,stage='portal-startup';
 const newConsents=()=>query('SELECT g.id,g.human_id,g.agent_id,g.organisation,g.recorded_by,g.state FROM grants g JOIN consents c ON c.grant_id=g.id ORDER BY g.id').filter(g=>!before.some(b=>b.id===g.id));
 try{
  portal=await startConsent({...process.env,POLICY_API_ORIGIN:origin,CONSENT_PORT:'9461'});
  const revoke=(id:string)=>revokeOwnedCanaryGrant(()=>query('SELECT state FROM grants WHERE id=?',id)[0]?.state,()=>revokeOwnedToolConsent(portal.origin,id));
  async function approve(){
   const b=new LocalBrowser(portal.origin),home=await b.request(portal.origin+'/');
   const login=await b.submit(forms(home.html).find(f=>f.action==='/login'));
   const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
   const review=await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
   const result=await b.submit(forms(review.html).find(f=>f.action==='/approve'),{duration:'3600',autonomous:'on'});
   const form=forms(result.html).find(f=>f.action==='/revoke'&&!before.some(g=>g.id===f.fields.grantId)&&!owned.includes(f.fields.grantId));assert.ok(form&&typeof form.fields.grantId==='string');const id=form.fields.grantId;assert.ok(!before.some(g=>g.id===id));owned.push(id);record();return id;
  }
  async function loginProof(){
   const c=new OidcClient({...load('oidc-config.json'),redirectUri:portal.origin+'/callback',clientKey:await importPKCS8(read('consent-oidc.private.pem'),'RS256')});
   const nonce=randomBytes(24).toString('hex'),verifier=randomBytes(32).toString('base64url'),b=new LocalBrowser(portal.origin);
   const login=await b.request(await c.start(randomBytes(24).toString('hex'),nonce,verifier));
   const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
   await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'},{captureCallback:true});
   const result=await c.redeem(new URL(b.callback).searchParams.get('code')!,verifier,nonce);return{idToken:result.idToken,nonce};
  }
  await withToolClient(admin,async()=>{
   try{
    const authority=await localToolAuthority(origin,'gateway');
    for(const mode of ['interactive','autonomous']){
     stage=mode+'-human-consent';const id=await approve();stage=mode+'-fresh-login';const login=mode==='interactive'?await loginProof():undefined;stage=mode+'-PF-issuance';const token=await authority.issue(id,mode,login);tokens.push(token.accessToken);
     check(mode+': verified human actor organisation grant mode issuer audience and scope',validateCanaryClaims(token.claims,id,mode));
     check(mode+': enrolled Docker tool accepts actual PF token',call({token:token.accessToken}).authorized===true);
     check(mode+': missing sender certificate denied',call({token:token.accessToken,client:'none'}).error==='transport_denied');
     check(mode+': prompt identity and resource override denied',call({token:token.accessToken,body:{sub:'forged',resource:'sharepoint:unapproved'}}).status===400);
     const upstream=await issueConsentedUpstream(id,mode,login,origin);tokens.push(upstream);check(mode+': upstream token audience denied',call({token:upstream}).status===401);
     const audit=query("SELECT * FROM audit WHERE grant_id=? AND action='decision' AND workload='policy-tool' AND outcome='permit'",id);
     check(mode+': independent pre and post tool policy audit preserves identities',audit.length>=2&&audit.every(a=>a.subject===profile.human&&a.actor===profile.agent&&a.actor_issuer===profile.agentIssuer&&a.organisation===profile.org&&a.mode===mode&&a.token_issuer==='https://pf-b.copilot.darkedges.com'&&a.audience==='api://copilot-tool'&&a.scope==='copilot.invoke'&&a.resource==='sharepoint:approved-research'));
     issued.push({id,mode,login,token});
    }
    stage='real-token-aging';const until=Math.max(...issued.map(i=>i.token.claims.exp))*1000+1000;assert.ok(until-Date.now()>0&&until-Date.now()<=122000);let progress=Date.now();
    while(Date.now()<until){await new Promise(done=>setTimeout(done,Math.min(1000,until-Date.now())));if(Date.now()-progress>=30000){console.log(JSON.stringify({phase:'enrolled-canary-token-aging',remainingSeconds:Math.max(0,Math.ceil((until-Date.now())/1000))}));progress=Date.now();}}
    for(const item of issued){
     check(item.mode+': actual expired token denied',call({token:item.token.accessToken}).status===401);
     const fresh=await authority.issue(item.id,item.mode,item.login);tokens.push(fresh.accessToken);check(item.mode+': fresh token under same active grant accepted',validateCanaryClaims(fresh.claims,item.id,item.mode)&&call({token:fresh.accessToken}).authorized===true);
     stage=item.mode+'-owner-revocation';await revoke(item.id);
     check(item.mode+': revoked grant blocks existing token',call({token:fresh.accessToken}).status===403);
     await assert.rejects(authority.issue(item.id,item.mode,item.login));check(item.mode+': revoked grant blocks new issuance',true);
     const denied=query("SELECT * FROM audit WHERE grant_id=? AND action='decision' AND workload='policy-tool' AND outcome='deny'",item.id);check(item.mode+': revocation recorded by independent PDP',denied.some(a=>Number(a.grant_version)>=2));
    }
    const journal=readFileSync(resolve(run,'audit/tool-access.jsonl'),'utf8'),rows=journal.trim().split('\n').map(line=>JSON.parse(line));
    check('restricted tool journal records success and denial without tokens or raw identities',rows.some(r=>r.outcome==='success')&&rows.some(r=>r.outcome==='denied')&&!journal.includes(profile.human)&&!journal.includes(profile.agent)&&tokens.every(t=>!journal.includes(t)));
   }finally{
    // Reconcile only new owner-consented grants; never revoke pre-existing rows.
    for(const g of newConsents()){
     assert.ok(g.human_id==='consent-human'&&g.agent_id==='container-agent'&&g.organisation===profile.org&&g.recorded_by==='policy-consent');
     if(!owned.includes(String(g.id))){owned.push(String(g.id));record();}
     if(g.state!=='revoked')await revoke(String(g.id));
    }
    clean=canaryTerminalState(before,canaryGrantState(),owned);assert.ok(clean);
   }
  });
  check('all canary grants revoked and preexisting grant state preserved',clean);
  return{before,owned};
 }catch{console.error(JSON.stringify({error:'Enrolled consent canary failed',stage}));throw Error('Enrolled consent canary failed');}finally{
  if(portal)await portal.stop();
  clean=canaryTerminalState(before,canaryGrantState(),owned);
  const clients=(await admin('a','oauth/clients/copilot-studio-generic-oauth')).enabled===true&&(await admin('b','oauth/clients/copilot-sso-exchange')).enabled===false;
  writeFileSync(resolve(run,'canary-cleanup.json'),JSON.stringify({grantsRevoked:clean,clientsRestored:clients,portalStopped:true}),{mode:0o600});assert.ok(clean&&clients);
 }
}
