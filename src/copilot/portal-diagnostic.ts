import {setTimeout as pause} from 'node:timers/promises';
import {DirectLineAdapter} from '../adapters/direct-line.ts';
import type {DirectLineConfig,DirectLineDependencies} from '../adapters/copilot.ts';
import type {DelegatedClaims,TokenVerifier} from '../adapters/token-exchange.ts';
import type {ProviderAccessClaims} from '../identity/provider-access.ts';
import {PolicyError,type VerifiedLogin} from '../policy/contracts.ts';
type Proof={grantId:string;providerToken:string;login:{idToken:string;nonce:string}};
type Controls={beforeConversation():void;beforeTokenPost():void};
type Config={channel:DirectLineConfig;agent:{issuer:string;subject:string};organisation:string;resource:string;timeoutMs:number;pollIntervalMs:number};
type Dependencies={
 loginVerifier:{verify(token:string,nonce:string):Promise<VerifiedLogin>};brokerVerifier:TokenVerifier;
 providerVerifier:{verify(token:string):Promise<ProviderAccessClaims>};
 issueBroker(proof:Proof,signal:AbortSignal):Promise<{brokerToken:string;agentToken:string}>;
 authorise:DirectLineDependencies['authorise'];secret:DirectLineDependencies['secret'];
 handoff(proof:{brokerToken:string;providerToken:string;agentToken:string;login:Proof['login']},signal:AbortSignal):Promise<void>;
 verifyToolAudit(context:{claims:Readonly<DelegatedClaims>;resource:string;startedAt:number},signal:AbortSignal):Promise<boolean>;
 observe?:(event:{event:'portal_diagnostic';stage:'token_post'|'result';status?:number;outcome?:'verified'|'unavailable'})=>void;
 fetch?:typeof fetch;
};
const signedIn='Authentication status: signed in. Copilot reports User.IsLoggedIn=true. Delegated tool access has not been verified.';
// Fixed interactive operation only. No prompt, URL, identity, scope or resource
// supplied by the browser selects a tool or transport destination.
export function createPortalDiagnostic(config:Config,dependencies:Dependencies){
 const c=structuredClone(config);
 if(c.channel.endpoint!=='https://directline.botframework.com/v3/directline'||c.channel.maxSessions!==1||!c.channel.providerSso||c.channel.tokenPostRules.length!==1||c.channel.tokenPostRules[0].origin!=='https://token.botframework.com'||c.channel.tokenPostRules[0].pathExact!=='/api/sas/postToken'||!c.agent?.issuer||!c.agent.subject||!c.organisation||!c.resource||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>75000||!Number.isInteger(c.pollIntervalMs)||c.pollIntervalMs<1||c.pollIntervalMs>1000)throw new PolicyError('configuration');
 return async(proof:Proof,controls:Controls):Promise<{authorized:true}>=>{
  const observe=(event:Parameters<NonNullable<Dependencies['observe']>>[0])=>{try{dependencies.observe?.(event);}catch{}};
  const controller=new AbortController(),signal=controller.signal;let adapter:DirectLineAdapter|undefined,handle:string|undefined,brokerToken='',closing=false;
  const timeout=setTimeout(()=>controller.abort(),c.timeoutMs),startedAt=Date.now();
  let rejectDeadline:(reason:Error)=>void=()=>{};
  const deadline=new Promise<never>((_resolve,reject)=>{rejectDeadline=reject;});
  const abort=()=>rejectDeadline(new PolicyError('unavailable'));signal.addEventListener('abort',abort,{once:true});
  try{return await Promise.race([deadline,(async()=>{
   const human=await dependencies.loginVerifier.verify(proof.login.idToken,proof.login.nonce);signal.throwIfAborted();
   const provider=await dependencies.providerVerifier.verify(proof.providerToken);signal.throwIfAborted();
   if(provider.sub!==human.subject)throw Error();
   const issued=await dependencies.issueBroker(proof,signal);signal.throwIfAborted();brokerToken=issued.brokerToken;
   const claims=await dependencies.brokerVerifier.verify(brokerToken);signal.throwIfAborted();
   const bind=(p:Readonly<ProviderAccessClaims>,b:Readonly<DelegatedClaims>)=>{
    const sso=c.channel.providerSso!;
    if(p.sub!==human.subject||p.iss!==sso.issuer||p.aud!==sso.audience||p.scope!==sso.scope||b.sub!==human.subject||b.act?.iss!==c.agent.issuer||b.act?.sub!==c.agent.subject||b.org_id!==c.organisation||b.delegation_id!==proof.grantId||b.execution_mode!=='interactive'||b.aud!==c.channel.brokerAudience||b.scope!==c.channel.scope)throw Error();
   };
   bind(provider,claims);await dependencies.authorise(claims,{accessToken:brokerToken});signal.throwIfAborted();
   let postSucceeded=false;
   adapter=new DirectLineAdapter(c.channel,{
    verifier:dependencies.brokerVerifier,providerVerifier:dependencies.providerVerifier,
    bindProviderIdentity:async(p,b)=>{signal.throwIfAborted();bind(p,b);},
    authorise:async(b,e)=>{if(!closing)signal.throwIfAborted();await dependencies.authorise(b,e);if(!closing)signal.throwIfAborted();},
    secret:async s=>{signal.throwIfAborted();return dependencies.secret(AbortSignal.any([signal,s]));},
    issueSsoToken:async()=>{signal.throwIfAborted();return proof.providerToken;},
    providerSession:{bind:async(b,p,s)=>{signal.throwIfAborted();if(b!==brokerToken||p!==proof.providerToken)throw Error();await dependencies.handoff({brokerToken:b,providerToken:p,agentToken:issued.agentToken,login:proof.login},AbortSignal.any([signal,s]));signal.throwIfAborted();},invalidate:()=>{/* Owned-grant recovery independently invalidates outstanding authority. */}},
    fetch:async(url,init)=>{
     signal.throwIfAborted();const target=new URL(String(url));
     if(target.origin==='https://token.botframework.com'){
      if(target.pathname!=='/api/sas/postToken'||init?.method!=='POST'||JSON.stringify(JSON.parse(String(init.body)))!==JSON.stringify({token:proof.providerToken}))throw Error();
      controls.beforeTokenPost();
     }else if(target.origin!=='https://directline.botframework.com'||!target.pathname.startsWith('/v3/directline/'))throw Error();
     const response=await(dependencies.fetch??fetch)(url,{...init,redirect:'error',signal:AbortSignal.any([signal,...(init?.signal?[init.signal]:[])])});signal.throwIfAborted();
     if(target.origin==='https://token.botframework.com'){postSucceeded=response.status===200;observe({event:'portal_diagnostic',stage:'token_post',status:response.status});}
     return response;
    }
   });
   controls.beforeConversation();const opened=await adapter.open(brokerToken);handle=opened.handle;
   await adapter.send(handle,brokerToken,'/federation-status');
   let authenticated=false;
   for(let n=0;n<25&&!authenticated;n++){
    signal.throwIfAborted();const page=await adapter.poll(handle,brokerToken);authenticated=page.messages.some(m=>m.text===signedIn);
    if(!authenticated)await pause(c.pollIntervalMs,undefined,{signal});
   }
   if(!authenticated||!postSucceeded)throw Error();
   await adapter.send(handle,brokerToken,'verify delegated tool access');
   let started=false,returned=false,verified=false;
   for(let n=0;n<25&&!(started&&returned&&verified);n++){
    signal.throwIfAborted();const page=await adapter.poll(handle,brokerToken),texts=new Set(page.messages.map(m=>m.text));
    if(texts.has('Delegated tool access not verified.')||page.messages.some(m=>m.text.startsWith('An error has occurred.')))throw Error();
    started ||= texts.has('Delegated diagnostic stage: connector started.');returned ||= texts.has('Delegated diagnostic stage: connector returned.');verified ||= texts.has('Delegated tool access verified.');
    if(!(started&&returned&&verified))await pause(c.pollIntervalMs,undefined,{signal});
   }
   if(!started||!returned||!verified||!await dependencies.verifyToolAudit({claims:structuredClone(claims),resource:c.resource,startedAt},signal))throw Error();
   signal.throwIfAborted();await dependencies.authorise(claims,{accessToken:brokerToken});signal.throwIfAborted();observe({event:'portal_diagnostic',stage:'result',outcome:'verified'});return{authorized:true as const};
  })()]);}catch{observe({event:'portal_diagnostic',stage:'result',outcome:'unavailable'});throw new PolicyError('unavailable');}
  finally{clearTimeout(timeout);closing=true;controller.abort();signal.removeEventListener('abort',abort);if(adapter&&handle&&brokerToken)try{await adapter.close(handle,brokerToken);}catch{}}
 };
}
