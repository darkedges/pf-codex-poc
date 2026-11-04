import {isDeepStrictEqual} from 'node:util';
import {DirectLineAdapter} from '../adapters/direct-line.ts';
import type {DirectLineConfig,DirectLineDependencies} from '../adapters/copilot.ts';
import {OidcClient} from '../identity/oidc.ts';
import {ProviderAccessVerifier} from '../identity/provider-access.ts';
import {EntraCertificateTokenSource} from '../m365/entra-certificate.ts';
import {MobileDeviceAuthority} from './device-authority.ts';
import {MobileResourceConsent} from './resource-consent.ts';
import {MobileProviderSessions} from './provider-sessions.ts';
import {MobileProviderEnrollment} from './provider-enrollment.ts';
import {MobileFederationRuntime} from './federation-runtime.ts';
import {ApprovedSiteDocuments} from './site-documents.ts';
import {MobileLoginHandoff} from './login-handoff.ts';
import {MobileChatExecutor} from './chat-executor.ts';
import {MobileChatJobs} from './chat-jobs.ts';
import {MobileHttpApi} from './http-api.ts';
import {MobileUsage} from './usage.ts';

type Config={origin:string;authorizationEndpoint:string;directLine:DirectLineConfig;site:ConstructorParameters<typeof ApprovedSiteDocuments>[0]};
type Dependencies={mobile:MobileDeviceAuthority;resources:MobileResourceConsent;provider:MobileProviderSessions;oidc:OidcClient;chat:MobileFederationRuntime;documents:MobileFederationRuntime;graph:EntraCertificateTokenSource;usage:MobileUsage;secret:(signal:AbortSignal)=>Promise<string>;fetch:typeof fetch;observe?:ConstructorParameters<typeof MobileHttpApi>[0]['observe'];observeCopilot?:DirectLineDependencies['observe']};
/** Protected composition only. All credentials are supplied by the hosting
 * workload after approved Vault retrieval; no listener or IAM changes occur.
 * Concrete real adapters are mandatory. No simulation/development fallback. */
export function createMobileApplication(c:Config,d:Dependencies){
 if(!(d.mobile instanceof MobileDeviceAuthority)||!(d.resources instanceof MobileResourceConsent)||!(d.provider instanceof MobileProviderSessions)||!(d.oidc instanceof OidcClient)||!(d.chat instanceof MobileFederationRuntime)||!(d.documents instanceof MobileFederationRuntime)||!(d.graph instanceof EntraCertificateTokenSource)||!(d.usage instanceof MobileUsage)||typeof d.secret!=='function'||typeof d.fetch!=='function'||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.SSLKEYLOGFILE)throw Error('mobile_application_configuration');
 const chat=d.chat.profile,documents=d.documents.profile,provider=d.provider.profile,oidc=d.oidc.profile;
 if(chat.scope!=='copilot.invoke'||documents.scope!=='m365.document.read'||chat.resource!==documents.resource||c.directLine.brokerAudience!==chat.b.trust.audience||c.site.audience!==documents.b.trust.audience||c.directLine.ssoAudience!==provider.trust.audience||!isDeepStrictEqual(c.directLine.providerSso,{issuer:provider.trust.issuer,audience:provider.trust.audience,scope:provider.trust.scope,maxLifetimeSeconds:provider.trust.maxLifetimeSeconds})||oidc.clientId!==provider.clientId||oidc.issuer!==provider.trust.issuer||oidc.redirectUri!==c.origin+'/mobile/callback'||!isDeepStrictEqual(oidc.providerAuthorization,{scope:'copilot.login',resource:'urn:copilot:login'}))throw Error('mobile_application_configuration');
 const enrollment=new MobileProviderEnrollment(d.oidc,d.mobile,d.provider),handoff=new MobileLoginHandoff({origin:c.origin,authorizationEndpoint:c.authorizationEndpoint,authority:enrollment.authority,oidc:enrollment.oidc});
 const providerVerifier=new ProviderAccessVerifier(provider.trust,5000,d.fetch);
 const executor=new MobileChatExecutor({capacity:4,foregroundMs:900000,pollIntervalMs:500},{revalidate:v=>d.mobile.revalidateEvidence(v),
  readDocuments:async(evidence,question,signal)=>{const issued=await d.documents.issue(evidence,signal),reader=new ApprovedSiteDocuments(c.site,{verify:token=>d.documents.authorise(token,signal),authorise:async(_claims,proof)=>{await d.documents.authorise(proof.accessToken,signal);},tokenSource:d.graph,fetch:d.fetch});return reader.read(question,issued.accessToken,signal);},
  issueChat:(evidence,signal)=>d.chat.issue(evidence,signal),authoriseChat:(token,signal)=>d.chat.authorise(token,signal),
  createAdapter:current=>{const adapter=new DirectLineAdapter(c.directLine,{observe:d.observeCopilot,verifier:{verify:token=>d.chat.authorise(token,current().signal)},providerVerifier,
   bindProviderIdentity:async(p,b,proof)=>{const active=current(),full=await d.chat.authorise(proof.brokerToken,AbortSignal.any([active.signal,proof.signal]));if(p.iss!==full.original_login_issuer||p.sub!==full.sub||b.sub!==full.sub||b.act.iss!==full.act.iss||b.act.sub!==full.act.sub||b.org_id!==full.org_id||b.delegation_id!==full.delegation_id)throw Error('mobile_provider_binding_denied');},
   authorise:async(_claims,proof)=>{await d.chat.authorise(proof.accessToken,current().signal);},secret:signal=>d.secret(AbortSignal.any([signal,current().signal])),issueSsoToken:request=>d.provider.get(current().evidence,AbortSignal.any([request.signal,current().signal])),
   fetch:(url,init)=>d.fetch(url,{...init,signal:AbortSignal.any([current().signal,...(init?.signal?[init.signal]:[])])})});return{adapter,dispose:()=>adapter.shutdown()};}
 });
 const jobs=new MobileChatJobs({timeoutMs:55000,capacity:4,revalidate:e=>d.mobile.revalidateEvidence(e),authorise:e=>d.resources.authoriseChat(e),execute:input=>{d.usage.reserve('question');return executor.execute(input);}});
 const consent={terms:()=>d.resources.terms(),approve:d.resources.approve.bind(d.resources),status:d.resources.status.bind(d.resources),authoriseChat:d.resources.authoriseChat.bind(d.resources),revoke:async(evidence:unknown,body:string)=>{const result=await d.resources.revoke(evidence,body);await d.provider.retire(evidence);return result;}};
 const api=new MobileHttpApi({origin:c.origin,authority:enrollment.authority,handoff,resourceConsent:consent,jobs,observe:d.observe});
 return{api,close(){jobs.close();executor.close();handoff.close();enrollment.close();d.provider.close();d.chat.close();d.documents.close();}};
}
