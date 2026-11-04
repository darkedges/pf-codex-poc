// Local PF integration only: user access token from the configured OAuth provider.
// No Microsoft URL is requested; the registered callback is captured locally.
import {randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {ProviderAccessVerifier,type ProviderAccessClaims} from '../../src/identity/provider-access.ts';
import type {DelegatedClaims} from '../../src/adapters/token-exchange.ts';
import {copilotProfile as p} from '../pf/copilot-config.mjs';
import {profile} from '../pf/config.mjs';
import {root,read} from '../pf/common.mjs';
import {LocalPublicBrowser,forms} from '../../tests/live-copilot/public-origin.mjs';
import {publicLoginRequest} from './public-login-http.mjs';
export const providerSso=Object.freeze({issuer:p.loginIssuer,audience:p.loginAudience,scope:'copilot.login',maxLifetimeSeconds:p.loginLifetimeSeconds});
export function providerVerifier(transport:typeof fetch=fetch){return new ProviderAccessVerifier({...providerSso,jwksUri:p.loginIssuer+'/pf/JWKS',keyIds:['copilot-login-signing']},5000,transport);}
export function bindLabProviderIdentity(provider:Readonly<ProviderAccessClaims>,broker:Readonly<DelegatedClaims>){
 // Explicit lab registry binding, never identity or organisation from a prompt/header.
 if(provider.iss!==p.loginIssuer||provider.aud!==p.loginAudience||provider.scope!=='copilot.login'||provider.sub!==profile.human||broker.sub!==profile.human||broker.org_id!==profile.org||broker.act?.iss!==profile.agentIssuer||broker.act?.sub!==profile.agent||broker.execution_mode!=='interactive')throw Error('Provider identity binding denied');
}
export async function obtainProviderLogin(transport=publicLoginRequest,verifier=providerVerifier(),signal=AbortSignal.timeout(30000)){
 try{
  signal.throwIfAborted();const state=randomBytes(24).toString('hex'),browser=new LocalPublicBrowser(transport);
  const url=p.loginIssuer+'/as/authorization.oauth2?'+new URLSearchParams({client_id:p.loginClientId,response_type:'code',scope:'copilot.login',redirect_uri:p.callback,state,pfidpadapterid:'consentHTMLForm',resource:'urn:copilot:login'});
  const login=await browser.request(url);signal.throwIfAborted();
  const approval=await browser.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});signal.throwIfAborted();
  const callback=await browser.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});signal.throwIfAborted();
  if(!callback.callback||callback.callback.origin+callback.callback.pathname!==p.callback||callback.callback.searchParams.get('state')!==state)throw Error();
  const code=callback.callback.searchParams.get('code');if(!code)throw Error();
  const secret=readFileSync(resolve(root,'.local/copilot/pf-generic-oauth-client-secret.txt'),'utf8').trim();
  const response=await transport(p.loginIssuer+'/as/token.oauth2',{client_id:p.loginClientId,client_secret:secret,grant_type:'authorization_code',redirect_uri:p.callback,code});signal.throwIfAborted();
  if(response.status!==200||response.value?.token_type!=='Bearer'||typeof response.value.access_token!=='string')throw Error();
  const token=response.value.access_token,claims=await verifier.verify(token);signal.throwIfAborted();if(claims.sub!==profile.human)throw Error();return{token,claims};
 }catch{throw Error('Configured provider login unavailable');}
}
