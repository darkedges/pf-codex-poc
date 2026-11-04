// Explicit local PF composition; never a mock fallback or a production listener.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {importPKCS8} from 'jose';
import {PingFederateExchange,JwksTokenVerifier} from '../../src/adapters/pingfederate.ts';
import {PolicyClient} from '../../src/policy/client.ts';
import {PolicyProtectedTool} from '../../src/copilot/tool-authority.ts';
import type {DelegatedClaims} from '../../src/adapters/token-exchange.ts';
import {toolExchangeConfig,toolTrust} from './copilot-tool-profile.mjs';
import {capability} from './policy-setup.ts';
import {read,root} from './common.mjs';
import {issueConsentedUpstream} from './consent-exchange.ts';
export async function localToolAuthority(origin:string,role:'tool'|'gateway'='tool'){
 if(!['tool','gateway'].includes(role))throw Error('Local decision role required');
 const policy=new PolicyClient({origin,clientId:'policy-'+role,keyId:'copilot-policy-'+role,key:await importPKCS8(read('policy-'+role+'.private.pem'),'RS256'),capability,timeoutMs:5000});
 const exchange=new PingFederateExchange(toolExchangeConfig(),{clientKey:await importPKCS8(readFileSync(resolve(root,'.local/copilot/pf-sso-exchange.private.pem'),'utf8'),'RS256'),authorise:policy.authorise});
 return{
  exchange,
  async issue(grantId:string,mode:string,login?:{idToken:string;nonce:string}){return exchange.exchange(await issueConsentedUpstream(grantId,mode,login,origin));},
  tool<T>(operation:(claims:Readonly<DelegatedClaims>,signal:AbortSignal)=>Promise<T>){return new PolicyProtectedTool({verifier:new JwksTokenVerifier([toolTrust()],capability.scope,5000),authorise:policy.authorise,operation,timeoutMs:10000});},
 };
}
