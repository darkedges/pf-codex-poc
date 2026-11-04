import {importPKCS8,SignJWT} from 'jose';import {randomUUID} from 'node:crypto';
import {PolicyClient} from '../../src/policy/client.ts';import {OidcVerifier} from '../../src/identity/oidc.ts';import {PingFederateExchange,JwksTokenVerifier} from '../../src/adapters/pingfederate.ts';
import {PolicyError} from '../../src/policy/contracts.ts';
import {load,call,nodes} from './common.mjs';import {profile} from './config.mjs';import {capability} from './policy-setup.ts';
import {validatePortalExecutor} from '../vault/portal-executor-profile.mjs';import {portalExecutorTrust} from '../vault/portal-executor-trust.mjs';

// Actual local PF gateway composition. Runtime private keys arrive only from the
// selected Vault record; no password login, private-key files or operator token.
export async function createPortalGateway(material:Record<string,string>,guard:()=>void){
 validatePortalExecutor(material,portalExecutorTrust());
 const key=(field:string)=>importPKCS8(material[field],'RS256');
 const [agentKey,pfAKey,pfBKey,policyAgentKey,policyGatewayKey]=await Promise.all(['agentKeyPem','pfAClientKeyPem','pfBClientKeyPem','policyAgentKeyPem','policyGatewayKeyPem'].map(key));
 const loginVerifier=new OidcVerifier(load('oidc-config.json'));
 const authority=new PolicyClient({origin:'https://localhost:9452',clientId:'policy-agent',keyId:'copilot-policy-agent',key:policyAgentKey,capability,timeoutMs:5000});
 const policy=new PolicyClient({origin:'https://localhost:9452',clientId:'policy-gateway',keyId:'copilot-policy-gateway',key:policyGatewayKey,capability,timeoutMs:5000});
 const config=load('consent-exchange-config.json'),brokerVerifier=new JwksTokenVerifier([config.downstream],capability.scope,5000);
 const exchange=new PingFederateExchange(config,{clientKey:pfBKey,authorise:async(c,e)=>{guard();await policy.authorise(c,e);guard();}});
 return{loginVerifier,brokerVerifier,policy,
  issueBroker:async(proof:{grantId:string;providerToken?:string;login:{idToken:string;nonce:string}},signal:AbortSignal)=>{
   const check=()=>{guard();signal.throwIfAborted();};
   try{
    check();const human=await loginVerifier.verify(proof.login.idToken,proof.login.nonce);check();
    if(human.subject!==profile.human)throw Error();
    const agentToken=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'copilot-agent',typ:'JWT'}).setIssuer(profile.agentIssuer).setSubject(profile.agent).setAudience('api://pf-a/agent-proof').setIssuedAt().setNotBefore('0s').setExpirationTime('120s').setJti(randomUUID()).sign(agentKey);
    const issued=await authority.request('/v1/assertions',{grantId:proof.grantId,mode:'interactive',operation:capability.scope,agentToken,login:proof.login});check();
    if(typeof issued.assertion!=='string'||issued.assertion.length>16000||issued.expiresIn!==60)throw Error();
    const clientAssertion=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'copilot-consent-gateway-1',typ:'client-authentication+jwt'}).setIssuer('consent-gateway-1').setSubject('consent-gateway-1').setAudience(nodes.a.issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(pfAKey);
    const upstream=await call(nodes.a.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:'consent-gateway-1',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:clientAssertion,subject_token:issued.assertion,subject_token_type:'urn:example:token-type:consented-interactive',actor_token:agentToken,actor_token_type:'urn:example:token-type:agent-proof',resource:'urn:copilot:consent:gateway-2',scope:capability.scope,requested_token_type:'urn:ietf:params:oauth:token-type:access_token'}});check();
    if(upstream.status!==200||typeof upstream.value?.access_token!=='string')throw Error();
    const result=await exchange.exchange(upstream.value.access_token);check();
    const claims=await brokerVerifier.verify(result.accessToken);check();
    if(claims.sub!==human.subject||claims.act.sub!==profile.agent||claims.act.iss!==profile.agentIssuer||claims.org_id!==profile.org||claims.delegation_id!==proof.grantId||claims.execution_mode!=='interactive'||claims.scope!==capability.scope)throw Error();
    return{brokerToken:result.accessToken,agentToken};
   }catch{throw new PolicyError('unavailable');}
  }
 };
}
