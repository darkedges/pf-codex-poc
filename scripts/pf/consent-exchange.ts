import { importPKCS8,SignJWT } from 'jose';
import { randomUUID } from 'node:crypto';
import { PolicyClient } from '../../src/policy/client.ts';
import { PingFederateExchange } from '../../src/adapters/pingfederate.ts';
import { capability } from './policy-setup.ts';
import { profile } from './config.mjs';
import { call,load,read,nodes } from './common.mjs';
const key=(name:string)=>importPKCS8(read(`${name}.private.pem`),'RS256');
// Internal lab orchestration only; token results must never be returned to the
// browser or model. Each consumer independently verifies proof and online PDP.
export async function issueConsentedUpstream(grantId:string,mode:string,login?:{idToken:string;nonce:string},origin=process.env.POLICY_API_ORIGIN){
 if(!origin)throw Error('Authenticated policy origin required');
  const agentToken=await new SignJWT({sub:profile.agent}).setProtectedHeader({alg:'RS256',kid:'copilot-agent',typ:'JWT'}).setIssuer(profile.agentIssuer).setAudience('api://pf-a/agent-proof').setIssuedAt().setNotBefore('0s').setExpirationTime('120s').setJti(randomUUID()).sign(await key('agent'));
  const authorityClient=new PolicyClient({origin,clientId:'policy-agent',keyId:load('policy-agent.jwks.json').keys[0].kid,key:await key('policy-agent'),capability,timeoutMs:5000});
  const issued=await authorityClient.request('/v1/assertions',{grantId,mode,operation:capability.scope,agentToken,...(mode==='interactive'&&login?{login}: {})});
  if(typeof issued.assertion!=='string'||issued.assertion.length>16000||issued.expiresIn!==60)throw Error('Invalid authority response');
  const subject=issued.assertion;
  const assertion=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'copilot-consent-gateway-1',typ:'client-authentication+jwt'}).setIssuer('consent-gateway-1').setSubject('consent-gateway-1').setAudience(nodes.a.issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(await key('consent-gateway-1'));
  const result=await call(nodes.a.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:'consent-gateway-1',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,subject_token:subject,subject_token_type:mode==='interactive'?'urn:example:token-type:consented-interactive':'urn:example:token-type:consented-autonomous',actor_token:agentToken,actor_token_type:'urn:example:token-type:agent-proof',resource:'urn:copilot:consent:gateway-2',scope:profile.scope,requested_token_type:'urn:ietf:params:oauth:token-type:access_token'}});
  if(result.status!==200||typeof result.value?.access_token!=='string')throw Error('Consented PF A exchange rejected');
  return result.value.access_token as string;
}
export async function runConsentedExchange(grantId:string,mode:string,login?:{idToken:string;nonce:string},origin=process.env.POLICY_API_ORIGIN){
  if(!origin)throw Error('Authenticated policy origin required');
  const upstream=await issueConsentedUpstream(grantId,mode,login,origin);
  const policy=new PolicyClient({origin,clientId:'policy-gateway',keyId:'copilot-policy-gateway',key:await key('policy-gateway'),capability,timeoutMs:5000});
  const exchange=new PingFederateExchange(load('consent-exchange-config.json'),{clientKey:await key('consent-gateway-2'),authorise:policy.authorise});
  const output=await exchange.exchange(upstream);
  return{subject:output.claims.sub,actor:output.claims.act.sub,mode:output.claims.execution_mode};
}
