// Explicit local-container composition. Reads workload/client keys, never the
// external agent's signing key. Not a persistent deployment credential loader.
import {importPKCS8,createLocalJWKSet,jwtVerify} from 'jose';
import {readFileSync} from 'node:fs';import {resolve} from 'node:path';
import {RetainedProofExchange} from '../../src/copilot/relay-exchange.ts';
import {JwksTokenVerifier,PingFederateExchange} from '../../src/adapters/pingfederate.ts';
import {PolicyClient} from '../../src/policy/client.ts';
import {load,read,root,nodes} from './common.mjs';import {profile} from './config.mjs';import {capability} from './policy-setup.ts';import {authorityTrust} from './authority-config.mjs';import {toolExchangeConfig,toolTrust} from './copilot-tool-profile.mjs';

export async function createLocalProfileRetainedExchange(origin:string,material:{policyAgentKeyPem:string;policyGatewayKeyPem:string;pfAClientKeyPem:string;pfBClientKeyPem:string},observe?:ConstructorParameters<typeof RetainedProofExchange>[1]['observe']){
 if(origin!=='https://localhost:9452')throw Error('Explicit persistent local policy required');
 const authorityClient=new PolicyClient({origin,clientId:'policy-agent',keyId:load('policy-agent.jwks.json').keys[0].kid,key:await importPKCS8(material.policyAgentKeyPem,'RS256'),capability,timeoutMs:5000});
 const policy=new PolicyClient({origin,clientId:'policy-gateway',keyId:'copilot-policy-gateway',key:await importPKCS8(material.policyGatewayKeyPem,'RS256'),capability,timeoutMs:5000});
 const config=toolExchangeConfig(),tool=new PingFederateExchange(config,{clientKey:await importPKCS8(material.pfBClientKeyPem,'RS256'),authorise:policy.authorise});
 const jwks=authorityTrust({AUTHORITY_SIGNER:'vault-transit'}),uri=profile.consentAuthorityIssuer+'/jwks';
 const assertionVerifier=new JwksTokenVerifier([{issuer:profile.consentAuthorityIssuer,jwksUri:uri,audience:'api://pf-a/consent-proof',algorithms:['RS256'],keyIds:jwks.keys.map((k:any)=>k.kid),organisations:[profile.org],actorIssuers:[profile.agentIssuer],maxLifetimeSeconds:60}],capability.scope,5000,async(url:any)=>{if(String(url)!==uri)throw Error('Unapproved local authority trust');return Response.json(jwks);});
 const agentKeys=createLocalJWKSet(load('agent.jwks.json'));
 const agentVerifier={async verify(token:string){const result=await jwtVerify(token,async(h,j)=>{if(h.alg!=='RS256'||h.kid!=='copilot-agent'||h.jku||h.jwk||h.x5u||h.x5c)throw Error('Invalid agent proof');return agentKeys(h,j);},{issuer:profile.agentIssuer,audience:'api://pf-a/agent-proof',algorithms:['RS256'],clockTolerance:0,maxTokenAge:240,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti']});const p=result.payload;if(p.aud!=='api://pf-a/agent-proof'||p.sub!==profile.agent||![p.iat,p.nbf,p.exp].every(Number.isInteger)||Number(p.exp)-Number(p.iat)>240)throw Error('Invalid agent proof');return{iss:p.iss!,sub:p.sub!,aud:p.aud,exp:Number(p.exp)};}};
 const exchange=new RetainedProofExchange({brokerAudience:load('consent-exchange-config.json').downstream.audience,authorityIssuer:profile.consentAuthorityIssuer,authorityAudience:'api://pf-a/consent-proof',upstreamIssuer:nodes.a.issuer,upstreamAudience:'api://gateway-2',toolIssuer:toolTrust().issuer,toolAudience:toolTrust().audience,scope:capability.scope,resource:capability.resource,tokenEndpoint:nodes.a.issuer+'/as/token.oauth2',requestedResource:'urn:copilot:consent:gateway-2',clientId:'consent-gateway-1',clientKeyId:'copilot-consent-gateway-1',clientAssertionAudience:nodes.a.issuer,timeoutMs:10000},{observe,clientKey:await importPKCS8(material.pfAClientKeyPem,'RS256'),requestAssertion:async(input,signal)=>{signal.throwIfAborted();const value=await authorityClient.request('/v1/assertions',input);signal.throwIfAborted();return value;},assertionVerifier,upstreamVerifier:new JwksTokenVerifier(config.upstream,capability.scope,5000),exchangeTool:token=>tool.exchange(token)});
 return{exchange,agentVerifier,policy};
}

// Legacy bounded operator harness: explicit file credentials, never called by the managed service.
export async function localRetainedProofExchange(origin:string,observe?:ConstructorParameters<typeof RetainedProofExchange>[1]['observe']){
 return createLocalProfileRetainedExchange(origin,{policyAgentKeyPem:read('policy-agent.private.pem'),policyGatewayKeyPem:read('policy-gateway.private.pem'),pfAClientKeyPem:read('consent-gateway-1.private.pem'),pfBClientKeyPem:readFileSync(resolve(root,'.local/copilot/pf-sso-exchange.private.pem'),'utf8')},observe);
}
