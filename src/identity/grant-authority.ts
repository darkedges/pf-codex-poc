import { randomUUID } from 'node:crypto';
import { jwtVerify,decodeProtectedHeader,decodeJwt } from 'jose';
import type { AssertionSigner } from './assertion-signer.ts';
import type { PolicyStore } from '../policy/store.ts';
import { PolicyError,type Capability,type VerifiedLogin } from '../policy/contracts.ts';
type Options={store:PolicyStore;capability:Capability;issuer:string;audience:string;signer:AssertionSigner;agentIssuer:string;agentAudience:string;agentKeyId:string;agentKey:CryptoKey;loginVerifier:{verify:(token:string,nonce:string)=>Promise<VerifiedLogin>}};
export type AssertionRequest={grantId:string;mode:'interactive'|'autonomous';agentToken:string;login?:{idToken:string;nonce:string}};
export type AuthenticatedActor={issuer:string;subject:string;operation:string;organisation:string;workload:string};
export class GrantAuthority{
 private options:Options;
 constructor(options:Options){if(typeof options.signer?.sign!=='function'||options.agentKey.type!=='public'||new URL(options.issuer).protocol!=='https:')throw new PolicyError('configuration');this.options={...options,capability:structuredClone(options.capability)};}
 async issue(input:AssertionRequest,binding?:AuthenticatedActor){
  try{
   const c=this.options;if(typeof input.agentToken!=='string'||input.agentToken.length>16000)throw Error();
   const header=decodeProtectedHeader(input.agentToken);if(header.alg!=='RS256'||header.kid!==c.agentKeyId||header.jku||header.jwk||header.x5u||header.x5c)throw Error();
   const {payload:agent}=await jwtVerify(input.agentToken,c.agentKey,{issuer:c.agentIssuer,audience:c.agentAudience,algorithms:['RS256'],clockTolerance:5,maxTokenAge:240,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti']});
   if(agent.aud!==c.agentAudience||typeof agent.sub!=='string'||!agent.sub||!Number.isInteger(agent.iat)||!Number.isInteger(agent.exp)||Number(agent.exp)<=Math.floor(Date.now()/1000)||Number(agent.exp)-Number(agent.iat)>240)throw Error();
   if(binding&&(binding.issuer!==c.agentIssuer||binding.subject!==agent.sub||binding.operation!==c.capability.scope))throw Error();
   const login=input.mode==='interactive'&&input.login?await c.loginVerifier.verify(input.login.idToken,input.login.nonce):undefined;
   const workload=binding?.workload??'consent-authority';
   const context=c.store.authoriseConsentedGrant(input.grantId,{issuer:c.agentIssuer,subject:agent.sub},input.mode,c.capability,workload,login);
   if(binding&&context.org_id!==binding.organisation)throw Error();
   const now=Math.floor(Date.now()/1000);
   const token=await c.signer.sign({...context,actor_sub:context.act.sub,actor_iss:context.act.iss,operation:c.capability.scope,resource:c.capability.resource,iss:c.issuer,aud:c.audience,iat:now,nbf:now,exp:now+60,jti:randomUUID()});
   c.store.authoriseConsentedGrant(input.grantId,{issuer:c.agentIssuer,subject:agent.sub},input.mode,c.capability,workload,login);
   if(Number(decodeJwt(token).exp)<=Math.floor(Date.now()/1000))throw Error();
   return token;
  }catch(error){throw new PolicyError(error instanceof PolicyError&&error.code==='unavailable'?'unavailable':'forbidden');}
 }
}
