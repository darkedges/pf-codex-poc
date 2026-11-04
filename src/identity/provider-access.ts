import {createRemoteJWKSet,customFetch,jwtVerify} from 'jose';
import {CopilotError} from '../adapters/copilot.ts';
export type ProviderAccessClaims={iss:string;aud:string;sub:string;scope:string;iat:number;nbf:number;exp:number;jti:string};
export type ProviderAccessTrust={issuer:string;jwksUri:string;audience:string;scope:string;keyIds:string[];maxLifetimeSeconds:number};
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=2048&&!/[\u0000-\u0020\u007f]/.test(v);
export class ProviderAccessVerifier{
 private trust:ProviderAccessTrust;private keys:ReturnType<typeof createRemoteJWKSet>;
 constructor(trust:ProviderAccessTrust,timeoutMs:number,transport:typeof fetch=fetch){
  try{
   for(const value of [trust.issuer,trust.jwksUri]){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error();}
   if(!text(trust.audience)||!text(trust.scope)||!Array.isArray(trust.keyIds)||!trust.keyIds.length||!trust.keyIds.every(text)||!Number.isInteger(trust.maxLifetimeSeconds)||trust.maxLifetimeSeconds<1||trust.maxLifetimeSeconds>3600||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>10000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
   this.trust=structuredClone(trust);
   this.keys=createRemoteJWKSet(new URL(trust.jwksUri),{timeoutDuration:timeoutMs,cacheMaxAge:60000,cooldownDuration:5000,[customFetch]:async(url,init)=>{
    if(String(url)!==this.trust.jwksUri)throw Error();const response=await transport(url,{...init,redirect:'error'});let size=0;const chunks=[];
    for await(const chunk of response.body??[]){size+=chunk.length;if(size>262144)throw Error();chunks.push(chunk);}return new Response(Buffer.concat(chunks),{status:response.status,headers:response.headers});
   }});
  }catch{throw new CopilotError('configuration');}
 }
 async verify(raw:string):Promise<ProviderAccessClaims>{
  try{
   if(typeof raw!=='string'||raw.length>16000)throw Error();const t=this.trust;
   const {payload:p}=await jwtVerify(raw,async(h,jwt)=>{if(h.alg!=='RS256'||!t.keyIds.includes(String(h.kid))||h.jku||h.jwk||h.x5u||h.x5c)throw Error();return this.keys(h,jwt);},{issuer:t.issuer,audience:t.audience,algorithms:['RS256'],clockTolerance:5,maxTokenAge:t.maxLifetimeSeconds,requiredClaims:['iss','aud','sub','scope','iat','nbf','exp','jti']});
   const now=Math.floor(Date.now()/1000);
   if(p.aud!==t.audience||p.scope!==t.scope||!text(p.sub)||!text(p.jti)||![p.iat,p.nbf,p.exp].every(Number.isInteger)||Number(p.exp)<=now||Number(p.exp)<=Number(p.iat)||Number(p.exp)-Number(p.iat)>t.maxLifetimeSeconds||Number(p.iat)>now+5||Number(p.nbf)>Number(p.exp)||['act','delegation_id','execution_mode','org_id'].some(k=>p[k]!==undefined))throw Error();
   return{iss:t.issuer,aud:t.audience,sub:p.sub,scope:t.scope,iat:Number(p.iat),nbf:Number(p.nbf),exp:Number(p.exp),jti:p.jti};
  }catch{throw new CopilotError('invalid_token');}
 }
}
