import {createHash} from 'node:crypto';
import {CopilotError} from '../adapters/copilot.ts';
import {ProviderAccessVerifier,type ProviderAccessTrust,type ProviderAccessClaims} from './provider-access.ts';

export type ProviderBrowserConfig=ProviderAccessTrust&{
 authorizationEndpoint:string;tokenEndpoint:string;redirectUri:string;clientId:string;clientSecret:string;
 adapterId:string;resource:string;timeoutMs:number;fetch?:typeof fetch;
};
const transaction=(v:string)=>typeof v==='string'&&/^[A-Za-z0-9_-]{43,128}$/.test(v);
const text=(v:unknown,max=2048):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\u0000-\u0020\u007f]/.test(v);
function secure(value:string){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error();return u;}

// Server-side component only. Its caller owns one-use state/cookie checks and supplies
// the human subject from independently verified OIDC evidence, never a form field.
export class ProviderBrowserClient{
 private config:ProviderBrowserConfig;
 private verifier:ProviderAccessVerifier;
 constructor(config:ProviderBrowserConfig){
  try{
   const issuer=secure(config.issuer);
   for(const endpoint of [config.jwksUri,config.authorizationEndpoint,config.tokenEndpoint])if(secure(endpoint).origin!==issuer.origin)throw Error();
   if(secure(config.redirectUri).pathname!=='/provider-callback'||!text(config.clientId)||!text(config.clientSecret,4096)||!text(config.adapterId)||!text(config.resource)||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>10000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
   this.config={...config,keyIds:[...config.keyIds]};
   const {issuer:trustedIssuer,jwksUri,audience,scope,keyIds,maxLifetimeSeconds}=this.config;
   this.verifier=new ProviderAccessVerifier({issuer:trustedIssuer,jwksUri,audience,scope,keyIds,maxLifetimeSeconds},config.timeoutMs,config.fetch);
  }catch{throw new CopilotError('configuration');}
 }
 start(state:string,verifier:string):string{
  if(!transaction(state)||!transaction(verifier))throw new CopilotError('invalid_request');
  const c=this.config,url=new URL(c.authorizationEndpoint);
  url.search=new URLSearchParams({client_id:c.clientId,response_type:'code',redirect_uri:c.redirectUri,scope:c.scope,state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',pfidpadapterid:c.adapterId,resource:c.resource}).toString();
  return url.href;
 }
 async redeem(code:string,verifier:string,verifiedHumanSubject:string):Promise<{token:string;claims:ProviderAccessClaims}>{
  if(!text(code,4096)||!transaction(verifier)||!text(verifiedHumanSubject))throw new CopilotError('invalid_request');
  let token:string;
  try{
   const c=this.config,response=await(c.fetch??fetch)(c.tokenEndpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(c.timeoutMs),headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({client_id:c.clientId,client_secret:c.clientSecret,grant_type:'authorization_code',redirect_uri:c.redirectUri,code,code_verifier:verifier})});
   if(!response.ok||response.redirected||!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')??'')){await response.body?.cancel();throw Error();}
   const reader=response.body?.getReader();if(!reader)throw Error();
   let size=0;const chunks:Uint8Array[]=[];
   try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>40000)throw Error();chunks.push(value);}}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
   const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));
   if(!result||result.token_type!=='Bearer'||!text(result.access_token,16000))throw Error();token=result.access_token;
  }catch{throw new CopilotError('unavailable');}
  const claims=await this.verifier.verify(token);
  if(claims.sub!==verifiedHumanSubject)throw new CopilotError('invalid_token');
  return{token,claims};
 }
}
