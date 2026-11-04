import { createHash,randomUUID } from 'node:crypto';
import { createRemoteJWKSet,customFetch,jwtVerify,SignJWT } from 'jose';
import { PolicyError,type VerifiedLogin } from '../policy/contracts.ts';
import { bodyHash } from '../policy/protocol.ts';
export type OidcObservation={stage:'input'|'key'|'jwt'|'binding'|'access_token_hash';outcome:'verified'|'rejected';code?:string;claim?:string};
export type OidcTrust={issuer:string;additionalIssuers?:string[];jwksUri:string;clientId:string;keyIds:string[];timeoutMs?:number;fetch?:typeof fetch;observe?:(event:OidcObservation)=>void};
export type OidcConfig=OidcTrust&{sessionReuse?:'after-first-login';callbackPath?:'/callback'|'/mobile/callback';providerAuthorization?:{scope:'copilot.login';resource:'urn:copilot:login'};authorizationEndpoint:string;browserAuthorizationEndpoint?:string;parEndpoint:string;tokenEndpoint:string;redirectUri:string;keyId:string;clientKey:CryptoKey;adapterId:string};
function secure(value:string){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search)throw new PolicyError('configuration');return u;}
export class OidcVerifier{
 private config:OidcTrust;
 private jwks:ReturnType<typeof createRemoteJWKSet>;
 constructor(config:OidcTrust){
  const issuer=secure(config.issuer),jwks=secure(config.jwksUri);
  if(config.additionalIssuers!==undefined&&(!Array.isArray(config.additionalIssuers)||config.additionalIssuers.length>4||new Set([config.issuer,...config.additionalIssuers]).size!==config.additionalIssuers.length+1))throw new PolicyError('configuration');
  for(const additional of config.additionalIssuers??[])secure(additional);
  if(jwks.origin!==issuer.origin||!config.clientId||!config.keyIds.length||config.keyIds.some(k=>typeof k!=='string'||!k)||!Number.isInteger(config.timeoutMs??5000)||(config.timeoutMs??5000)<100||(config.timeoutMs??5000)>30000)throw new PolicyError('configuration');
  this.config={...config,keyIds:[...config.keyIds],additionalIssuers:[...(config.additionalIssuers??[])]};
  this.jwks=createRemoteJWKSet(jwks,{timeoutDuration:config.timeoutMs??5000,cacheMaxAge:60000,cooldownDuration:5000,[customFetch]:async(url,init)=>{
   if(String(url)!==config.jwksUri)throw new PolicyError('login_failed');return(config.fetch??fetch)(url,{...init,redirect:'error'});
  }});
 }
 async verify(token:string,nonce:string,accessToken?:string):Promise<VerifiedLogin>{
  let stage:OidcObservation['stage']='input';
  const report=(event:OidcObservation)=>{try{this.config.observe?.(event);}catch{}};
  try{
   if(typeof token!=='string'||token.length>16000||typeof nonce!=='string'||nonce.length<16||nonce.length>256)throw Error();
   const c=this.config,{payload:p}=await jwtVerify(token,async(header,jwt)=>{
    stage='key';if(header.alg!=='RS256'||typeof header.kid!=='string'||!c.keyIds.includes(header.kid)||header.jku||header.jwk||header.x5u||header.x5c)throw Error();stage='jwt';return this.jwks(header,jwt);
   },{issuer:[c.issuer,...(c.additionalIssuers??[])],audience:c.clientId,algorithms:['RS256'],clockTolerance:5,maxTokenAge:300,requiredClaims:['iss','sub','aud','iat','exp','nonce','auth_time']});
   stage='binding';
   const now=Math.floor(Date.now()/1000);
   if(p.aud!==c.clientId||typeof p.sub!=='string'||!p.sub||p.sub.length>2048||p.nonce!==nonce||(p.azp!==undefined&&p.azp!==c.clientId)||!Number.isInteger(p.iat)||!Number.isInteger(p.exp)||!Number.isInteger(p.auth_time)||Number(p.exp)<=now||Number(p.exp)-Number(p.iat)>600||Number(p.iat)>now+5||Number(p.auth_time)>now+5||Number(p.auth_time)<now-300)throw Error();
   stage='access_token_hash';if(accessToken!==undefined&&p.at_hash!==undefined){const hash=createHash('sha256').update(accessToken).digest().subarray(0,16).toString('base64url');if(p.at_hash!==hash)throw Error();}
   report({stage,outcome:'verified'});
   return{issuer:p.iss!,subject:p.sub,audience:c.clientId,issuedAt:Number(p.iat)*1000,authTime:Number(p.auth_time)*1000,expiresAt:Number(p.exp)*1000,tokenHash:bodyHash(token),nonceHash:bodyHash(nonce)};
  }catch(error){const e=error as {code?:unknown;claim?:unknown};const codes=['ERR_JWT_CLAIM_VALIDATION_FAILED','ERR_JWT_EXPIRED','ERR_JWS_SIGNATURE_VERIFICATION_FAILED','ERR_JWKS_NO_MATCHING_KEY','ERR_JWKS_TIMEOUT','ERR_JWT_INVALID','ERR_JWS_INVALID','ERR_JOSE_ALG_NOT_ALLOWED'];const claims=['iss','sub','aud','iat','exp','nbf','nonce','auth_time','azp','at_hash'];report({stage,outcome:'rejected',...(typeof e?.code==='string'&&codes.includes(e.code)?{code:e.code}:{}),...(typeof e?.claim==='string'&&claims.includes(e.claim)?{claim:e.claim}:{})});throw new PolicyError('login_failed');}
 }
}
export class OidcClient{
 private config:OidcConfig;
 private verifier:OidcVerifier;
 private recentLoginVerified=false;
 get profile(){const c=this.config;return{issuer:c.issuer,clientId:c.clientId,redirectUri:c.redirectUri,providerAuthorization:c.providerAuthorization?{...c.providerAuthorization}:undefined};}
 constructor(config:OidcConfig){
  if(config.sessionReuse!==undefined&&config.sessionReuse!=='after-first-login')throw new PolicyError('configuration');
  if(config.callbackPath!==undefined&&!['/callback','/mobile/callback'].includes(config.callbackPath))throw new PolicyError('configuration');
  if(config.providerAuthorization&&(config.callbackPath!=='/mobile/callback'||Object.keys(config.providerAuthorization).sort().join()!=='resource,scope'||config.providerAuthorization.scope!=='copilot.login'||config.providerAuthorization.resource!=='urn:copilot:login'))throw new PolicyError('configuration');
  const issuer=secure(config.issuer);
  for(const endpoint of [config.authorizationEndpoint,config.parEndpoint,config.tokenEndpoint])if(secure(endpoint).origin!==issuer.origin)throw new PolicyError('configuration');
  // A deployment-pinned reverse proxy changes only the browser destination, never token trust.
  if(config.browserAuthorizationEndpoint!==undefined&&secure(config.browserAuthorizationEndpoint).pathname!==secure(config.authorizationEndpoint).pathname)throw new PolicyError('configuration');
  const redirect=secure(config.redirectUri);if(redirect.pathname!==(config.callbackPath??'/callback')||!config.keyId||config.clientKey.type!=='private'||!config.adapterId||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new PolicyError('configuration');
  this.config={...config,...(config.providerAuthorization?{providerAuthorization:{...config.providerAuthorization}}:{})};this.verifier=new OidcVerifier(config);
 }
 private async post(endpoint:string,fields:Record<string,string>){
  try{
   const c=this.config,assertion=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:c.keyId,typ:'client-authentication+jwt'}).setIssuer(c.clientId).setSubject(c.clientId).setAudience(c.issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(c.clientKey);
   const response=await(c.fetch??fetch)(endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(c.timeoutMs??5000),headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({...fields,client_id:c.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion})});
   if(!response.ok)throw Error();let raw='';for await(const part of response.body??[]){raw+=Buffer.from(part).toString('utf8');if(raw.length>40000)throw Error();}
   const result=JSON.parse(raw);if(!result||typeof result!=='object'||Array.isArray(result))throw Error();return result;
  }catch{throw new PolicyError('login_failed');}
 }
 async start(state:string,nonce:string,verifier:string){
  if(![state,nonce,verifier].every(v=>/^[A-Za-z0-9_-]{32,128}$/.test(v)))throw new PolicyError('login_failed');
  const c=this.config,reuse=c.sessionReuse==='after-first-login'&&this.recentLoginVerified,result=await this.post(c.parEndpoint,{response_type:'code',scope:c.providerAuthorization?'openid copilot.login offline_access':'openid',...(c.providerAuthorization?{resource:c.providerAuthorization.resource}:{}),redirect_uri:c.redirectUri,state,nonce,code_challenge:bodyHash(verifier),code_challenge_method:'S256',pfidpadapterid:c.adapterId,...(reuse?{max_age:'300'}:{prompt:'login',max_age:'0'})});
  if(typeof result.request_uri!=='string'||!result.request_uri.startsWith('urn:')||result.request_uri.length>1024||!Number.isInteger(result.expires_in)||result.expires_in<1||result.expires_in>120)throw new PolicyError('login_failed');
  const redirect=new URL(c.browserAuthorizationEndpoint??c.authorizationEndpoint);redirect.search=new URLSearchParams({client_id:c.clientId,request_uri:result.request_uri}).toString();return redirect.href;
 }
 async redeem(code:string,verifier:string,nonce:string){
  if(typeof code!=='string'||!code||code.length>4096)throw new PolicyError('login_failed');
  const c=this.config,result=await this.post(c.tokenEndpoint,{grant_type:'authorization_code',code,redirect_uri:c.redirectUri,code_verifier:verifier});
  if(typeof result.id_token!=='string'||typeof result.access_token!=='string'||result.access_token.length>16000||result.token_type!=='Bearer')throw new PolicyError('login_failed');
  if(c.providerAuthorization&&(typeof result.refresh_token!=='string'||!result.refresh_token||result.refresh_token.length>4096||/[\s\u0000-\u001f\u007f]/.test(result.refresh_token)))throw new PolicyError('login_failed');
  const login=await this.verifier.verify(result.id_token,nonce,result.access_token);this.recentLoginVerified=true;return{login,idToken:result.id_token,...(c.providerAuthorization?{providerCredential:{accessToken:result.access_token,refreshToken:result.refresh_token as string}}:{})};
 }
}
