import { compactVerify,SignJWT,type JWTPayload } from 'jose';
import { PolicyError } from '../policy/contracts.ts';

export interface AssertionSigner { sign(payload:JWTPayload):Promise<string> }
// Explicit lab backend. Production composition must choose protected remote custody.
export class DevelopmentSigner implements AssertionSigner {
 private key:CryptoKey;private kid:string;
 constructor(key:CryptoKey,kid:string){if(key.type!=='private'||!kid)throw new PolicyError('configuration');this.key=key;this.kid=kid;}
 sign(payload:JWTPayload){return new SignJWT(payload).setProtectedHeader({alg:'RS256',kid:this.kid,typ:'JWT'}).sign(this.key);}
}
type TransitConfig={origin:string;mount:string;name:string;version:number;kid:string;publicKey:CryptoKey;token:()=>string;timeoutMs:number;fetch?:typeof fetch};
// Vault API: transit/sign/:name/sha2-256, explicitly PKCS#1 v1.5 for RS256.
// No private key export, automatic version selection, redirects, retries or fallback.
export class VaultTransitSigner implements AssertionSigner {
 private config:TransitConfig;
 constructor(config:TransitConfig){
  const u=new URL(config.origin);
  if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash||!/^\w[\w-]{0,63}$/.test(config.mount)||!/^\w[\w-]{0,100}$/.test(config.name)||!Number.isInteger(config.version)||config.version<1||!config.kid||config.publicKey.type!=='public'||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>30000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new PolicyError('configuration');
  this.config={...config,origin:u.origin};
 }
 async sign(payload:JWTPayload):Promise<string>{
  try{
   const c=this.config,signal=AbortSignal.timeout(c.timeoutMs),token=c.token();if(!token||/[\r\n]/.test(token))throw Error();
   // JOSE does not expose remote signing hooks. Encode the standard JWS input,
   // then independently verify the complete result with mature JOSE before release.
   const input=Buffer.from(JSON.stringify({alg:'RS256',kid:c.kid,typ:'JWT'})).toString('base64url')+'.'+Buffer.from(JSON.stringify(payload)).toString('base64url');
   const r=await(c.fetch??fetch)(`${c.origin}/v1/${c.mount}/sign/${c.name}/sha2-256`,{method:'POST',redirect:'error',signal,headers:{'Content-Type':'application/json','X-Vault-Token':token},body:JSON.stringify({input:Buffer.from(input).toString('base64'),key_version:c.version,signature_algorithm:'pkcs1v15',prehashed:false})});
   if(!r.ok)throw Error();let raw='';for await(const chunk of r.body??[]){raw+=Buffer.from(chunk).toString('utf8');if(raw.length>16384)throw Error();}
   const signature=JSON.parse(raw)?.data?.signature,prefix=`vault:v${c.version}:`;
   if(typeof signature!=='string'||!signature.startsWith(prefix)||! /^[A-Za-z0-9+/]+={0,2}$/.test(signature.slice(prefix.length)))throw Error();
   const assertion=input+'.'+Buffer.from(signature.slice(prefix.length),'base64').toString('base64url');
   await compactVerify(assertion,c.publicKey,{algorithms:['RS256']});signal.throwIfAborted();return assertion;
  }catch{throw new PolicyError('unavailable');}
 }
}
