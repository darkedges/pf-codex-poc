import {createPrivateKey,createHash,X509Certificate,type KeyObject} from 'node:crypto';import {randomUUID} from 'node:crypto';import {SignJWT} from 'jose';
import {validateGraphCredential} from './vault-credential.mjs';import type {GraphAppTokenSource} from './graph-documents.ts';
export type GraphCredentialTrust={tenantId:string;clientId:string;certificateSha256:string};
type Credential={schemaVersion:1;purpose:'sharepoint-broker';tenantId:string;clientId:string;certificatePem:string;privateKeyPem:string};
export class EntraCertificateError extends Error{constructor(code='unavailable'){super(code);this.name='EntraCertificateError';}}
// Controller-only client-credentials transport. Never consumes a PF token and
// never interprets the Microsoft access token as an external human identity.
export class EntraCertificateTokenSource implements GraphAppTokenSource{
 #key:KeyObject;#trust:GraphCredentialTrust;#endpoint:string;#thumbprint:string;#validTo:number;#timeout:number;#fetch:typeof fetch;
 constructor(config:{trust:GraphCredentialTrust;timeoutMs:number},record:Credential,transport:typeof fetch=fetch){
  try{
   if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>30000)throw Error();
   const validated=validateGraphCredential(record,config.trust),cert=new X509Certificate(validated.certificatePem);this.#key=createPrivateKey(validated.privateKeyPem);this.#trust={...config.trust};this.#endpoint='https://login.microsoftonline.com/'+this.#trust.tenantId+'/oauth2/v2.0/token';this.#thumbprint=createHash('sha256').update(cert.raw).digest('base64url');this.#validTo=Date.parse(cert.validTo);this.#timeout=config.timeoutMs;this.#fetch=transport;
  }catch{throw new EntraCertificateError('configuration');}
 }
 async getToken(){
  try{
   const now=Math.floor(Date.now()/1000),signal=AbortSignal.timeout(this.#timeout);if(this.#validTo<=Date.now()+120000)throw Error();
   const assertion=await new SignJWT({}).setProtectedHeader({alg:'PS256',typ:'JWT','x5t#S256':this.#thumbprint}).setIssuer(this.#trust.clientId).setSubject(this.#trust.clientId).setAudience(this.#endpoint).setIssuedAt(now).setNotBefore(now).setExpirationTime(now+60).setJti(randomUUID()).sign(this.#key);signal.throwIfAborted();
   const body=new URLSearchParams({client_id:this.#trust.clientId,grant_type:'client_credentials',scope:'https://graph.microsoft.com/.default',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion});
   const response=await this.#fetch(this.#endpoint,{method:'POST',redirect:'error',signal,headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:body.toString()});if(response.status!==200)throw Error();
   let size=0;const chunks:Uint8Array[]=[];for await(const chunk of response.body??[]){size+=chunk.byteLength;if(size>65536)throw Error();chunks.push(chunk);}signal.throwIfAborted();
   const result=JSON.parse(Buffer.concat(chunks,size).toString('utf8'));
   if(typeof result.access_token!=='string'||!result.access_token||result.access_token.length>32768||/\s/.test(result.access_token)||String(result.token_type).toLowerCase()!=='bearer'||!Number.isSafeInteger(result.expires_in)||result.expires_in<30||result.expires_in>86400)throw Error();
   return{value:result.access_token,expiresAt:Math.min((now+result.expires_in)*1000,this.#validTo)};
  }catch{throw new EntraCertificateError();}
 }
}
