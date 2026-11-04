import {importJWK,type JWTPayload} from 'jose';
import {VaultTransitSigner,type AssertionSigner} from '../identity/assertion-signer.ts';
import {documentSignerSpec,validatedDocumentLease} from './document-authority-custody.mjs';import {withDeadline} from './approved-content.ts';

type Call=(path:string,options?:{method?:string;body?:unknown;token?:string})=>Promise<{status:number;value?:any}>;
// The supplied transport owns the dedicated signer certificate and validates
// the configured Vault server CA. No root token or private Transit key enters
// this composition. Every sign obtains one short, one-use cert-auth lease.
export async function createDocumentVaultSigner(call:Call,profile:any):Promise<AssertionSigner>{
 try{
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||profile?.origin!=='https://localhost:9470'||profile.mount!=='transit'||profile.name!==documentSignerSpec.name||profile.version!==1||profile.kid!=='document-authority-v1'||profile.timeoutMs!==3000||!profile.publicJwk||Object.keys(profile.publicJwk).sort().join()!=='alg,e,kid,kty,n,use'||profile.publicJwk.kid!==profile.kid||profile.publicJwk.alg!=='RS256'||profile.publicJwk.use!=='sig'||profile.publicJwk.kty!=='RSA')throw Error();
  const config=structuredClone(profile),key=await importJWK(config.publicJwk,'RS256');if(key instanceof Uint8Array||key.type!=='public'||Number((key.algorithm as RsaHashedKeyAlgorithm).modulusLength)<3072)throw Error();
  return{sign:async(payload:JWTPayload)=>{
   try{
    const signal=AbortSignal.timeout(3000),token=validatedDocumentLease(await withDeadline(call('/auth/tool-cert/login',{method:'POST',body:{name:documentSignerSpec.role}}),signal),documentSignerSpec.policy);
    const signer=new VaultTransitSigner({...config,publicKey:key,token:()=>token,fetch:async(url,init)=>{
     if(String(url)!=='https://localhost:9470/v1'+documentSignerSpec.path||init?.method!=='POST'||init.redirect!=='error')throw Error();
     const result=await withDeadline(call(documentSignerSpec.path,{method:'POST',token,body:JSON.parse(String(init.body))}),signal);
     return Response.json(result.value??{},{status:result.status});
    }});
    return await withDeadline(signer.sign(structuredClone(payload)),signal);
   }catch{throw Error('document_signer_unavailable');}
  }};
 }catch{throw Error('document_signer_configuration');}
}
