import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { bodyHash } from './protocol.ts';
import { PolicyError,type Capability } from './contracts.ts';
import type { DelegatedClaims } from '../adapters/token-exchange.ts';
type Config={origin:string;clientId:string;keyId:string;key:CryptoKey;capability:Capability;timeoutMs:number;fetch?:typeof fetch};
export class PolicyClient{
  private config:Config;
  constructor(config:Config){
    const u=new URL(config.origin);
    if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash||!config.clientId||!config.keyId||config.key.type!=='private'||typeof config.capability?.scope!=='string'||!config.capability.scope||typeof config.capability.resource!=='string'||!config.capability.resource||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>30000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new PolicyError('configuration');
    this.config={...config,origin:u.origin,capability:structuredClone(config.capability)};
  }
  async request(path:string,value:Record<string,unknown>){
    try{
      if(!/^\/v1\/[A-Za-z0-9/_:-]+$/.test(path)||path.length>300)throw Error();
      const c=this.config,raw=JSON.stringify(value);
      if(Buffer.byteLength(raw)>50000)throw Error();
      const assertion=await new SignJWT({method:'POST',body_sha256:bodyHash(raw)}).setProtectedHeader({alg:'RS256',kid:c.keyId,typ:'policy-request+jwt'})
        .setIssuer(c.clientId).setSubject(c.clientId).setAudience(c.origin+path).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(c.key);
      const r=await(c.fetch??fetch)(c.origin+path,{method:'POST',redirect:'error',signal:AbortSignal.timeout(c.timeoutMs),headers:{'Content-Type':'application/json',Accept:'application/json',Authorization:'Policy '+assertion},body:raw});
      if(!r.ok)throw new PolicyError(r.status===403?'forbidden':r.status===401?'unauthenticated':'unavailable');
      let rawResult='';for await(const chunk of r.body??[]){rawResult+=Buffer.from(chunk).toString('utf8');if(rawResult.length>32768)throw Error();}
      return JSON.parse(rawResult)as Record<string,unknown>;
    }catch(error){throw error instanceof PolicyError?error:new PolicyError('unavailable');}
  }
  authorise=async(_claims:Readonly<DelegatedClaims>,evidence?:{accessToken:string})=>{
    if(!evidence||typeof evidence.accessToken!=='string')throw new PolicyError();
    const result=await this.request('/v1/decisions',{token:evidence.accessToken,capability:this.config.capability});
    if(result.permit!==true||typeof result.decisionId!=='string'||!Number.isInteger(result.grantVersion)||Number(result.grantVersion)<1)throw new PolicyError();
  };
}
