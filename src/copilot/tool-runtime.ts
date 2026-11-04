import {open,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isAbsolute,resolve} from 'node:path';
import {createPrivateKey,createPublicKey,X509Certificate} from 'node:crypto';
import {importPKCS8,importJWK} from 'jose';
import {JwksTokenVerifier,type IssuerTrust} from '../adapters/pingfederate.ts';
import {PolicyClient} from '../policy/client.ts';
import {PolicyProtectedTool,ToolAccessError} from './tool-authority.ts';
import {ToolApi} from './tool-api.ts';
import {createToolServer} from './tool-server.ts';
import {ToolReadiness} from './tool-readiness.ts';
import {RestrictedToolAudit} from './tool-audit.ts';
import {ToolMonitor} from './tool-monitor.ts';

const check=(v:unknown)=>{if(!v)throw Error();};
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=2048&&!/[\u0000-\u0020\u007f]/.test(v);
function closed(v:any,keys:string){check(v&&typeof v==='object'&&!Array.isArray(v));check(Object.keys(v).sort().join(',')===keys.split(',').sort().join(','));}
function https(value:string,originOnly=false){check(text(value));const u=new URL(value);check(u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash);if(originOnly)check(u.pathname==='/');}
async function boundedFile(path:string,max:number){
 const file=await open(path,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));try{
  const info=await file.stat();check(info.isFile()&&info.size>0&&info.size<=max);
  const data=Buffer.alloc(max+1);let n=0;
  while(n<=max){const r=await file.read(data,n,data.length-n,null);n+=r.bytesRead;if(!r.bytesRead)break;}
  check(n>0&&n<=max);return data.subarray(0,n).toString('utf8');
 }finally{await file.close();}
}
type RuntimeDependencies={fetch?:typeof fetch;observe?:(event:Record<string,unknown>)=>void};
// Loads only fixed secret filenames from an explicit protected mount. No lab
// discovery, inline credentials, token issuance, database access or mock mode.
export async function loadToolRuntime(env:Record<string,string|undefined>=process.env,dependencies:RuntimeDependencies={}){
 try{
  check(env.TOOL_MODE==='verified'&&env.NODE_TLS_REJECT_UNAUTHORIZED!=='0'&&process.env.NODE_TLS_REJECT_UNAUTHORIZED!=='0');
  check(env.TOOL_CONFIG_FILE&&isAbsolute(env.TOOL_CONFIG_FILE)&&env.TOOL_SECRETS_DIR&&isAbsolute(env.TOOL_SECRETS_DIR));
  check(env.TOOL_AUDIT_DIR&&isAbsolute(env.TOOL_AUDIT_DIR));
  const directory=await realpath(env.TOOL_SECRETS_DIR!);
  const secret=async(name:string,max=65536)=>{
   const requested=resolve(directory,name),actual=await realpath(requested);check(actual===requested);
   return boundedFile(actual,max);
  };
  check(env.NODE_EXTRA_CA_CERTS===resolve(env.TOOL_SECRETS_DIR!,'tool-outbound-ca.pem'));
  const configRaw=await boundedFile(env.TOOL_CONFIG_FILE!,32768),p=JSON.parse(configRaw);
  closed(p,'version,trust,policy,clientCertificateSha256,timeouts,admission');check(p.version===1);
  closed(p.admission,'maxConcurrentRequests,perWorkloadRequestsPerMinute,maxConnections');
  closed(p.trust,'issuer,jwksUri,audience,algorithms,keyIds,organisations,actorIssuers,maxLifetimeSeconds');
  check(p.trust.audience==='api://copilot-tool'&&JSON.stringify(p.trust.algorithms)==='["RS256"]'&&p.trust.maxLifetimeSeconds===120);
  https(p.trust.issuer);https(p.trust.jwksUri);
  for(const field of ['keyIds','organisations','actorIssuers'])check(Array.isArray(p.trust[field])&&p.trust[field].length>0&&p.trust[field].length<=20&&p.trust[field].every(text)&&new Set(p.trust[field]).size===p.trust[field].length);
  for(const issuer of p.trust.actorIssuers)https(issuer);
  closed(p.policy,'origin,clientId,keyId');https(p.policy.origin,true);check(text(p.policy.clientId)&&text(p.policy.keyId));
  check(Array.isArray(p.clientCertificateSha256)&&p.clientCertificateSha256.length>0&&p.clientCertificateSha256.length<=20&&p.clientCertificateSha256.every((pin:unknown)=>typeof pin==='string'&&/^([A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(pin)));
  closed(p.timeouts,'jwksMs,policyMs,toolMs');
  check([p.timeouts.jwksMs,p.timeouts.policyMs,p.timeouts.toolMs].every(n=>Number.isInteger(n)&&n>=100&&n<=5000));
  check(p.timeouts.toolMs>p.timeouts.policyMs*2&&p.timeouts.toolMs>p.timeouts.jwksMs);
  const key=await secret('tool-server-key.pem',16384),cert=await secret('tool-server-cert.pem');
  const ca=await secret('tool-client-ca.pem'),outbound=await secret('tool-outbound-ca.pem');
  for(const pem of [cert,ca,outbound]){
   const blocks=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);check(blocks?.length);
   for(const block of blocks!){const x=new X509Certificate(block);check(Date.parse(x.validFrom)<=Date.now()&&Date.parse(x.validTo)>Date.now());}
  }
  const privateKey=createPrivateKey(key);check(privateKey.asymmetricKeyType==='rsa'||privateKey.asymmetricKeyType==='ec');
  check(new X509Certificate(cert).publicKey.export({type:'spki',format:'der'}).equals(createPublicKey(privateKey).export({type:'spki',format:'der'})));
  const policyPem=await secret('tool-policy-key.pem',16384),policyMaterial=createPrivateKey(policyPem);
  check(policyMaterial.asymmetricKeyType==='rsa'&&(policyMaterial.asymmetricKeyDetails?.modulusLength??0)>=2048);
  const policyKey=await importPKCS8(policyPem,'RS256',{extractable:false});
  const auditKey=await secret('tool-audit-key',128);check(/^[a-f0-9]{64}$/.test(auditKey.trim()));
  const audit=new RestrictedToolAudit({directory:env.TOOL_AUDIT_DIR!,key:Buffer.from(auditKey.trim(),'hex')}),monitor=new ToolMonitor();
  const emit=(event:Record<string,unknown>)=>{const projected=monitor.observe(event);if(projected)try{dependencies.observe?.(projected);}catch{}};
  const expiry=Math.min(...[cert,ca,outbound].flatMap(pem=>(pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)??[]).map(block=>Date.parse(new X509Certificate(block).validTo))));
  const policy=new PolicyClient({origin:p.policy.origin,clientId:p.policy.clientId,keyId:p.policy.keyId,key:policyKey,capability:{scope:'copilot.invoke',resource:'sharepoint:approved-research'},timeoutMs:p.timeouts.policyMs,fetch:dependencies.fetch});
  const verifier=new JwksTokenVerifier([p.trust as IssuerTrust],'copilot.invoke',p.timeouts.jwksMs,dependencies.fetch);
  const tool=new PolicyProtectedTool({verifier,authorise:policy.authorise,timeoutMs:p.timeouts.toolMs,operation:async()=>({authorized:true}),audit:async event=>audit.write(event),observe:event=>emit({...event})});
  const readiness=new ToolReadiness({timeoutMs:2500,cacheMs:1000,checks:[
   async()=>{
    const current=await Promise.all([secret('tool-server-key.pem',16384),secret('tool-server-cert.pem'),secret('tool-client-ca.pem'),secret('tool-outbound-ca.pem'),secret('tool-policy-key.pem',16384),boundedFile(env.TOOL_CONFIG_FILE!,32768),secret('tool-audit-key',128)]);
    check(current.every((v,i)=>v===[key,cert,ca,outbound,policyPem,configRaw,auditKey][i])&&audit.healthy());
    for(const pem of [cert,ca,outbound])for(const block of pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)??[]){const x=new X509Certificate(block);check(Date.parse(x.validFrom)<=Date.now()&&Date.parse(x.validTo)>Date.now());}
    return true;
   },
   async()=>{const result=await policy.request('/v1/health',{});return result.ready===true;},
   async signal=>{
    const response=await(dependencies.fetch??fetch)(p.trust.jwksUri,{redirect:'error',signal,headers:{Accept:'application/json'}});
    if(!response.ok||!response.headers.get('content-type')?.startsWith('application/json')){await response.body?.cancel();return false;}
    let raw='';for await(const chunk of response.body??[]){signal.throwIfAborted();raw+=Buffer.from(chunk).toString('utf8');check(raw.length<=65536);}
    const jwks=JSON.parse(raw);check(Array.isArray(jwks.keys)&&jwks.keys.length>0&&jwks.keys.length<=100);
    check(jwks.keys.every(k=>!['d','p','q','dp','dq','qi','oth','k'].some(field=>field in k)));
    for(const jwk of jwks.keys.filter(k=>p.trust.keyIds.includes(k.kid)&&k.kty==='RSA'&&(k.alg===undefined||k.alg==='RS256')&&k.use==='sig')){
     const publicKey=await importJWK(jwk,'RS256');if(!(publicKey instanceof Uint8Array)&&publicKey.type==='public'&&(publicKey.algorithm as RsaHashedKeyAlgorithm).modulusLength>=2048)return true;
    }
    return false;
   },
  ]});
  const ready=async()=>{const result=await readiness.check(),event=monitor.readiness(result);if(event)try{dependencies.observe?.(event);}catch{}return result;};
  const metrics=()=>monitor.snapshot(expiry,audit.healthy());
  const server=createToolServer({key,cert,ca},new ToolApi(tool),{certificateSha256:p.clientCertificateSha256},{admission:p.admission,ready,metrics,observe:emit});
  return{server,ready,metrics};
 }catch{throw new ToolAccessError('configuration');}
}
