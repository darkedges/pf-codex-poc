import {open,readdir,realpath} from 'node:fs/promises';import {isAbsolute,resolve} from 'node:path';
import {relayFileMapping,validateRelayRecord} from './relay-credentials.mjs';
import {ProviderRelayError,connectionKeyAuthenticator,type ProviderRelayDependencies,type ProviderRelayConfig} from './provider-tool-relay.ts';
import {composeProviderToolConnection,type RelayHttpControls} from './provider-relay-http.ts';
import {RelayAuditJournal} from './relay-audit.ts';
import type {DirectLineConfig,DirectLineDependencies} from '../adapters/copilot.ts';
type RuntimeDependencies=Omit<ProviderRelayDependencies,'authenticateCaller'|'audit'|'invokeTool'>&{channel:Omit<DirectLineDependencies,'verifier'|'providerVerifier'|'bindProviderIdentity'|'providerSession'>};
const samePath=(a:string,b:string)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
async function file(path:string,max=65536){
 if(!isAbsolute(path)||!samePath(await realpath(path),resolve(path)))throw Error();
 const handle=await open(path,'r');try{const stat=await handle.stat();if(!stat.isFile()||stat.nlink!==1||stat.size<1||stat.size>max)throw Error();const result=await handle.readFile('utf8');if(Buffer.byteLength(result)>max)throw Error();return result;}finally{await handle.close();}
}
// Selected secret-manager snapshots and trusted dependencies only. No listen or network at load.
export async function loadRelayRuntime(env:Record<string,string|undefined>,dependencies:RuntimeDependencies){
 try{
  if(env.RELAY_MODE!=='verified'||!['1','7'].includes(env.RELAY_AUDIT_RETENTION_DAYS??'')||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
  for(const name of ['RELAY_CONFIG_FILE','RELAY_SECRETS_DIR','RELAY_AUDIT_DIR'])if(!env[name]||!isAbsolute(env[name]!)||!samePath(await realpath(env[name]!),resolve(env[name]!)))throw Error();
  const configPath=env.RELAY_CONFIG_FILE!,secrets=env.RELAY_SECRETS_DIR!,auditDirectory=env.RELAY_AUDIT_DIR!;
  const fields=Object.entries(relayFileMapping),names=fields.map(([,name])=>name).sort();
  if(JSON.stringify((await readdir(secrets)).sort())!==JSON.stringify(names))throw Error();
  const configRaw=await file(configPath,50000),config=JSON.parse(configRaw)as {version:number;relay:ProviderRelayConfig;directLine:DirectLineConfig;privateToolOrigin:string;controls:RelayHttpControls};
  if(Object.keys(config).sort().join()!=='controls,directLine,privateToolOrigin,relay,version'||config.version!==1||typeof config.privateToolOrigin!=='string')throw Error();
  const values=await Promise.all(fields.map(([,name])=>file(resolve(secrets,name))));
  const record=Object.fromEntries(fields.map(([field],index)=>[field,values[index]]));validateRelayRecord(record);
  const audit=new RelayAuditJournal({directory:auditDirectory,key:Buffer.from(record.auditHmacKeyHex,'hex'),retentionDays:Number(env.RELAY_AUDIT_RETENTION_DAYS)as 1|7});
  const ready=async()=>{try{if(!audit.healthy()||await file(configPath,50000)!==configRaw||JSON.stringify((await readdir(secrets)).sort())!==JSON.stringify(names))return false;const current=await Promise.all(fields.map(([,name])=>file(resolve(secrets,name))));if(!current.every((value,index)=>value===values[index]))return false;validateRelayRecord(record);return true;}catch{return false;}};
  const connection=composeProviderToolConnection({relayConfig:config.relay,relayDependencies:{...dependencies,authenticateCaller:connectionKeyAuthenticator({callerId:config.relay.callerId,sha256:record.connectionKeySha256}),authoriseBroker:async(claims,evidence)=>{if(!await ready())throw new ProviderRelayError('unavailable');await dependencies.authoriseBroker(claims,evidence);},audit:async event=>{audit.write(event);}},directLineConfig:config.directLine,directLineDependencies:dependencies.channel,privateTool:{origin:config.privateToolOrigin,key:record.outboundKeyPem,cert:record.outboundCertificatePem,ca:record.outboundCaPem,serverCertificateSha256:record.toolServerCertificateSha256,timeoutMs:5000},tls:{key:record.serverKeyPem,cert:record.serverCertificatePem},controls:config.controls});
  return{...connection,ready,audit};
 }catch{throw new ProviderRelayError('configuration');}
}
