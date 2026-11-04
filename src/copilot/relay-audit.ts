import {openSync,closeSync,fstatSync,readFileSync,writeSync,fsyncSync,lstatSync,realpathSync,readdirSync,renameSync,unlinkSync,constants} from 'node:fs';
import {isAbsolute,resolve} from 'node:path';import {createHmac,timingSafeEqual} from 'node:crypto';
export type RelayAuditEvent={event:'copilot_tool_relay';requestId:string;phase:'bound'|'attempt'|'success'|'denied'};
type Options={directory:string;key:Buffer;retentionDays:1|7;maxBytes?:number};
const names=['relay-access.jsonl','relay-access.jsonl.1'];
const fail=():never=>{throw Error('Relay audit unavailable');};
function options(o:Options){
 if(!o||!isAbsolute(o.directory)||realpathSync(o.directory)!==resolve(o.directory)||!lstatSync(o.directory).isDirectory()||!Buffer.isBuffer(o.key)||o.key.length!==32||![1,7].includes(o.retentionDays)||!Number.isInteger(o.maxBytes??1048576)||(o.maxBytes??1048576)<1024||(o.maxBytes??1048576)>1048576)fail();
 return{directory:resolve(o.directory),key:Buffer.from(o.key),retentionDays:o.retentionDays,maxBytes:o.maxBytes??1048576};
}
function scan(o:ReturnType<typeof options>,now:number,enforceAge:boolean){
 const records=new Map<string,{raw:string;oldest:number}>();
 for(const name of readdirSync(o.directory)){
  if(!names.includes(name))fail();const path=resolve(o.directory,name),info=lstatSync(path);
  if(!info.isFile()||info.isSymbolicLink()||info.nlink!==1||info.size>o.maxBytes)fail();
  const fd=openSync(path,constants.O_RDONLY|(constants.O_NOFOLLOW??0));let raw:string;
  try{const s=fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.size!==info.size)fail();raw=readFileSync(fd,'utf8');}finally{closeSync(fd);}
  if(raw&&!raw.endsWith('\n'))fail();let oldest=Infinity;
  for(const line of raw.trim().split('\n').filter(Boolean)){
   const r=JSON.parse(line),at=Date.parse(r.at);
   if(Object.keys(r).sort().join()!=='at,event,phase,requestId,tag,version'||r.version!==1||r.event!=='copilot_tool_relay'||!['bound','attempt','success','denied'].includes(r.phase)||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(r.requestId)||!Number.isFinite(at)||at>now+5000||! /^[a-f0-9]{64}$/.test(r.tag))fail();
   const unsigned={version:1,event:r.event,at:r.at,requestId:r.requestId,phase:r.phase},tag=createHmac('sha256',o.key).update(JSON.stringify(unsigned)).digest();
   if(!timingSafeEqual(tag,Buffer.from(r.tag,'hex')))fail();oldest=Math.min(oldest,at);
  }
  if(enforceAge&&oldest<=now-o.retentionDays*86400000)fail();records.set(name,{raw,oldest});
 }
 return records;
}
export class RelayAuditJournal {
 private options:ReturnType<typeof options>;
 constructor(input:Options){try{this.options=options(input);scan(this.options,Date.now(),true);}catch{fail();}}
 healthy(now=Date.now()){try{scan(this.options,now,true);return true;}catch{return false;}}
 write(event:RelayAuditEvent){
  try{
   if(!event||Object.keys(event).sort().join()!=='event,phase,requestId'||event.event!=='copilot_tool_relay'||!['bound','attempt','success','denied'].includes(event.phase)||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(event.requestId))fail();
   const o=this.options,records=scan(o,Date.now(),true),unsigned={version:1,event:event.event,at:new Date().toISOString(),requestId:event.requestId,phase:event.phase};
   const data=Buffer.from(JSON.stringify({...unsigned,tag:createHmac('sha256',o.key).update(JSON.stringify(unsigned)).digest('hex')})+'\n');if(data.length>o.maxBytes)fail();
   const active=resolve(o.directory,names[0]),archive=resolve(o.directory,names[1]);let size=Buffer.byteLength(records.get(names[0])?.raw??'');
   if(size+data.length>o.maxBytes){if(records.has(names[1]))unlinkSync(archive);renameSync(active,archive);size=0;}
   const fd=openSync(active,constants.O_CREAT|constants.O_WRONLY|constants.O_APPEND|(constants.O_NOFOLLOW??0),0o600);
   try{const info=fstatSync(fd);if(!info.isFile()||info.nlink!==1||info.size!==size)fail();let written=0;while(written<data.length){const count=writeSync(fd,data,written,data.length-written);if(!count)fail();written+=count;}fsyncSync(fd);}finally{closeSync(fd);}
  }catch{fail();}
 }
}
// Explicit stopped-only whole-file maintenance; never an active/offline deletion job.
export function pruneStoppedRelayAudit(input:Options,stopped:boolean,now=Date.now()){
 try{if(stopped!==true)fail();const o=options(input),records=scan(o,now,false);let removed=0;for(const [name,r] of records)if(r.oldest<=now-o.retentionDays*86400000){unlinkSync(resolve(o.directory,name));removed++;}return removed;}catch{fail();}
}
