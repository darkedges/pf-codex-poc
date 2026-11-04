import {openSync,closeSync,fstatSync,readSync,writeSync,fsyncSync,lstatSync,realpathSync,renameSync,unlinkSync,constants} from 'node:fs';
import {isAbsolute,resolve} from 'node:path';
import {createHmac} from 'node:crypto';
import type {DelegatedClaims} from '../adapters/token-exchange.ts';
export type ToolAuditEvidence={requestId:string;outcome:'attempt'|'success'|'denied';code?:string;claims?:Readonly<DelegatedClaims>};
const codes=['invalid_token','policy_denied','tool_failed','audit_failed'];
export class RestrictedToolAudit {
 private directory:string;private key:Buffer;private max:number;
 constructor(options:{directory:string;key:Buffer;maxBytes?:number}){
  const max=options.maxBytes??1048576;
  if(!isAbsolute(options.directory)||realpathSync(options.directory)!==resolve(options.directory)||!Buffer.isBuffer(options.key)||options.key.length!==32||!Number.isInteger(max)||max<1024||max>1048576)throw Error('Restricted audit unavailable');
  this.directory=options.directory;this.key=Buffer.from(options.key);this.max=max;
  const fd=this.open(true);closeSync(fd);
 }
 private path(archive=false){return resolve(this.directory,archive?'tool-access.jsonl.1':'tool-access.jsonl');}
 private open(create=false){
  try{const existing=lstatSync(this.path());if(!existing.isFile()||existing.nlink!==1)throw Error();}catch(e){if(!create||(e as NodeJS.ErrnoException).code!=='ENOENT')throw Error('Restricted audit unavailable');}
  const fd=openSync(this.path(),(create?constants.O_CREAT:0)|constants.O_RDWR|constants.O_APPEND|(constants.O_NOFOLLOW??0),0o600);
  try{
   const info=fstatSync(fd);if(!info.isFile()||info.nlink!==1||info.size>this.max)throw Error();
   if(info.size){const byte=Buffer.alloc(1);readSync(fd,byte,0,1,info.size-1);if(byte[0]!==10)throw Error();}
   return fd;
  }catch{closeSync(fd);throw Error('Restricted audit unavailable');}
 }
 healthy(){try{const fd=this.open();try{fsyncSync(fd);}finally{closeSync(fd);}return true;}catch{return false;}}
 write(event:ToolAuditEvidence){
  if(!/^[a-f0-9-]{36}$/.test(event.requestId)||!['attempt','success','denied'].includes(event.outcome)||event.code!==undefined&&!codes.includes(event.code))throw Error('Restricted audit unavailable');
  const ref=(kind:string,values:unknown[])=>createHmac('sha256',this.key).update(JSON.stringify([kind,...values])).digest('hex');
  const c=event.claims;
  if(c&&(!['interactive','autonomous'].includes(c.execution_mode)||c.aud!=='api://copilot-tool'||c.scope!=='copilot.invoke'||![c.iss,c.sub,c.act?.iss,c.act?.sub,c.org_id,c.delegation_id].every(v=>typeof v==='string'&&v.length>0&&v.length<=2048)))throw Error('Restricted audit unavailable');
  const record={version:1,event:'tool_access',at:new Date().toISOString(),requestId:event.requestId,outcome:event.outcome,...(event.code?{code:event.code}:{}),...(c?{identity:{humanRef:ref('human',[c.iss,c.sub]),actorRef:ref('actor',[c.act.iss,c.act.sub]),organisationRef:ref('organisation',[c.org_id]),grantRef:ref('grant',[c.delegation_id]),issuerRef:ref('issuer',[c.iss]),executionMode:c.execution_mode==='interactive'?'interactive':'autonomous',audience:'api://copilot-tool'}}:{})};
  const data=Buffer.from(JSON.stringify(record)+'\n');if(data.length>this.max)throw Error('Restricted audit unavailable');
  let fd=this.open();try{
   if(fstatSync(fd).size+data.length>this.max){
    closeSync(fd);fd=-1;
    try{const old=lstatSync(this.path(true));if(!old.isFile()||old.nlink!==1)throw Error();unlinkSync(this.path(true));}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
    renameSync(this.path(),this.path(true));fd=this.open(true);
   }
   if(writeSync(fd,data)!==data.length)throw Error();fsyncSync(fd);
  }catch{throw Error('Restricted audit unavailable');}finally{if(fd>=0)closeSync(fd);}
 }
}
