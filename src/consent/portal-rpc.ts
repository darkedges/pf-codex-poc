import {randomUUID} from 'node:crypto';import {PolicyError} from '../policy/contracts.ts';
type Peer={on(event:string,fn:(...args:any[])=>void):unknown;removeListener(event:string,fn:(...args:any[])=>void):unknown;send(message:unknown):unknown};
type Method='oidc.start'|'oidc.redeem'|'provider.start'|'provider.redeem'|'policy.request'|'execute';
export type PortalRpcMethods=Partial<Record<Method,(...args:any[])=>Promise<unknown>>>;
const methods:Method[]=['oidc.start','oidc.redeem','provider.start','provider.redeem','policy.request','execute'];
const object=(v:any)=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:any,names:string[])=>object(v)&&Object.keys(v).every(k=>names.includes(k));
const text=(v:any,max=16000)=>typeof v==='string'&&v.length>0&&v.length<=max;
const proof=(v:any)=>keys(v,['idToken','nonce'])&&text(v.idToken)&&text(v.nonce,256);
const argsValid=(method:Method,args:any)=>{
 if(!Array.isArray(args))return false;
 if(method==='oidc.start')return args.length===3&&args.every(v=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v));
 if(method==='provider.start')return args.length===2&&args.every(v=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v));
 if(method==='oidc.redeem'||method==='provider.redeem')return args.length===3&&args.every(v=>text(v,4096));
 if(method==='policy.request')return args.length===2&&['/v1/consents/preview','/v1/consents/approve','/v1/consents/revoke'].includes(args[0])&&keys(args[1],['idToken','nonce','termsHash','modes','durationSeconds','grantId'])&&proof({idToken:args[1].idToken,nonce:args[1].nonce});
 return args.length===1&&keys(args[0],['grantId','providerToken','login'])&&text(args[0].grantId,160)&&text(args[0].providerToken)&&proof(args[0].login);
};
function resultValid(method:Method,args:any[],value:any){
 if(method.endsWith('.start'))return text(value,12000)&&new URL(value).protocol==='https:';
 if(method==='execute')return keys(value,['authorized'])&&value.authorized===true;
 if(method==='oidc.redeem')return keys(value,['login','idToken'])&&text(value.idToken)&&keys(value.login,['issuer','subject','audience','issuedAt','authTime','expiresAt','tokenHash','nonceHash']);
 if(method==='provider.redeem')return keys(value,['token','claims'])&&text(value.token)&&keys(value.claims,['iss','aud','sub','scope','iat','nbf','exp','jti']);
 if(args[0].endsWith('/preview'))return keys(value,['human','agent','capability','termsHash','modes','durationsSeconds','grants'])&&keys(value.human,['subject','organisation'])&&keys(value.agent,['id','subject','issuer'])&&keys(value.capability,['scope','resource'])&&Array.isArray(value.grants)&&value.grants.length<=20&&value.grants.every((g:any)=>keys(g,['id','state','modes','expiresAt']));
 if(args[0].endsWith('/approve'))return keys(value,['grantId','expiresAt','modes']);
 return keys(value,['revoked'])&&value.revoked===true;
}
function bounded(value:unknown){try{return Buffer.byteLength(JSON.stringify(value))<=100000;}catch{return false;}}
export function attachPortalRpcServer(peer:Peer,handlers:PortalRpcMethods){
 let closed=false,draining=false;const seen=new Set<string>(),pending=new Set<Promise<void>>();
 const send=(m:any)=>{if(!closed)try{peer.send(m);}catch{}};
 const receive=(message:any)=>{
  if(message?.kind!=='call')return;
  const id=message.id;
  if(typeof id!=='string'||!/^[a-f0-9-]{36}$/.test(id))return;
  const fail=()=>send({kind:'result',id,ok:false,error:'unavailable'});
  if(closed||draining||pending.size>=4||seen.size>=128||seen.has(id)||!keys(message,['kind','id','method','args'])||!methods.includes(message.method)||!bounded(message)||!argsValid(message.method,message.args)||typeof handlers[message.method as Method]!=='function'){fail();return;}
  seen.add(id);
  const task=(async()=>{try{
   const result=await handlers[message.method as Method]!(...message.args);
   if(!bounded(result)||!resultValid(message.method,message.args,result))throw Error();
   send({kind:'result',id,ok:true,value:result});
  }catch{fail();}})();pending.add(task);void task.finally(()=>pending.delete(task));
 };
 peer.on('message',receive);
 return{drain:async()=>{draining=true;await Promise.allSettled([...pending]);},close:()=>{closed=true;draining=true;peer.removeListener('message',receive);}};
}
export function createPortalRpcClient(peer:Peer){
 let closed=false;const pending=new Map<string,{method:Method;args:any[];done:(v:unknown)=>void;fail:(e:Error)=>void;timer:ReturnType<typeof setTimeout>}>();
 const close=()=>{if(closed)return;closed=true;peer.removeListener('message',receive);peer.removeListener('disconnect',close);for(const p of pending.values()){clearTimeout(p.timer);p.fail(new PolicyError('unavailable'));}pending.clear();};
 const receive=(m:any)=>{
  if(m?.kind!=='result'||!pending.has(m.id))return;const p=pending.get(m.id)!;pending.delete(m.id);clearTimeout(p.timer);
  try{if(!bounded(m)||!keys(m,['kind','id','ok','value','error'])||m.ok!==true||!resultValid(p.method,p.args,m.value))throw Error();p.done(m.value);}catch{p.fail(new PolicyError('unavailable'));}
 };
 peer.on('message',receive);peer.on('disconnect',close);
 return{call:(method:Method,args:any[]):Promise<any>=>new Promise((done,fail)=>{
  if(closed||pending.size>=4||!methods.includes(method)||!argsValid(method,args)){fail(new PolicyError('unavailable'));return;}
  const id=randomUUID(),timer=setTimeout(()=>{pending.delete(id);fail(new PolicyError('unavailable'));},method==='execute'?85000:15000);pending.set(id,{method,args,done,fail,timer});
  try{peer.send({kind:'call',id,method,args});}catch{pending.delete(id);clearTimeout(timer);fail(new PolicyError('unavailable'));}
 }),close};
}
