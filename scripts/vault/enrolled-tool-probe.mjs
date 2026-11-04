// Fixed local verification destinations. No secrets/tokens in arguments/output.
import {readFileSync} from 'node:fs';
import {request} from 'node:https';
const input=JSON.parse(readFileSync(0,'utf8'));
if(input.token!==undefined&&(typeof input.token!=='string'||input.token.length>16000))throw Error('Invalid probe token');
const backend=input.target==='backend',health=['live','ready','metrics'].includes(input.health);
const path=backend?input.path??'/pf/JWKS':health?'/health/'+input.health:'/v1/tools/verify-access';
if(!['/pf/JWKS','/pf-admin-api/v1/version','/as/token.oauth2','/v1/grants','/v1/assertions','/pf/JWKS?target=admin','/v1/health'].includes(path)&&!['/health/live','/health/ready','/health/metrics','/v1/tools/verify-access'].includes(path))throw Error('Invalid probe');
const result=await new Promise(done=>{
 const req=request({hostname:backend?'tool-backend':'tool-api',port:backend?7443:8443,path,method:backend||health?'GET':'POST',ca:readFileSync('/run/probe/server-ca.pem'),rejectUnauthorized:true,...(!backend&&input.client!=='none'?{key:readFileSync('/run/probe/client-key.pem'),cert:readFileSync('/run/probe/client-cert.pem')}:{}) ,headers:backend||health?{}:{'Content-Type':'application/json',...(input.token?{Authorization:'Bearer '+input.token}:input.bearer?{Authorization:'Bearer invalid'}:{})}},res=>{
  let raw='';res.on('data',c=>{raw+=c;if(raw.length>262144)req.destroy();});res.on('end',()=>{let body;try{body=JSON.parse(raw);}catch{}done({status:res.statusCode,authorized:body?.authorized===true,ready:body?.ready===true,live:body?.live===true,publicJwks:Array.isArray(body?.keys)&&body.keys.some(k=>k.kty==='RSA'&&k.kid==='copilot-tool-signing'&&typeof k.n==='string')&&body.keys.every(k=>['RSA','EC'].includes(k.kty)&&!['d','p','q','dp','dq','qi','k'].some(f=>f in k)),metrics:!!body?.counters});});res.on('error',()=>done({error:'transport_denied'}));res.on('aborted',()=>done({error:'transport_denied'}));
 });
 const timer=setTimeout(()=>req.destroy(),4000);req.on('close',()=>clearTimeout(timer));req.on('error',()=>done({error:'transport_denied'}));req.end(backend||health?undefined:JSON.stringify(input.body??{}));
});
console.log(JSON.stringify(result));
