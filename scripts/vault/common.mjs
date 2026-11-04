import { request } from 'node:https';
import { mkdirSync,writeFileSync,readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { local,read } from '../pf/common.mjs';
export const directory=resolve(local,'vault'),origin='https://localhost:9470',keyName='consent-authority';
export const privateRead=name=>readFileSync(resolve(directory,name),'utf8');
export const privateLoad=name=>JSON.parse(privateRead(name));
export function privateSave(name,value){if(!/^[\w.-]+$/.test(name))throw Error('Invalid private artifact');mkdirSync(directory,{recursive:true});writeFileSync(resolve(directory,name),typeof value==='string'?value:JSON.stringify(value,null,2),{mode:0o600});}
export function vault(path,{method='GET',body,token,timeoutMs=5000,cert,key}={}){
 if(!/^\/[A-Za-z0-9/_-]+$/.test(path)||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('Invalid Vault lab request');
 const data=body===undefined?undefined:JSON.stringify(body);
 return new Promise((done,reject)=>{
  const headers={Accept:'application/json'};if(token)headers['X-Vault-Token']=token;if(data){headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(data);}
  const req=request(origin+'/v1'+path,{method,headers,ca:read('ca.pem'),rejectUnauthorized:true,cert,key},res=>{
   let text='';res.on('data',chunk=>{text+=chunk;if(text.length>1000000)req.destroy();});
   res.on('end',()=>{let value;try{value=JSON.parse(text);}catch{}done({status:res.statusCode,value});});res.on('error',()=>reject(Error('Vault response unavailable')));
  });
  const timer=setTimeout(()=>req.destroy(Error('Vault request timed out')),timeoutMs);
  req.on('close',()=>clearTimeout(timer));req.on('error',()=>reject(Error('Vault HTTPS request unavailable')));req.end(data);
 });
}
export async function operator(path,options={}){const r=await vault(path,{...options,token:privateLoad('bootstrap.json').root_token});if(r.status<200||r.status>=300)throw Error(`Vault operator request rejected (${r.status})`);return r.value;}
export async function runtimeToken(ttl='8h'){
 const result=await operator('/auth/token/create',{method:'POST',body:{policies:['consent-sign'],no_default_policy:true,ttl,explicit_max_ttl:ttl,renewable:false,display_name:'local-consent-authority'}});
 if(typeof result?.auth?.client_token!=='string')throw Error('Vault workload credential unavailable');return result.auth;
}
