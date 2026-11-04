// Fixed private tool diagnostic. Tokens enter only on stdin; output is projected.
import {readFileSync} from 'node:fs';import {request} from 'node:https';import {checkServerIdentity} from 'node:tls';
try{
 if(/http|https|tls/i.test(process.env.NODE_DEBUG??''))throw Error();
 const input=JSON.parse(readFileSync(0,'utf8')),config=JSON.parse(readFileSync('/run/probe/config.json','utf8'));
 if(typeof input.token!=='string'||!input.token||input.token.length>16000||/\s/.test(input.token)||Buffer.byteLength(JSON.stringify(input.body??{}))>1024)throw Error();
 const result=await new Promise(done=>{
  const req=request({hostname:'tool-api',port:8443,path:'/v1/tools/verify-access',method:'POST',agent:false,ca:readFileSync('/run/probe/ca.pem'),rejectUnauthorized:true,checkServerIdentity:(host,cert)=>checkServerIdentity(host,cert)??(cert.fingerprint256===config.toolPin?undefined:Error('Unapproved peer')),...(input.client==='none'?{}:{key:readFileSync('/run/probe/key.pem'),cert:readFileSync('/run/probe/cert.pem')}),headers:{'Content-Type':'application/json',Authorization:'Bearer '+input.token}},res=>{
   let raw='';res.on('data',chunk=>{raw+=chunk;if(raw.length>1024)req.destroy();});res.on('end',()=>{try{const body=JSON.parse(raw);done({status:res.statusCode,authorized:Object.keys(body).length===1&&body.authorized===true});}catch{done({error:'transport_denied'});}});res.on('error',()=>done({error:'transport_denied'}));res.on('aborted',()=>done({error:'transport_denied'}));
  });const timer=setTimeout(()=>req.destroy(),5000);req.on('close',()=>clearTimeout(timer));req.on('error',()=>done({error:'transport_denied'}));req.end(JSON.stringify(input.body??{}));
 });console.log(JSON.stringify(result));
}catch{console.log(JSON.stringify({error:'transport_denied'}));}
