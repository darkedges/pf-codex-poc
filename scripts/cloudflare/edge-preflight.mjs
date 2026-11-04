// Read-only public DNS/TLS diagnostic. No Cloudflare API credentials or HTTP
// requests to the proposed PF hosts; no DNS/route/certificate changes.
import {connect} from 'node:tls';import {mkdirSync,writeFileSync} from 'node:fs';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';
const root=resolve(fileURLToPath(new URL('../../',import.meta.url))),hosts=['pf-a.copilot.darkedges.com','pf-b.copilot.darkedges.com'];
async function dns(name,type){
 try{
  const response=await fetch('https://cloudflare-dns.com/dns-query?'+new URLSearchParams({name,type}),{headers:{Accept:'application/dns-json'},redirect:'error',signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw Error();const body=await response.text();if(body.length>32768)throw Error();const result=JSON.parse(body);
  return{status:result.Status,answers:(result.Answer??[]).filter(a=>[1,5,28].includes(a.type)).map(a=>({type:a.type,data:a.data}))};
 }catch{return{status:'unavailable',answers:[]};}
}
async function tls(host,edgeIp){
 if(!edgeIp)return{verified:false,errorCode:'EDGE_IP_UNAVAILABLE'};
 return new Promise(done=>{
  const socket=connect({host:edgeIp,port:443,servername:host,rejectUnauthorized:true},()=>{
   const cert=socket.getPeerCertificate();socket.destroy();done({verified:socket.authorized,validTo:cert.valid_to,coveredCopilotNames:cert.subjectaltname?.split(', ').filter(s=>s.endsWith('.copilot.darkedges.com'))??[]});
  });
  const timer=setTimeout(()=>socket.destroy(Error('deadline')),10000);socket.once('close',()=>clearTimeout(timer));
  socket.once('error',error=>done({verified:false,errorCode:error.code??'TLS_UNAVAILABLE'}));
 });
}
const edge=await dns('darkedges.com','A'),edgeIp=edge.answers.find(a=>a.type===1)?.data;
const results=[];
for(const host of hosts){const a=await dns(host,'A'),aaaa=await dns(host,'AAAA');results.push({host,dnsA:a,dnsAAAA:aaaa,tls:await tls(host,edgeIp)});}
const result={checkedAt:new Date().toISOString(),readOnly:true,edgeIp:edgeIp??null,dnsChanged:false,routesChanged:false,certificateChanged:false,results};
const directory=resolve(root,'.local/cloudflare-plan');mkdirSync(directory,{recursive:true});writeFileSync(resolve(directory,'edge-preflight.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
