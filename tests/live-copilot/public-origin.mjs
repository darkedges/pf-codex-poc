// Test-only routing: public Host header, pinned loopback TLS/CA, no DNS changes.
import {request} from 'node:https';
import {read,nodes} from '../../scripts/pf/common.mjs';
import {copilotProfile} from '../../scripts/pf/copilot-config.mjs';
import {forms} from '../live/local-browser.mjs';
import {browserAssets,cookieAttributes} from '../../scripts/pf/browser-assets.mjs';
export {forms};
const origins=new Map([[copilotProfile.loginIssuer,nodes.a.issuer],[copilotProfile.toolIssuer,nodes.b.issuer]]);
export function localPublicRequest(value,fields,headers={}){
 const url=new URL(value),origin=origins.get(url.origin);
 if(!origin||url.username||url.password||url.hash)throw Error('Unapproved public test origin');
 const data=fields?new URLSearchParams(fields).toString():undefined;
 return new Promise((done,reject)=>{
  const req=request(new URL(url.pathname+url.search,origin),{method:data?'POST':'GET',ca:read('ca.pem'),servername:'localhost',rejectUnauthorized:true,
   headers:{...headers,Host:url.host,...(data?{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(data)}:{})}},res=>{
   let html='';res.on('data',chunk=>{html+=chunk;if(html.length>2_000_000)req.destroy(Error('Bounded test response exceeded'));});
   res.on('end',()=>{let value;try{value=JSON.parse(html);}catch{}done({status:res.statusCode,html,value,location:res.headers.location,cookies:res.headers['set-cookie']??[],contentType:res.headers['content-type'],cacheControl:res.headers['cache-control']});});
   res.on('error',()=>reject(Error('Public-profile local response failed')));
  });
  const deadline=setTimeout(()=>req.destroy(Error('Public-profile local deadline exceeded')),10000);
  req.on('close',()=>clearTimeout(deadline));req.on('error',()=>reject(Error('Public-profile local request failed')));req.end(data);
 });
}
export class LocalPublicBrowser{
 constructor(transport=localPublicRequest){this.transport=transport;this.document=copilotProfile.loginIssuer+'/';this.cookies=new Map();this.paths=new Set();this.assets=new Set();this.cookieReview=new Map();}
 async request(value,fields){
  let url=new URL(value,this.document),body=fields;
  for(let step=0;step<16;step++){
   if(url.origin!==copilotProfile.loginIssuer)throw Error('Browser refused unexpected public origin');
   this.paths.add(url.pathname);
   const result=await this.transport(url.href,body,{Cookie:[...this.cookies.values()].join(';'),...(body?{Origin:copilotProfile.loginIssuer}:{})});
   for(const asset of browserAssets(result.html,url.href))this.assets.add(asset);
   for(const cookie of result.cookies){const pair=cookie.split(';')[0],name=pair.split('=')[0];this.cookies.set(name,pair);this.cookieReview.set(name,cookieAttributes(cookie));}
   if([301,302,303,307,308].includes(result.status)&&result.location){
    const next=new URL(result.location,url);
    if(next.origin===new URL(copilotProfile.callback).origin&&next.pathname===new URL(copilotProfile.callback).pathname)return{...result,callback:next};
    if([301,302,303].includes(result.status))body=undefined;
    url=next;continue;
   }
   this.document=url.href;return result;
  }
  throw Error('Bounded public browser redirects exceeded');
 }
 submit(form,fields={}){return this.request(new URL(form.action,this.document),{...form.fields,...fields});}
}
