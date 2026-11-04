// Minimal HTTPS browser harness for the fixed local PF/consent origins. Never logs URLs or bodies.
import { nodes } from '../../scripts/pf/common.mjs';
const decode=s=>s.replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;|&apos;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&#(\d+);/g,(_,n)=>String.fromCharCode(Number(n)));
const attrs=s=>Object.fromEntries([...s.matchAll(/([\w.:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)].map(m=>[m[1],decode(m[2]??m[3])]));
export function forms(html){return[...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)].map(m=>({action:attrs(m[1]).action??'',fields:Object.fromEntries([...m[2].matchAll(/<input\b([^>]*)>/gi)].map(i=>({attributes:attrs(i[1]),source:i[1]})).filter(i=>i.attributes.name&&(!['checkbox','radio'].includes(i.attributes.type)||/\bchecked\b/.test(i.source))).map(i=>[i.attributes.name,i.attributes.value??'']))}));}
export class LocalBrowser{
 constructor(origin){this.origin=origin;this.cookies=new Map();this.document=origin+'/';this.callback=undefined;}
 async request(value,fields,options={}){
  let url=new URL(value,this.document),method=fields?'POST':'GET',body=fields?new URLSearchParams(fields).toString():undefined;
  let requestOrigin=options.origin??new URL(this.document).origin;
  for(let step=0;step<16;step++){
   if(![this.origin,nodes.a.issuer].includes(url.origin)||url.protocol!=='https:')throw Error('Browser refused unexpected endpoint');
   const headers={Cookie:[...this.cookies.values()].filter(c=>url.pathname.startsWith(c.path)).map(c=>c.pair).join(';')};
   if(body!==undefined){headers['Content-Type']='application/x-www-form-urlencoded';headers.Origin=requestOrigin;}
   const response=await fetch(url,{method,headers,body,redirect:'manual',signal:AbortSignal.timeout(10000)});
   for(const value of response.headers.getSetCookie()){
    const [pair,...parts]=value.split(';'),[name,...rest]=pair.split('='),path=parts.find(p=>/^\s*path=/i.test(p))?.trim().slice(5)??'/';
    const key=name+'|'+path;if(parts.some(p=>/^\s*max-age=0$/i.test(p)))this.cookies.delete(key);else this.cookies.set(key,{pair:name+'='+rest.join('='),path});
   }
   if([301,302,303,307,308].includes(response.status)&&response.headers.has('location')){
    const next=new URL(response.headers.get('location'),url);
    if(next.origin===this.origin&&next.pathname==='/callback'){this.callback=next.href;if(options.captureCallback){return{status:response.status,html:'',url:url.href};}}
    if(options.noRedirect)return{status:response.status,html:await response.text(),url:url.href,location:next.href};
    if([301,302,303].includes(response.status)){method='GET';body=undefined;}url=next;continue;
   }
   const html=await response.text();this.document=url.href;return{status:response.status,html,url:url.href};
  }
  throw Error('Browser redirect limit');
 }
 submit(form,fields={},options={}){return this.request(new URL(form.action,this.document).href,{...form.fields,...fields},options);}
}
