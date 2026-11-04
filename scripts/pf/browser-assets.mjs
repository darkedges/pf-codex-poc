const publicOrigin='https://pf-a.copilot.darkedges.com';
const decode=s=>s.replace(/&amp;/g,'&');
export function browserAssets(content,base,css=false){
 let document=new URL(base);if(document.origin!==publicOrigin)throw Error('Unapproved browser review origin');
 if(!css){const element=content.match(/<base\b[^>]*\bhref\s*=\s*["']([^"']+)["']/i);if(element){document=new URL(decode(element[1]),document);if(document.origin!==publicOrigin||document.username||document.password||document.hash||document.search)throw Error('Unapproved browser base');}}
 const refs=css?[...content.matchAll(/url\(\s*["']?([^\s"')]+)["']?\s*\)/gi)].map(m=>m[1]):[...content.matchAll(/(?:src|href)\s*=\s*["']([^"']+)["']/gi)].map(m=>m[1]);
 const urls=[];
 for(const ref of refs){
  if(ref.startsWith('#')||ref.startsWith('data:'))continue;
  let url;try{url=new URL(decode(ref),document);}catch{throw Error('Malformed browser resource');}
  if(css){url.hash='';if(!url.search)url.search='';}
  // HTML links that are not resources (for example password-reset anchors)
  // are not followed by this diagnostic. CSS URLs are always resource inputs.
  if(!css&&!/\.(?:css|js|png|svg|ico|gif|jpe?g|woff2?|ttf)(?:$)/i.test(url.pathname))continue;
  if(url.origin!==publicOrigin||url.username||url.password||url.hash||!/^\/assets\/[A-Za-z0-9_./-]+$/.test(url.pathname)||url.pathname.includes('//')){
   const error=Error('Unapproved browser resource');error.resourceOrigin=url.origin;error.assetName=url.pathname.split('/').at(-1);error.resourcePath=url.pathname.replace(/^\/as\/[A-Za-z0-9_-]+\/resume\//,'/as/{transaction}/resume/');throw error;
  }
  urls.push(url.href);
 }
 if(urls.length>50)throw Error('Browser resource count exceeded');
 return[...new Set(urls)];
}
export function cookieAttributes(value){
 const [pair,...attributes]=value.split(';'),name=pair.split('=')[0];
 const parts=attributes.map(a=>a.trim()),field=key=>parts.find(p=>p.toLowerCase().startsWith(key.toLowerCase()+'='))?.slice(key.length+1);
 return{name,secure:parts.some(p=>p.toLowerCase()==='secure'),httpOnly:parts.some(p=>p.toLowerCase()==='httponly'),sameSite:field('SameSite')??null,domain:field('Domain')??null,path:(field('Path')??'/').replace(/^\/as\/[A-Za-z0-9_-]+\/resume\//,'/as/{transaction}/resume/')};
}
