type Config={siteId:string;siteUrl:string;tenantId:string;authorityJwks:{keys:unknown[]}};
import type {MobileUsageKind} from './usage.ts';
type Transports={publicFetch:typeof fetch;localFetch:typeof fetch;guard?:()=>void;signal?:AbortSignal;reserve?:(kind:MobileUsageKind)=>void};
const fail=()=>Error('mobile_network_denied');
/** Independent egress gate. Resource adapters still validate discovered IDs,
 * current authorization and signed redirects. No URL comes from a chat prompt. */
export function mobileNetwork(c:Config,t:Transports):typeof fetch{
 const site=new URL(c.siteUrl);if(site.protocol!=='https:'||!site.hostname.endsWith('.sharepoint.com')||site.username||site.password||site.search||site.hash||!c.siteId.startsWith(site.hostname+',')||!/^[a-f0-9-]{36}$/.test(c.tenantId)||!Array.isArray(c.authorityJwks?.keys))throw fail();
 return async(url,init)=>{
  t.guard?.();t.signal?.throwIfAborted();const raw=String(url),u=new URL(raw),method=(init?.method??'GET').toUpperCase(),headers=new Headers(init?.headers);
  if(u.protocol!=='https:'||u.username||u.password||u.hash||init?.redirect==='follow'||headers.has('cookie'))throw fail();
  const signal=AbortSignal.any([...(t.signal?[t.signal]:[]),...(init?.signal?[init.signal]:[])]);
  if(raw==='https://partner-a.test/mobile-authority/jwks'){if(method!=='GET'||headers.has('authorization'))throw fail();return Response.json(c.authorityJwks);}
  let local=false,allowed=false;
  if(['https://localhost:9033','https://localhost:9034'].includes(u.origin)){local=true;allowed=method==='GET'&&u.pathname==='/pf/JWKS'&&!u.search||method==='POST'&&u.pathname==='/as/token.oauth2'&&!u.search;}
  else if(u.origin==='https://pf-a.copilot.darkedges.com')allowed=method==='GET'&&u.pathname==='/pf/JWKS'&&!u.search||method==='POST'&&['/as/token.oauth2','/as/par.oauth2'].includes(u.pathname)&&!u.search;
  else if(u.origin==='https://login.microsoftonline.com')allowed=method==='POST'&&u.pathname==='/'+c.tenantId+'/oauth2/v2.0/token'&&!u.search;
  else if(u.origin==='https://graph.microsoft.com')allowed=method==='GET'&&(decodeURIComponent(u.pathname)==='/v1.0/sites/'+c.siteId+'/drives'||/^\/v1\.0\/drives\/[A-Za-z0-9_!-]{1,200}\/(?:root\/children|items\/[A-Za-z0-9_!-]{1,200}(?:\/(?:children|content))?)$/.test(u.pathname));
  else if(u.origin===site.origin)allowed=method==='GET'&&!headers.has('authorization')&&['/_layouts/15/download.aspx',site.pathname+'/_layouts/15/download.aspx'].includes(u.pathname);
  else if(u.origin==='https://directline.botframework.com'){
   const activities=/^\/v3\/directline\/conversations\/[A-Za-z0-9_-]{1,200}\/activities$/.test(u.pathname);
   const watermark=[...u.searchParams.keys()].join()==='watermark'&&u.searchParams.getAll('watermark').length===1&&Boolean(u.searchParams.get('watermark'))&&u.searchParams.get('watermark')!.length<=512&&!/[\u0000-\u001f\u007f]/.test(u.searchParams.get('watermark')!);
   allowed=activities&&method==='GET'&&(!u.search||watermark)||!u.search&&method==='POST'&&(activities||['/v3/directline/tokens/generate','/v3/directline/tokens/refresh','/v3/directline/conversations'].includes(u.pathname));
  }
  else if(u.origin==='https://token.botframework.com')allowed=method==='POST'&&u.pathname==='/api/sas/postToken'&&!headers.has('authorization');
  if(u.origin==='https://graph.microsoft.com'){
   const select=new Set(['id','name','size','eTag','file','folder','remoteItem','deleted','parentReference','sharepointIds','driveType','webUrl']);
   if([...u.searchParams.keys()].some(k=>!['$select','$top','$skiptoken'].includes(k)||u.searchParams.getAll(k).length!==1)||u.searchParams.has('$top')&&u.searchParams.get('$top')!=='50'||u.searchParams.has('$select')&&u.searchParams.get('$select')!.split(',').some(k=>!select.has(k)))throw fail();
  }
  if(!allowed)throw fail();let kind:MobileUsageKind|undefined;
  if(local&&method==='POST')kind='pf_token';else if(u.origin==='https://login.microsoftonline.com')kind='graph_token';else if(u.origin==='https://graph.microsoft.com')kind='graph_get';else if(u.origin===site.origin)kind='download';else if(u.origin==='https://token.botframework.com')kind='token_post';else if(u.origin==='https://directline.botframework.com'){kind=u.pathname.endsWith('/tokens/generate')||u.pathname.endsWith('/tokens/refresh')?'directline_token':u.pathname==='/v3/directline/conversations'?'conversation':method==='POST'?'activity_post':'activity_get';}
  if(kind)t.reserve?.(kind);return(local?t.localFetch:t.publicFetch)(raw,{...init,redirect:init?.redirect==='manual'?'manual':'error',credentials:'omit',signal});
 };
}
