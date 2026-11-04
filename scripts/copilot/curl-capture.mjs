import {spawnSync} from 'node:child_process';
const origin='https://token.botframework.com';
function target(value){const u=new URL(value);if(u.origin!==origin||u.pathname!=='/api/sas/postToken'||u.username||u.password||u.hash||/[\r\n\0]/.test(value)||[...u.searchParams.keys()].sort().join()!=='expiry,hmac,id,state')throw Error('Unapproved curl capture destination');return u;}
function quote(value){if(/[\r\n\0]/.test(value))throw Error('Invalid curl configuration value');return '"'+value.replaceAll('\\','\\\\').replaceAll('"','\\"')+'"';}
export function buildCurlConfig(url,init){
 target(url);const headers=new Headers(init.headers);if(init.method!=='POST'||headers.get('content-type')!=='application/json'||headers.has('accept')&&headers.get('accept')!=='application/json'||[...headers.keys()].some(k=>!['accept','content-type'].includes(k)))throw Error('Unapproved curl request');
 const body=JSON.parse(String(init.body));if(Object.keys(body).join()!=='token'||typeof body.token!=='string'||!body.token||body.token.length>16000)throw Error('Invalid curl token body');
 return ['url = '+quote(url),'request = "POST"',...[...headers].map(([k,v])=>'header = '+quote(k+': '+v)),'data-binary = '+quote(JSON.stringify(body))].join('\n')+'\n';
}
export function parseCurlResponse(raw){
 if(typeof raw!=='string'||raw.length>262144)throw Error('Curl response unavailable');
 const marker=/\n__CAPTURE_HTTP_STATUS__(\d{3})\n?$/.exec(raw);if(!marker)throw Error('Curl status missing');let remaining=raw.slice(0,marker.index),last;
 while(/^HTTP\//.test(remaining)){
  const split=/\r?\n\r?\n/.exec(remaining);if(!split)throw Error('Curl headers incomplete');const lines=remaining.slice(0,split.index).split(/\r?\n/),status=/^HTTP\/(\S+) (\d{3})(?: (.*))?$/.exec(lines.shift());if(!status)throw Error('Curl status invalid');const headers=new Headers();
  for(const line of lines){const at=line.indexOf(':');if(at<1)throw Error('Curl header invalid');headers.append(line.slice(0,at),line.slice(at+1).trim());}
  last={httpVersion:status[1],status:Number(status[2]),statusText:status[3]??'',headers};remaining=remaining.slice(split.index+split[0].length);
 }
 if(!last||last.status!==Number(marker[1]))throw Error('Curl status mismatch');return{...last,body:remaining};
}
export function redactCapture({url,requestHeaders,response,secrets,tokenProfile,timing}){
 const u=target(url),values=new Set(secrets.filter(v=>typeof v==='string'&&v.length));values.add(url);
 for(const cookie of response.headers.getSetCookie()){const at=cookie.indexOf('=');if(at>=0){const value=cookie.slice(at+1).split(';')[0];if(value)values.add(value);}}
 for(const [name,value] of u.searchParams){if(value){values.add(value);values.add(encodeURIComponent(value));const encoded=new RegExp('(?:^|&)'+name+'=([^&]*)').exec(u.search.slice(1))?.[1];if(encoded)values.add(encoded);}}
 let redactions=0;const scrub=text=>{let out=String(text);for(const value of [...values].sort((a,b)=>b.length-a.length))if(out.includes(value)){out=out.split(value).join('[REDACTED]');redactions++;}out=out.replace(/eyJ[A-Za-z0-9_-]{7,}(?:\.[A-Za-z0-9_-]+){2,4}/g,()=>{redactions++;return'[REDACTED_JWT]';}).replace(/(Bearer\s+)[A-Za-z0-9._~+\/-]+=*/gi,'$1[REDACTED]').replace(/("(?:access_token|refresh_token|id_token|token|client_secret|hmac|sig|state|code|cookie)"\s*:\s*)"(?:\\.|[^"\\])*"/gi,(_m,prefix)=>{redactions++;return prefix+'"[REDACTED]"';}).replace(/((?:[?&]|&amp;)(?:expiry|hmac|id|state|sig|code|access_token)=)[^&\s"'<>]*/gi,(_m,prefix)=>{redactions++;return prefix+'[REDACTED]';});return out;};
 const allowed=['date','content-type','content-length','x-ms-request-id','x-ms-correlation-request-id','request-id','server','cache-control','pragma','strict-transport-security','x-content-type-options','x-powered-by'];const headers={};
 for(const name of allowed){const value=response.headers.get(name);if(value!==null)headers[name]=scrub(value);}
 const before=redactions,body=scrub(response.body);
 return{schemaVersion:1,request:{method:'POST',endpoint:origin+'/api/sas/postToken',queryParameterNames:[...u.searchParams.keys()],signedQueryValues:'REDACTED',headers:Object.fromEntries(new Headers(requestHeaders)),automaticallyAddedRequestHeadersCaptured:false,body:{token:'[REDACTED_CONFIGURED_PROVIDER_USER_TOKEN]'},tokenProfile},response:{httpVersion:response.httpVersion,status:response.status,statusText:scrub(response.statusText),headers,omittedHeaderNames:[...response.headers.keys()].filter(k=>!allowed.includes(k)),body,bodyRedacted:redactions>before},timing,rawCredentialsRetained:false};
}
export function curlTokenPost(url,init){
 const config=buildCurlConfig(url,init);init.signal?.throwIfAborted();
 // --disable must be first: never load a curlrc that could add auth/redirects.
 // Signed URL and token travel only in process stdin, never arguments/files.
 const child=spawnSync(process.platform==='win32'?'curl.exe':'curl',['--disable','--silent','--show-error','--include','--max-time','10','--connect-timeout','5','--retry','0','--max-filesize','16384','--proto','=https','--write-out','\n__CAPTURE_HTTP_STATUS__%{http_code}\n','--config','-'],{input:config,encoding:'utf8',windowsHide:true,timeout:12000,maxBuffer:262144,stdio:['pipe','pipe','pipe']});
 if(child.error||child.status!==0)throw Error('Single curl token POST failed; no retry allowed');
 const parsed=parseCurlResponse(child.stdout),response=new Response([204,205,304].includes(parsed.status)?null:parsed.body,{status:parsed.status,statusText:parsed.statusText,headers:parsed.headers});const marker=/\n__CAPTURE_HTTP_STATUS__\d{3}\n?$/.exec(child.stdout);return{parsed,response,rawResponse:child.stdout.slice(0,marker.index)};
}
