// Bounded diagnostic transport for the one approved public login origin.
export async function publicLoginRequest(value,fields,headers={},transport=fetch){
 try{
  const url=new URL(value);
  if(url.origin!=='https://pf-a.copilot.darkedges.com'||url.username||url.password||url.hash||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
  const body=fields?new URLSearchParams(fields).toString():undefined;
  const response=await transport(url.href,{method:body?'POST':'GET',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{...headers,...(body?{'Content-Type':'application/x-www-form-urlencoded'}:{})},body});
  let html='';for await(const part of response.body??[]){html+=Buffer.from(part).toString('utf8');if(html.length>2_000_000)throw Error();}
  let result;try{result=JSON.parse(html);}catch{}
  return{status:response.status,html,value:result,location:response.headers.get('location')??undefined,cookies:response.headers.getSetCookie(),contentType:response.headers.get('content-type'),cacheControl:response.headers.get('cache-control')};
 }catch{throw Error('Public PF login request failed');}
}
