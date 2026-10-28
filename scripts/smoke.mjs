const PFA=process.env.PF_A_URL||'http://127.0.0.1:9201';
const GW=process.env.GATEWAY_1_URL||'http://127.0.0.1:9301';
async function post(url,data){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});return {status:r.status,json:await r.json()};}
const u=await post(PFA+'/dev/issue',{kind:'user'});
const a=await post(PFA+'/dev/issue',{kind:'agent'});
if(u.status!==200||a.status!==200)throw Error('Mock credentials could not be issued');
const basic={agent_token:a.json.access_token,grant_id:'grant-demo',operation:'documents.search',resource:'sharepoint:approved-research',query:'policy'};
const interactive=await post(GW+'/v1/invoke',{...basic,user_token:u.json.access_token,mode:'interactive'});
const autonomous=await post(GW+'/v1/invoke',{...basic,user:'partner-a:user-123',mode:'autonomous'});
const revoked=await post(GW+'/v1/invoke',{...basic,grant_id:'grant-revoked',mode:'interactive',user_token:u.json.access_token});
const unauthorized=await post(GW+'/v1/invoke',{...basic,resource:'sharepoint:finance',mode:'interactive',user_token:u.json.access_token});
console.log(JSON.stringify({interactive,autonomous,revoked,unauthorized},null,2));
if(interactive.status!==200||autonomous.status!==200||revoked.status===200||unauthorized.status===200) process.exitCode=1;
