import { body, getBearer, json, startServer, str, postJson, envUrl } from '../lib/http.ts';
import { createGateway2Exchange } from '../adapters/gateway-2.ts';
// This HTTP host remains demo-only. A production host must inject an authoritative policy API.
if (process.env.GATEWAY2_EXCHANGE_MODE && process.env.GATEWAY2_EXCHANGE_MODE !== 'mock') throw Error('Production exchange requires a production host and online policy dependency');
const exchange = await createGateway2Exchange({ mode: 'mock' });
const broker=envUrl('BROKER_URL','http://127.0.0.1:9400');
startServer(9302,async(req,res)=>{
  if(req.method==='POST' && req.url==='/v1/ingress'){
    const original=getBearer(req);
    const { accessToken: token } = await exchange.exchange(original);
    const b=await body(req);
    // Never accept sub/act from the JSON request; derive from cryptographically verified claims.
    const output=await postJson(broker+'/v1/execute',{operation:str(b,'operation'),resource:str(b,'resource'),query:String(b.query||'')},{Authorization:`Bearer ${token}`});
    json(res,200,output);return;
  }
  json(res,404,{error:'Not found'});
});
