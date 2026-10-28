import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { AuthError } from './jwt.ts';
export class InputError extends Error { constructor(message='Invalid request'){super(message);this.name='InputError';} }
export const envUrl = (key:string,fallback:string):string=>process.env[key]||fallback;
export const getBearer = (req:IncomingMessage):string => {
  const val=req.headers.authorization;
  if(typeof val!=='string' || !/^Bearer [A-Za-z0-9_.-]+$/.test(val)) throw new AuthError('Bearer token required');
  return val.slice(7);
};
export const json = (res:ServerResponse, code:number, value:unknown)=>{
  const body=JSON.stringify(value);
  res.writeHead(code,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
  res.end(body);
};
export async function body(req:IncomingMessage, maxBytes=128_000):Promise<Record<string,unknown>> {
  let data='';for await(const chunk of req){data+=chunk;if(Buffer.byteLength(data)>maxBytes) throw new InputError('Request too large');}
  if(!data) return {};
  try{
    if((req.headers['content-type']||'').startsWith('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(data));
    if(!(req.headers['content-type']||'').startsWith('application/json')) throw new InputError('Expected JSON');
    const v=JSON.parse(data);if(!v || typeof v!=='object' || Array.isArray(v)) throw new InputError('Expected JSON object');return v;
  }catch(e){if(e instanceof InputError)throw e;throw new InputError('Bad JSON');}
}
export function str(obj:Record<string,unknown>, field:string):string {
  const v=obj[field]; if(typeof v!=='string'||!v||v.length>8192) throw new InputError(`Missing/invalid ${field}`);return v;
}
export function startServer(port:number, route:(req:IncomingMessage,res:ServerResponse)=>Promise<void>):void {
  if(process.env.DEMO_ONLY!=='true') throw Error('DEMO_ONLY=true required. Not a production HTTP service.');
  createServer(async(req,res)=>{
    try{
      if(req.url==='/healthz' && req.method==='GET'){json(res,200,{ok:true});return;}
      await route(req,res);
    }catch(e){
      const err=e as Error;
      const code=e instanceof AuthError?403:e instanceof InputError?400:502;
      // Never return stack traces or credentials to clients.
      json(res,code,{error:code===502?'upstream_or_server_failure':err.message});
      if(code===502) console.error(err.name,err.message);
    }
  }).listen(port,process.env.HOST||'127.0.0.1',()=>console.log(`DEMO service on ${process.env.HOST||'127.0.0.1'}:${port}`));
}
export async function postJson(url:string, value:Record<string,unknown>,headers:Record<string,string>={}):Promise<Record<string,unknown>>{
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(value),signal:AbortSignal.timeout(5000)});
  const result=await r.json();if(!r.ok) throw new AuthError(`Downstream refused request: ${(result as Record<string,unknown>).error||r.status}`);
  return result as Record<string,unknown>;
}
export async function tokenExchange(url:string,params:Record<string,string>):Promise<string>{
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(params),signal:AbortSignal.timeout(5000)});
  const result=await r.json() as Record<string,unknown>;
  if(!r.ok || typeof result.access_token!=='string') throw new AuthError('Token exchange rejected');
  return result.access_token;
}
