import { CopilotError,type CopilotAdapter } from '../adapters/copilot.ts';
type Input={method:string;path:string;authorization:string;rawBody:string};
export class CopilotApi {
 private adapter:CopilotAdapter;
 constructor(adapter:CopilotAdapter){if((['open','send','poll','refresh','close']as const).some(k=>typeof adapter?.[k]!=='function'))throw new CopilotError('configuration');this.adapter=adapter;}
 async handle(input:Input):Promise<{status:number;body:Record<string,unknown>}>{
  try{
   const match=/^Bearer ([^\s]{1,16000})$/.exec(input.authorization);if(!match)throw new CopilotError('invalid_token');const raw=match[1];
   if(input.path.length>250||Buffer.byteLength(input.rawBody)>8192||!['POST','GET','DELETE'].includes(input.method))throw new CopilotError('invalid_request');
   let body:Record<string,unknown>={};
   if(input.method==='POST'){
    try{body=JSON.parse(input.rawBody||'{}');}catch{throw new CopilotError('invalid_request');}
    if(!body||typeof body!=='object'||Array.isArray(body))throw new CopilotError('invalid_request');
   }else if(input.rawBody)throw new CopilotError('invalid_request');
   if(input.path==='/v1/conversations'&&input.method==='POST'){
    if(Object.keys(body).length)throw new CopilotError('invalid_request');return{status:201,body:await this.adapter.open(raw)};
   }
   const route=/^\/v1\/conversations\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:\/(messages|activities|refresh))?$/.exec(input.path);
   if(!route)throw new CopilotError('invalid_request');const [,handle,action]=route;
   if(input.method==='POST'&&action==='messages'){
    if(Object.keys(body).length!==1||typeof body.text!=='string')throw new CopilotError('invalid_request');return{status:200,body:await this.adapter.send(handle,raw,body.text)};
   }
   if(Object.keys(body).length)throw new CopilotError('invalid_request');
   if(input.method==='GET'&&action==='activities')return{status:200,body:await this.adapter.poll(handle,raw)};
   if(input.method==='POST'&&action==='refresh')return{status:200,body:await this.adapter.refresh(handle,raw)};
   if(input.method==='DELETE'&&!action)return{status:200,body:await this.adapter.close(handle,raw)};
   throw new CopilotError('invalid_request');
  }catch(error){
   const code=error instanceof CopilotError?error.code:'unavailable';
   const status=code==='invalid_request'?400:['invalid_token','expired','sso_expired'].includes(code)?401:['policy_denied','session_denied'].includes(code)?403:code==='session_busy'?409:['oauth_invalid','challenge_replay','protocol_error'].includes(code)?502:503;
   return{status,body:{error:code}};
  }
 }
}
