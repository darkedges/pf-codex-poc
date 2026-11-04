import {buildCurlConfig} from './curl-capture.mjs';
export function captureVaultPath(id){if(!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id))throw Error('Invalid retained capture ID');return '/federated-copilot-tool-secrets/data/provider-debug/'+id;}
export function createVaultCaptureWriter(id,token,call){
 const path=captureVaultPath(id);let saved,version=0;
 const write=async data=>{
  try{const result=await call(path,{method:'POST',token:token(),body:{options:{cas:version},data}});if(result.status!==200||result.value?.data?.version!==version+1)throw Error();version++;return{path,version};}catch{throw Error('Private capture unavailable');}
 };
 return{
  async request(url,init){
   if(version!==0)throw Error('Private capture already started');buildCurlConfig(url,init);
   saved={schemaVersion:1,purpose:'user-approved-original-token-and-signed-url-retention',capturedAt:new Date().toISOString(),state:'request-retained-before-send',request:{method:'POST',url,headers:Object.fromEntries(new Headers(init.headers)),body:String(init.body)}};
   return write(saved);
  },
  async response(rawResponse,timing){if(version!==1||typeof rawResponse!=='string'||rawResponse.length>262144)throw Error('Private capture response unavailable');return write({...saved,state:'request-and-response-retained',rawResponse,timing});}
 };
}
export async function executeRetainedPost(writer,url,init,send,observation){
 await writer.request(url,init);
 const startedAt=Date.now(),monotonic=performance.now(),result=send();
 const receivedAt=Date.now();const timing={postStartedAt:new Date(startedAt).toISOString(),responseReceivedAt:new Date(receivedAt).toISOString()};if(observation){timing.cardObservedAt=new Date(observation.wall).toISOString();timing.cardToPostMilliseconds=Math.round((monotonic-observation.monotonic)*1000)/1000;}await writer.response(result.rawResponse,timing);
 return{...result,startedAt,monotonic,receivedAt};
}
