import {buildCurlConfig} from './curl-capture.mjs';
export function retainedHttpPacket(data){
 if(data?.state!=='request-and-response-retained'||typeof data.rawResponse!=='string')throw Error('Complete private capture required');buildCurlConfig(data.request.url,{method:data.request.method,headers:data.request.headers,body:data.request.body});
 return ['PRIVATE ORIGINAL CAPTURE — for inspection, not authorization to replay.','Automatic cURL request headers were not captured.','',data.request.method+' '+data.request.url,...Object.entries(data.request.headers).map(([k,v])=>k+': '+v),'',data.request.body,'','--- Exact HTTP response returned by cURL ---',data.rawResponse].join('\n');
}
