export function backendRoute(method,path){
 if(method==='GET'&&path==='/pf/JWKS')return'jwks';
 if(method==='POST'&&path==='/v1/decisions')return'decision';
 if(method==='POST'&&path==='/v1/health')return'health';
 return undefined;
}
