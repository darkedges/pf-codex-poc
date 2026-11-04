import {existsSync} from 'node:fs';
import {loadToolRuntime} from './tool-runtime.ts';

// Docker publishes the container's 8443 only on host loopback. A direct host
// launch stays on loopback and cannot opt into 0.0.0.0 without container context.
let server:Awaited<ReturnType<typeof loadToolRuntime>>['server']|undefined;
try{
 const host=process.env.TOOL_BIND_ADDRESS??'127.0.0.1';
 if(!['127.0.0.1','0.0.0.0'].includes(host)||host==='0.0.0.0'&&!existsSync('/.dockerenv'))throw Error();
 const runtime=await loadToolRuntime(process.env,{observe:event=>console.log(JSON.stringify(event))});server=runtime.server;
 server.on('error',()=>{console.error('Tool HTTPS listener unavailable');process.exitCode=1;});
 server.listen(8443,host,()=>console.log(JSON.stringify({event:'tool_runtime_started',transport:'https-mtls',diagnosticOnly:true})));
 const stop=()=>{if(!server)return;server.beginDrain();const deadline=setTimeout(()=>{server?.closeAllConnections();process.exitCode=1;},5000);deadline.unref();server.close(()=>{clearTimeout(deadline);process.exitCode=0;});};
 process.once('SIGTERM',stop);process.once('SIGINT',stop);
}catch{console.error('Tool runtime configuration rejected');process.exitCode=1;}
