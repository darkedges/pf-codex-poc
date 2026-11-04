// Fixed TCP tunnel only: TLS terminates at the existing tool, never here.
import {createServer,createConnection} from 'node:net';
const sockets=new Set();let closing=false;
const server=createServer(incoming=>{if(closing||sockets.size>=64){incoming.destroy();return;}const outgoing=createConnection({host:'tool-api',port:8443});for(const socket of [incoming,outgoing]){sockets.add(socket);socket.setTimeout(10000,()=>socket.destroy());socket.on('error',()=>{incoming.destroy();outgoing.destroy();});socket.on('close',()=>{sockets.delete(socket);incoming.destroy();outgoing.destroy();});}const deadline=setTimeout(()=>{incoming.destroy();outgoing.destroy();},20000);incoming.on('close',()=>clearTimeout(deadline));incoming.pipe(outgoing).pipe(incoming);});
server.maxConnections=32;server.on('error',()=>{console.error('Private tool forwarding unavailable');process.exitCode=1;});
server.listen(8443,'0.0.0.0',()=>console.log(JSON.stringify({ready:true,fixedTarget:'tool-api:8443',tlsTerminated:false})));
const stop=()=>{closing=true;server.close(()=>process.exit(0));for(const socket of sockets)socket.destroy();};process.once('SIGTERM',stop);process.once('SIGINT',stop);
