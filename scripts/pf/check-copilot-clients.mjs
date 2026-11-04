import {admin} from './common.mjs';
const args=process.argv.slice(2);
if(args.length>1||args.some(a=>a!=='--login-enabled'))throw Error('Select disabled staging or --login-enabled state');
for(const [node,id]of [['a','copilot-studio-generic-oauth'],['b','copilot-sso-exchange']]){
 const client=await admin(node,'oauth/clients/'+id);
 const expected=node==='a'&&args[0]==='--login-enabled';
 if(client.enabled!==expected)throw Error('Dedicated OAuth client state differs from the explicit lifecycle profile');
 console.log(JSON.stringify({node,clientId:id,enabled:client.enabled}));
}
