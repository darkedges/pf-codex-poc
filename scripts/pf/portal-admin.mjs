import {call,load,nodes} from './common.mjs';
// Operator-only fixed client management. No raw vendor error response is logged.
export async function portalAdmin(node,path,method='GET',body){
 const allowed=node==='a'?['oauth/clients/copilot-consent-portal','oauth/clients/copilot-studio-generic-oauth']:node==='b'?['oauth/clients/copilot-sso-exchange']:[];
 if(!allowed.includes(path)||!['GET','PUT'].includes(method))throw Error('Unapproved PF portal administration');
 const result=await call(nodes[node].admin+'/pf-admin-api/v1/'+path,{method,body,admin:load('admin-'+node+'.json')});
 if(result.status<200||result.status>=300)throw Error('PF portal administration unverified');return result.value;
}
