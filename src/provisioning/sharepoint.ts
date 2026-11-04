import {createHash} from 'node:crypto';
const graphApp='00000003-0000-0000-c000-000000000000',selectedRole='883ea226-0bf2-4a8f-9f9d-92c9162a727d';
const appName='copilot-m365-resource-broker';
const guid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(v)&&!/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(v);
export class SharePointSetupError extends Error{constructor(code:string){super(code);this.name='SharePointSetupError';}}
type Config={tenantId:string;adminUser:string;siteUrl:string;siteId:string;graphServicePrincipalId:string};
export type SharePointSetupReceipt={planHash:string;status:string;appObjectId?:string;appId?:string;servicePrincipalId?:string;sitePermissionId?:string};
export type SharePointSetupDependencies={identity:()=>Promise<{tenantId:string;user:string}>;request:(method:'GET'|'POST',path:string,body?:unknown)=>Promise<any>;read:()=>Promise<SharePointSetupReceipt|undefined>;write:(receipt:SharePointSetupReceipt)=>Promise<void>;lock:<T>(fn:()=>Promise<T>)=>Promise<T>};
export function planSharePointSetup(value:unknown){
 try{
 const c=value as Config;if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).sort().join(',')!=='adminUser,graphServicePrincipalId,siteId,siteUrl,tenantId'||!guid(c.tenantId)||!guid(c.graphServicePrincipalId)||typeof c.adminUser!=='string'||!/^[a-z0-9._-]+@[a-z0-9-]+\.onmicrosoft\.com$/.test(c.adminUser)||typeof c.siteUrl!=='string'||!/^https:\/\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.sharepoint\.com\/sites\/[A-Za-z0-9_-]+$/.test(c.siteUrl))throw Error();
 const url=new URL(c.siteUrl),parts=c.siteId?.split(',');if(parts?.length!==3||parts[0]!==url.hostname||!guid(parts[1])||!guid(parts[2]))throw Error();
 const requested={tenantId:c.tenantId,adminUser:c.adminUser,siteUrl:c.siteUrl,siteId:c.siteId,graphServicePrincipalId:c.graphServicePrincipalId};
 const application={displayName:appName,signInAudience:'AzureADMyOrg',requiredResourceAccess:[{resourceAppId:graphApp,resourceAccess:[{id:selectedRole,type:'Role'}]}]} as const;
 return{requested,application,siteRoles:['read'] as const,credentialCreation:false,liveVerified:false,hash:createHash('sha256').update(JSON.stringify({requested,application,siteRoles:['read'],credentialCreation:false})).digest('hex')};
 }catch{throw new SharePointSetupError('invalid_configuration');}
}
function collection(v:any){if(!v||!Array.isArray(v.value)||v['@odata.nextLink']||v.value.length>100)throw new SharePointSetupError('response_invalid');return v.value;}
function permission(v:any,appId:string){const identities=v?.grantedToIdentitiesV2??v?.grantedToIdentities;return typeof v?.id==='string'&&v.id.length>0&&v.id.length<=500&&JSON.stringify(v.roles)==='["read"]'&&Array.isArray(identities)&&identities.length===1&&identities[0]?.application?.id===appId&&!identities[0]?.user;}
// Operator-only provisioning. No data-plane transport, token acquisition or credential creation.
// Durable intent precedes every mutation. Any existing receipt blocks reapplication,
// including a lost response; an operator must independently reconcile partial setup.
export async function applySharePointSetup(value:unknown,approvedHash:string,deps:SharePointSetupDependencies){
 const plan=planSharePointSetup(value),c=plan.requested;if(approvedHash!==plan.hash)throw new SharePointSetupError('plan_approval_required');
 return deps.lock(async()=>{
 let receipt:SharePointSetupReceipt|undefined,mutationStarted=false;
 const identity=async()=>{const i=await deps.identity();if(i.tenantId!==c.tenantId||i.user!==c.adminUser)throw new SharePointSetupError('wrong_identity');};
 try{
 if(await deps.read())throw new SharePointSetupError('existing_setup_requires_review');await identity();
 const sitePath='/sites/'+c.siteId,site=await deps.request('GET',sitePath+'?$select=id,webUrl');if(site?.id!==c.siteId||site.webUrl!==c.siteUrl)throw new SharePointSetupError('site_mismatch');
 const graph=await deps.request('GET','/servicePrincipals/'+c.graphServicePrincipalId);const roles=graph?.appRoles?.filter((r:any)=>r.value==='Sites.Selected');
 if(graph?.id!==c.graphServicePrincipalId||graph.appId!==graphApp||roles?.length!==1||roles[0].id!==selectedRole||roles[0].isEnabled!==true||!roles[0].allowedMemberTypes?.includes('Application'))throw new SharePointSetupError('graph_role_mismatch');
 if(collection(await deps.request('GET',"/applications?$filter="+encodeURIComponent("displayName eq '"+appName+"'")+"&$select=id,appId")).length)throw new SharePointSetupError('existing_app_not_approved');
 const mutate=async(status:string,path:string,body:unknown)=>{await identity();receipt={...receipt,planHash:plan.hash,status};await deps.write(receipt);mutationStarted=true;return deps.request('POST',path,body);};
 const app=await mutate('app-create-intent','/applications',plan.application);if(!guid(app?.id)||!guid(app?.appId))throw Error();receipt={...receipt!,appObjectId:app.id,appId:app.appId};await deps.write(receipt);
 const sp=await mutate('service-principal-intent','/servicePrincipals',{appId:app.appId});if(!guid(sp?.id)||sp.appId!==app.appId)throw Error();receipt={...receipt!,servicePrincipalId:sp.id};await deps.write(receipt);
 const assignment={principalId:sp.id,resourceId:c.graphServicePrincipalId,appRoleId:selectedRole};
 const assigned=await mutate('selected-role-intent','/servicePrincipals/'+sp.id+'/appRoleAssignments',assignment);if(Object.entries(assignment).some(([k,v])=>assigned?.[k]!==v))throw Error();
 const granted=await mutate('site-read-intent',sitePath+'/permissions',{roles:['read'],grantedToIdentities:[{application:{id:app.appId,displayName:appName}}]});if(!permission(granted,app.appId))throw Error();receipt={...receipt!,sitePermissionId:granted.id};await deps.write(receipt);
 await identity();const assignments=collection(await deps.request('GET','/servicePrincipals/'+sp.id+'/appRoleAssignments'));if(assignments.length!==1||Object.entries(assignment).some(([k,v])=>assignments[0]?.[k]!==v))throw Error();
 const permissions=collection(await deps.request('GET',sitePath+'/permissions')).filter((p:any)=>[...(p.grantedToIdentitiesV2??[]),...(p.grantedToIdentities??[])].some((i:any)=>i?.application?.id===app.appId));if(permissions.length!==1||permissions[0].id!==granted.id||!permission(permissions[0],app.appId))throw Error();
 const readback=await deps.request('GET','/applications/'+app.id+'?$select=id,appId,signInAudience,requiredResourceAccess,passwordCredentials,keyCredentials,web,spa,publicClient');
 if(readback?.id!==app.id||readback.appId!==app.appId||readback.signInAudience!=='AzureADMyOrg'||JSON.stringify(readback.requiredResourceAccess)!==JSON.stringify(plan.application.requiredResourceAccess)||!Array.isArray(readback.passwordCredentials)||readback.passwordCredentials.length||!Array.isArray(readback.keyCredentials)||readback.keyCredentials.length||['web','spa','publicClient'].some(k=>!Array.isArray(readback[k]?.redirectUris)||readback[k].redirectUris.length))throw Error();
 await identity();receipt={...receipt!,status:'ready-without-credential'};await deps.write(receipt);return{status:receipt.status,planHash:plan.hash,appId:app.appId,servicePrincipalId:sp.id,sitePermissionId:granted.id,siteUrl:c.siteUrl,graphDataAccessVerified:false};
 }catch(e){if(mutationStarted)throw new SharePointSetupError('setup_uncertain');throw e instanceof SharePointSetupError?e:new SharePointSetupError('preflight_unavailable');}
 });
}
