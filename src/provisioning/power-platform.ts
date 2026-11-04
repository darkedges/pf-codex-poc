import { createHash } from 'node:crypto';
export class ProvisioningError extends Error {constructor(code:string){super(code);this.name='ProvisioningError';}}
type Config={tenantId:string|null;name:string;domain:string;region:string;type:'Sandbox'|'Developer';currency:string;language:number;securityGroupId:string|null;developerUser:string|null;environmentId:string|null;licenseAndCapacityReviewed:boolean};
type Environment={id:string;name:string;url:string;type:string};
export type ProvisioningReceipt={status:'creating'|'pending'|'uncertain'|'ready';tenantId:string;configHash:string;environment?:Environment};
export type ProvisioningDependencies={run:(args:string[],timeoutMs?:number)=>Promise<unknown>;read:()=>Promise<ProvisioningReceipt|undefined>;write:(receipt:ProvisioningReceipt)=>Promise<void>;lock:<T>(work:()=>Promise<T>)=>Promise<T>};
const object=(v:unknown):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const guid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(v)&&!/^0{8}(?:-0{4}){3}-0{12}$/.test(v);
const text=(v:unknown,max=200):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v);
const key=(v:string)=>v.toLowerCase().replace(/[^a-z0-9]/g,'');
function field(value:unknown,names:string[]):any{
 if(!object(value))return undefined;const matches=Object.entries(value).filter(([k])=>names.map(key).includes(key(k)));
 if(matches.length>1&&matches.some(([,v])=>JSON.stringify(v)!==JSON.stringify(matches[0][1])))throw new ProvisioningError('response_invalid');return matches[0]?.[1];
}
function configuration(value:unknown):Config{
 if(!object(value)||Object.keys(value).some(k=>!['tenantId','name','domain','region','type','currency','language','securityGroupId','developerUser','environmentId','licenseAndCapacityReviewed'].includes(k)))throw new ProvisioningError('invalid_configuration');
 const nullableGuid=(v:unknown)=>v==null?null:guid(v)?v.toLowerCase():(()=>{throw new ProvisioningError('invalid_configuration');})();
 if(!text(value.name,100)||!/^[A-Za-z0-9][A-Za-z0-9 ._()-]{2,99}$/.test(value.name)||!text(value.domain,50)||!/^[a-z][a-z0-9-]{1,48}[a-z0-9]$/.test(value.domain)||!text(value.region,40)||!/^[a-z][a-z0-9-]+$/.test(value.region)||!['Sandbox','Developer'].includes(value.type)||!text(value.currency,3)||!/^[A-Z]{3}$/.test(value.currency)||value.language!==1033||typeof value.licenseAndCapacityReviewed!=='boolean'||(value.developerUser!=null&&(!text(value.developerUser,254)||!/^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$/.test(value.developerUser))))throw new ProvisioningError('invalid_configuration');
 const c:Config={tenantId:nullableGuid(value.tenantId),name:value.name,domain:value.domain,region:value.region,type:value.type,currency:value.currency,language:value.language,securityGroupId:nullableGuid(value.securityGroupId),developerUser:value.developerUser??null,environmentId:nullableGuid(value.environmentId),licenseAndCapacityReviewed:value.licenseAndCapacityReviewed};
 if(c.type==='Developer'&&c.securityGroupId!==null||c.type==='Sandbox'&&c.developerUser!==null)throw new ProvisioningError('invalid_configuration');return c;
}
export function planEnvironment(value:unknown){
 const c=configuration(value),blockers:string[]=[];
 if(!c.tenantId)blockers.push('tenant_id_required');if(c.type==='Sandbox'&&!c.securityGroupId)blockers.push('security_group_required');if(c.type==='Developer'&&!c.developerUser)blockers.push('developer_owner_required');if(!c.licenseAndCapacityReviewed)blockers.push('license_and_capacity_review_required');
 const args=['admin','create','--name',c.name,'--domain',c.domain,'--region',c.region,'--type',c.type,'--currency',c.currency,'--language','English','--max-async-wait-time','15'];
 if(c.securityGroupId)args.push('--security-group-id',c.securityGroupId);if(c.developerUser)args.push('--user',c.developerUser);args.push('--json');
 return{action:'create-dataverse-environment' as const,tenantId:c.tenantId,requested:c,blockers,createArguments:args,hash:createHash('sha256').update(JSON.stringify(c)).digest('hex'),liveVerified:false};
}
function authentication(value:unknown){
 let properties:Record<string,unknown>;
 if(Array.isArray(value)){
  properties={};for(const row of value){if(!object(row)||!text(row.Key,100)||Object.hasOwn(properties,key(row.Key)))throw new ProvisioningError('response_invalid');properties[key(row.Key)]=row.Value;}
 }else if(object(value))properties=value;else throw new ProvisioningError('authentication_required');
 const tenant=field(properties,['tenantId']),user=field(properties,['user','userPrincipalName']),oid=field(properties,['Entra ID Object Id','objectId']);
 if(!guid(tenant)||!text(user,254))throw new ProvisioningError('authentication_required');
 return{tenant:tenant.toLowerCase(),user:user.toLowerCase(),fingerprint:JSON.stringify([tenant.toLowerCase(),user.toLowerCase(),guid(oid)?oid.toLowerCase():null])};
}
function summary(value:unknown):Environment{
 const id=field(value,['environmentId']),name=field(value,['environment','displayName','friendlyName']),url=field(value,['environmentUrl','url']),type=field(value,['type','environmentType','environmentSku']);
 if(!guid(id)||!text(name,100)||!text(url,500)||!text(type,50))throw new ProvisioningError('response_invalid');
 let endpoint:URL;try{endpoint=new URL(url);}catch{throw new ProvisioningError('response_invalid');}
 if(endpoint.protocol!=='https:'||!endpoint.hostname.endsWith('.dynamics.com')||endpoint.username||endpoint.password||endpoint.port||endpoint.pathname!=='/'||endpoint.search||endpoint.hash)throw new ProvisioningError('response_invalid');
 return{id:id.toLowerCase(),name,url:endpoint.href,type};
}
function summaries(value:unknown){if(!Array.isArray(value))throw new ProvisioningError('response_invalid');return value.map(summary);}
function verifyDetail(value:unknown,observed:Environment,c:Config){
 const p=field(value,['properties']),metadata=field(p,['linkedEnvironmentMetadata']),tenant=field(p,['tenantId'])??field(value,['tenantId']),id=field(value,['name','environmentId']),location=field(value,['location']),type=field(p,['environmentSku']),name=field(p,['displayName']);
 const url=field(metadata,['instanceUrl']),group=field(metadata,['securityGroupId']),state=field(metadata,['instanceState']),provisioning=field(p,['provisioningState']);
 if(!guid(id)||id.toLowerCase()!==observed.id||!guid(tenant)||tenant.toLowerCase()!==c.tenantId||location!==c.region||type!==c.type||name!==c.name||state!=='Ready'||provisioning!==undefined&&!['Succeeded','Ready'].includes(provisioning))throw new ProvisioningError('environment_drift');
 if(c.type==='Sandbox'&&(!guid(group)||group.toLowerCase()!==c.securityGroupId))throw new ProvisioningError('environment_drift');
 const checked=summary({EnvironmentId:id,Environment:name,EnvironmentUrl:url,Type:type});
 if(checked.url!==observed.url||new URL(checked.url).hostname.split('.')[0]!==c.domain)throw new ProvisioningError('environment_drift');
 const language=field(metadata,['baseLanguage','baseLanguageCode']),currency=field(field(metadata,['currency']),['code']),runtime=field(field(field(p,['states']),['runtime']),['id']);
 if(language!==undefined&&language!==c.language||currency!==undefined&&currency!==c.currency||runtime!==undefined&&runtime!=='Enabled')throw new ProvisioningError('environment_drift');
 return checked;
}
export async function provisionEnvironment(value:unknown,options:{apply?:boolean;approvedPlan?:string;inspect?:boolean},dependencies:ProvisioningDependencies){
 try{
 const plan=planEnvironment(value),c=plan.requested;if(!options.apply&&!options.inspect)return{status:'planned',plan};
 if(options.apply&&(options.approvedPlan!==plan.hash))throw new ProvisioningError('plan_approval_required');
 if(!c.tenantId||options.apply&&plan.blockers.length)throw new ProvisioningError('incomplete_configuration');
 return await dependencies.lock(async()=>{
  let receipt=await dependencies.read();
  if(receipt&&(receipt.tenantId!==c.tenantId||receipt.configHash!==plan.hash||!['creating','pending','uncertain','ready'].includes(receipt.status)))throw new ProvisioningError('state_conflict');
  const check=async()=>{const profile=authentication(await dependencies.run(['auth','who','--json'],30000));if(profile.tenant!==c.tenantId)throw new ProvisioningError('wrong_tenant');if(c.type==='Developer'&&profile.user!==c.developerUser?.toLowerCase())throw new ProvisioningError('wrong_developer_owner');return profile;};
  const profile=await check();
  const discover=async()=>{
   const list=summaries(await dependencies.run(['admin','list','--name',c.name,'--json'],60000));
   const matching=list.filter(e=>e.name===c.name||e.id===(c.environmentId??receipt?.environment?.id));
   if(matching.length>1)throw new ProvisioningError('environment_conflict');return matching[0];
  };
  let found=await discover();
  if(options.inspect&&!found)return{status:receipt?'creation_pending':'not_found',plan};
  if(!found){
   if(receipt||c.environmentId)throw new ProvisioningError('creation_pending');
   if((await check()).fingerprint!==profile.fingerprint)throw new ProvisioningError('authentication_changed');
   receipt={status:'creating',tenantId:c.tenantId!,configHash:plan.hash};await dependencies.write(receipt);
   // No automatic creation retries: an interrupted CLI can already have created the resource.
   try{await dependencies.run(plan.createArguments,16*60000);}catch{
    await dependencies.write({...receipt,status:'uncertain'});throw new ProvisioningError('creation_uncertain');
   }
   receipt={...receipt,status:'pending'};await dependencies.write(receipt);
   if((await check()).fingerprint!==profile.fingerprint)throw new ProvisioningError('authentication_changed');found=await discover();
   if(!found)throw new ProvisioningError('creation_pending');
  }else if(!receipt&&!c.environmentId){
   if(options.inspect)return{status:'existing_unmanaged',environment:found,plan};
   throw new ProvisioningError('existing_environment_not_approved');
  }
  if(c.environmentId&&found.id!==c.environmentId||receipt?.environment&&found.id!==receipt.environment.id||found.type!==c.type||found.name!==c.name||new URL(found.url).hostname.split('.')[0]!==c.domain)throw new ProvisioningError('environment_drift');
  const details=await dependencies.run(['environment-management','get-environment-by-id-for-user','--environment',found.id,'--json'],60000);
  const verified=verifyDetail(details,found,c);
  if((await check()).fingerprint!==profile.fingerprint)throw new ProvisioningError('authentication_changed');
  if(!options.inspect)await dependencies.write({status:'ready',tenantId:c.tenantId!,configHash:plan.hash,environment:verified});
  return{status:'ready',environment:verified,plan};
 });
 }catch(error){throw error instanceof ProvisioningError?error:new ProvisioningError('unavailable');}
}
