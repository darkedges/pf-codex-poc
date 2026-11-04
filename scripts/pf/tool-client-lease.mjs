// Local lab only: preserve the active human client; enable B for a bounded caller.
function comparableHumanClient(client){
 const copy=structuredClone(client);
 // PF re-encrypts this write-only secret on reads. Ciphertext equality cannot
 // establish secret equality. Never write A; compare all observable settings.
 if(copy.clientAuth)delete copy.clientAuth.encryptedSecret;
 return JSON.stringify(copy);
}
export async function withToolClient(admin,work){
 const a=await admin('a','oauth/clients/copilot-studio-generic-oauth'),b=await admin('b','oauth/clients/copilot-sso-exchange');
 if(a.enabled!==true||b.enabled!==false||b.clientAuth?.type!=='PRIVATE_KEY_JWT'||b.clientAuth.enforceReplayPrevention!==true||JSON.stringify(b.grantTypes)!==JSON.stringify(['TOKEN_EXCHANGE'])||b.defaultAccessTokenManagerRef?.id!=='copilotToolJWT')throw Error('Unexpected lab client lifecycle or profile');
 try{
  await admin('b','oauth/clients/copilot-sso-exchange','PUT',{...b,enabled:true});
  return await work();
 }finally{
  let disabled=false;
  for(let attempt=0;attempt<3&&!disabled;attempt++)try{
   const current=await admin('b','oauth/clients/copilot-sso-exchange');
   await admin('b','oauth/clients/copilot-sso-exchange','PUT',{...current,enabled:false});
   disabled=(await admin('b','oauth/clients/copilot-sso-exchange')).enabled===false;
  }catch{}
  if(!disabled)throw Error('Tool client disable recovery required');
  if(comparableHumanClient(await admin('a','oauth/clients/copilot-studio-generic-oauth'))!==comparableHumanClient(a))throw Error('Human client changed during verification; reconcile without overwriting');
 }
}
