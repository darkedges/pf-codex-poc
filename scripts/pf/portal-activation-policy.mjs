import {createHash} from 'node:crypto';
const origin='https://agent.copilot.darkedges.com';
const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
export const clientFingerprint=client=>{const copy=structuredClone(client);delete copy.modificationDate;if(copy.clientAuth){delete copy.clientAuth.encryptedSecret;for(const old of copy.clientAuth.secondarySecrets??[])delete old.encryptedSecret;}return createHash('sha256').update(JSON.stringify(canonical(copy))).digest('hex');};
export function assertPortalToolKey(client,pinned){
 try{if(client?.jwksSettings?.jwksUrl)throw Error();const actual=JSON.parse(client.jwksSettings.jwks);if(!Array.isArray(actual.keys)||!actual.keys.length||actual.keys.some(k=>k.kty!=='RSA'||k.alg!=='RS256'||k.use!=='sig'||!k.kid||['d','p','q','dp','dq','qi'].some(field=>field in k))||JSON.stringify(canonical(actual))!==JSON.stringify(canonical(pinned)))throw Error();}catch{throw Error('PF tool client key differs from enrolled public trust');}
}
const definitions={
 'copilot-consent-portal':{before:['https://localhost:9460/callback','https://localhost:9461/callback'],callback:origin+'/callback',auth:'PRIVATE_KEY_JWT',scope:'openid'},
 'copilot-studio-generic-oauth':{before:['https://token.botframework.com/.auth/web/redirect'],callback:origin+'/provider-callback',auth:'SECRET',scope:'copilot.login'}
};
export function callbackChange(current){
 const d=definitions[current?.clientId];
 if(!d||current.enabled!==true||current.clientAuth?.type!==d.auth||JSON.stringify(current.grantTypes)!=='["AUTHORIZATION_CODE"]'||current.restrictScopes!==true||JSON.stringify(current.restrictedScopes)!==JSON.stringify([d.scope])||JSON.stringify(current.redirectUris)!==JSON.stringify(d.before))throw Error('PF callback profile drift');
 if(d.auth==='PRIVATE_KEY_JWT'&&(current.clientAuth.enforceReplayPrevention!==true||current.clientAuth.tokenEndpointAuthSigningAlgorithm!=='RS256'||current.requirePushedAuthorizationRequests!==true||current.requireProofKeyForCodeExchange!==true))throw Error('Consent PAR/PKCE/client authentication drift');
 if(d.auth==='SECRET'&&(current.defaultAccessTokenManagerRef?.id!=='copilotLoginJWT'||current.restrictToDefaultAccessTokenManager!==true))throw Error('Configured provider token manager drift');
 const after={...structuredClone(current),redirectUris:[...d.before,d.callback]};
 return{clientId:current.clientId,beforeHash:clientFingerprint(current),afterHash:clientFingerprint(after),beforeRedirects:[...d.before],afterRedirects:[...after.redirectUris]};
}
export async function applyPortalCallbacks(admin,changes,rollback=false){
 if(!Array.isArray(changes)||changes.length!==2||JSON.stringify(changes.map(c=>c.clientId).sort())!==JSON.stringify(Object.keys(definitions).sort()))throw Error('Exact PF callback scope required');
 const prepared=[];
 for(const change of changes){
  const definition=definitions[change.clientId],expected=[...definition.before,definition.callback];
  if(JSON.stringify(change.beforeRedirects)!==JSON.stringify(definition.before)||JSON.stringify(change.afterRedirects)!==JSON.stringify(expected))throw Error('PF callback plan mismatch');
  const path='oauth/clients/'+change.clientId,current=await admin('a',path),hash=clientFingerprint(current),source=rollback?change.afterHash:change.beforeHash,target=rollback?change.beforeHash:change.afterHash;
  if(hash===target)continue;if(hash!==source)throw Error('PF callback settings drift');
  const candidate={...current,redirectUris:[...(rollback?change.beforeRedirects:change.afterRedirects)]};
  if(clientFingerprint(candidate)!==target)throw Error('Unexpected PF callback mutation');prepared.push({path,candidate,target});
 }
 // Validate both clients before making either write. Never persist client bodies.
 for(const change of prepared){await admin('a',change.path,'PUT',change.candidate);if(clientFingerprint(await admin('a',change.path))!==change.target)throw Error('PF callback read-back failed');}
}
function toolProfile(client){return client?.clientId==='copilot-sso-exchange'&&client.clientAuth?.type==='PRIVATE_KEY_JWT'&&client.clientAuth.enforceReplayPrevention===true&&client.clientAuth.tokenEndpointAuthSigningAlgorithm==='RS256'&&JSON.stringify(client.grantTypes)==='["TOKEN_EXCHANGE"]'&&client.defaultAccessTokenManagerRef?.id==='copilotToolJWT';}
export function createPortalPfLease(options){
 const {admin,store,owner}=options,toolPath='oauth/clients/copilot-sso-exchange',humanPath='oauth/clients/copilot-studio-generic-oauth';
 if(!owner?.instance||!Number.isSafeInteger(owner.pid)||owner.pid<1||!Number.isSafeInteger(options.expiresAt)||options.expiresAt<=0||options.expiresAt>Date.now()+3600000||![options.baselineHash,options.humanHash].every(h=>/^[a-f0-9]{64}$/.test(h)))throw Error('Invalid portal PF lease');
 const matches=record=>record?.schemaVersion===1&&record.owner?.instance===owner.instance&&record.owner.pid===owner.pid&&record.expiresAt===options.expiresAt&&record.baselineHash===options.baselineHash&&record.humanHash===options.humanHash;
 let releasing;
 return{
  acquire:async()=>{
   if(store.get()||options.expiresAt<=Date.now())throw Error('Existing or expired PF lease requires recovery');
   const [human,tool]=await Promise.all([admin('a',humanPath),admin('b',toolPath)]);
   if(!toolProfile(tool)||tool.enabled!==false||human.enabled!==true||clientFingerprint(tool)!==options.baselineHash||clientFingerprint(human)!==options.humanHash)throw Error('PF lease profile drift');
   const candidate={...tool,enabled:true},record={schemaVersion:1,owner:{...owner},expiresAt:options.expiresAt,baselineHash:options.baselineHash,enabledHash:clientFingerprint(candidate),humanHash:options.humanHash};
   store.create(record);await admin('b',toolPath,'PUT',candidate);
   if(clientFingerprint(await admin('b',toolPath))!==record.enabledHash)throw Error('PF enable read-back failed');
  },
  check:async()=>{
   const record=store.get();if(!matches(record)||Date.now()>=record.expiresAt)throw Error('PF lease expired or unknown');
   if(clientFingerprint(await admin('b',toolPath))!==record.enabledHash||clientFingerprint(await admin('a',humanPath))!==record.humanHash)throw Error('PF lease drift');
  },
  release:()=>releasing??=(async()=>{
   const record=store.get();if(!record)return;if(!matches(record))throw Error('Foreign PF lease ownership');
   const current=await admin('b',toolPath),hash=clientFingerprint(current);
   if(!toolProfile(current)||![record.baselineHash,record.enabledHash].includes(hash))throw Error('PF restore drift; ownership retained');
   if(hash===record.enabledHash)await admin('b',toolPath,'PUT',{...current,enabled:false});
   if(clientFingerprint(await admin('b',toolPath))!==record.baselineHash)throw Error('PF disable read-back failed');
   if(clientFingerprint(await admin('a',humanPath))!==record.humanHash)throw Error('Human client changed; disabled tool lease retained for review');
   store.remove();
  })()
 };
}
