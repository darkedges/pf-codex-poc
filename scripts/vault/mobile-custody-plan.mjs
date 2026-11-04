// Public recipe only. Creating any listed object requires the separate staging
// review. No operator credential, network, file, key generation or startup here.
export function mobileCustodyPlan(){
 const policies={
  'mobile-runtime-read':{'mobile-runtime/data/credentials':['read']},
  'mobile-provider-store':{'mobile-provider/data/*':['create','read','update']},
  'mobile-agent-sign':{'transit/sign/mobile-agent-v1/sha2-256':['update']},
  'mobile-authority-sign':{'transit/sign/mobile-authority-v1/sha2-256':['update']},
  'mobile-graph-read':{'federated-copilot-tool-secrets/data/sharepoint-broker':['read']}
 };
 return{schemaVersion:1,purpose:'mobile-disabled-staging',approved:false,
  mounts:[{path:'mobile-runtime',type:'kv',version:2,maxVersions:1,casRequired:true},{path:'mobile-provider',type:'kv',version:2,maxVersions:1,casRequired:true}],
  transitKeys:['mobile-agent-v1','mobile-authority-v1'].map(name=>({mount:'transit',name,type:'rsa-3072',exportable:false,allowPlaintextBackup:false,version:1})),
  record:{path:'mobile-runtime/data/credentials',cas:0,newPrivateKeys:['mobile-copilot-login','mobile-chat-gateway-1','mobile-chat-gateway-2','mobile-document-gateway-1','mobile-document-gateway-2'],rsaBits:3072,copyOnly:[{path:'federated-copilot-tool-secrets/data/portal-controller',field:'directLineSecret'}]},
  policies,
  certificateRoles:Object.keys(policies).map(name=>({mount:'auth/tool-cert',name:'copilot-'+name,policies:[name],certificateDays:30,rsaBits:3072,tokenNoDefaultPolicy:true,tokenTtlSeconds:name.endsWith('-read')?120:300,tokenMaxTtlSeconds:name.endsWith('-read')?120:300,tokenNumUses:name.endsWith('-read')?1:0})),
  limitations:{authorityHardwareAttestation:'UNVERIFIED',hostAccountIsTrustBoundary:true,rootForNamedBootstrapOnly:true,automaticRootAccess:false,automaticUnseal:false},
  pfClientsEnabled:false,windowsTaskInstalled:false,publicRoutesChanged:false,microsoftRequests:0,providerRefreshRequests:0};
}
