import {readFileSync,writeFileSync,mkdirSync,existsSync,openSync,closeSync,rmSync} from 'node:fs';import {resolve} from 'node:path';import {randomUUID} from 'node:crypto';
import {root,load} from '../pf/common.mjs';import {copilotProfile as p} from '../pf/copilot-config.mjs';
import {protect,custody,readProtected} from './tool-custody.mjs';import {vault} from './common.mjs';import {fetchRelayRecord,relayRecordDigest,validateRelayRecord} from './relay-secrets.mjs';
import {loadRelayRuntime} from '../../src/copilot/relay-runtime.ts';import {assertChannelBinding} from '../../src/copilot/channel-binding.ts';
const args=process.argv.slice(2);if(args.length!==1||args[0]!=='--prepare')throw Error('Use --prepare; this command never starts a listener');
const lock=resolve(custody,'relay-runtime-preparation.lock');let fd;let success=false;
try{
 protect();fd=openSync(lock,'wx',0o600);
 const configPath=resolve(custody,'relay-runtime.json');if(existsSync(configPath))throw Error('Existing runtime selection requires reconciliation');
 const enrollment=JSON.parse(readFileSync(resolve(custody,'relay-enrollment.json'),'utf8'));
 if(!/^relay-snapshot-1-[a-f0-9-]{36}$/.test(enrollment.snapshot))throw Error();
 const fetched=await fetchRelayRecord((path,options)=>vault(path,{...options,cert:readProtected('relay-renderer-cert.pem'),key:readProtected('relay-renderer-key.pem')}));if(fetched.version!==enrollment.version)throw Error();
 const snapshot=resolve(custody,enrollment.snapshot);for(const [name,value] of Object.entries(validateRelayRecord(fetched.record)))if(readFileSync(resolve(snapshot,name),'utf8')!==value)throw Error();
 const channel=resolve(root,'.local/copilot'),settings=JSON.parse(readFileSync(resolve(channel,'channel-settings.json'),'utf8')),binding=JSON.parse(readFileSync(resolve(channel,'channel-credential-binding.json'),'utf8')),contract=JSON.parse(readFileSync(resolve(channel,'current-channel-contract.json'),'utf8'));
 assertChannelBinding(settings,binding);assertChannelBinding(contract.target,binding);if(contract.endpoint!=='https://directline.botframework.com/v3/directline'||contract.tokenPostRule.origin!=='https://token.botframework.com'||contract.tokenPostRule.pathExact!=='/api/sas/postToken')throw Error();
 const broker=load('consent-exchange-config.json'),provider={issuer:p.loginIssuer,audience:p.loginAudience,scope:'copilot.login'},operations=JSON.parse(readFileSync(resolve(custody,'service/operations.json'),'utf8'));if(operations.retentionDays!==1)throw Error();
 const config={version:1,relay:{brokerAudience:broker.downstream.audience,toolAudience:p.toolAudience,scope:'copilot.invoke',callerId:'copilot-relay-connection',provider,bindingLifetimeSeconds:120,maxBindings:100,timeoutMs:10000},directLine:{endpoint:contract.endpoint,brokerAudience:broker.downstream.audience,ssoAudience:p.loginAudience,scope:'copilot.invoke',providerSso:{...provider,maxLifetimeSeconds:p.loginLifetimeSeconds},botId:contract.botId,trustedOrigins:['https://server-only.federated-copilot.invalid'],tokenPostRules:[contract.tokenPostRule],timeoutMs:10000,maxSessions:10,sessionLifetimeSeconds:120,maxActivities:100},privateToolOrigin:'https://tool-api:8443',controls:{maxConcurrent:4,maxConnections:32,requestsPerMinute:60}};
 const directory=resolve(custody,'relay-service');mkdirSync(directory,{recursive:true,mode:0o700});mkdirSync(resolve(directory,'audit'),{recursive:true,mode:0o700});
 const validation=resolve(custody,'relay-runtime-validation-'+randomUUID());mkdirSync(validation,{mode:0o700});mkdirSync(resolve(validation,'audit'),{mode:0o700});
 const validationConfig=resolve(validation,'runtime.json');writeFileSync(validationConfig,JSON.stringify(config,null,2),{mode:0o600,flag:'wx'});
 const env={RELAY_MODE:'verified',RELAY_CONFIG_FILE:validationConfig,RELAY_SECRETS_DIR:snapshot,RELAY_AUDIT_DIR:resolve(validation,'audit'),RELAY_AUDIT_RETENTION_DAYS:'1'};
 let authorityCalls=0;const disabled=async()=>{authorityCalls++;throw Error('Authority intentionally unavailable in offline preparation');};
 // Explicit deny-only validation dependencies, never a runtime or mock fallback.
 const prepared=await loadRelayRuntime(env,{brokerVerifier:{verify:disabled},providerVerifier:{verify:disabled},toolVerifier:{verify:disabled},bindProviderIdentity:disabled,authoriseBroker:disabled,issueToolToken:disabled,channel:{secret:disabled,issueSsoToken:disabled,authorise:disabled,fetch:disabled}});
 if(prepared.server.listening||!await prepared.ready()||authorityCalls!==0)throw Error();
 const requestId=randomUUID();prepared.audit.write({event:'copilot_tool_relay',requestId,phase:'attempt'});prepared.audit.write({event:'copilot_tool_relay',requestId,phase:'denied'});if(!await prepared.ready())throw Error();
 writeFileSync(configPath,JSON.stringify(config,null,2),{mode:0o600,flag:'wx'});
 writeFileSync(resolve(directory,'environment.json'),JSON.stringify({...env,RELAY_CONFIG_FILE:configPath,RELAY_AUDIT_DIR:resolve(directory,'audit')},null,2),{mode:0o600,flag:'wx'});
 writeFileSync(resolve(directory,'operations.json'),JSON.stringify(operations,null,2),{mode:0o600,flag:'wx'});
 const receipt={completedAt:new Date().toISOString(),snapshotVersion:fetched.version,snapshotDigest:relayRecordDigest(fetched.record),snapshotFiles:8,localCredentialReadiness:true,auditWriteVerified:true,retentionDays:1,listenerStarted:false,authorityWired:false,privateNetworkReachabilityTested:false,connectorConfigured:false,microsoftRequests:0,authorityCalls,validationDirectory:validation};
 writeFileSync(resolve(directory,'preparation.json'),JSON.stringify(receipt,null,2),{mode:0o600,flag:'wx'});success=true;console.log(JSON.stringify({prepared:true,snapshotFiles:8,localCredentialReadiness:true,auditWriteVerified:true,listenerStarted:false,authorityWired:false,microsoftRequests:0}));
}catch{console.error('Relay runtime preparation incomplete; no listener or authority fallback started');process.exitCode=1;}
finally{if(fd!==undefined){closeSync(fd);if(success)rmSync(lock);}}
