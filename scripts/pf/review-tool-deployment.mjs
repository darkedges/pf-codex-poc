import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const check=value=>{if(!value)throw Error('Invalid non-deploying tool review draft');};
const objectKeys=(value,keys)=>{
 check(value&&typeof value==='object'&&!Array.isArray(value));
 check(Object.keys(value).sort().join(',')===keys.split(',').sort().join(','));
};
export function reviewToolDeploymentDraft(p){
 try{
  objectKeys(p,'schemaVersion,status,deploymentEnabled,scope,hostingProposal,ingress,delegatedTrust,secretMountProposals,egress,runtimeLimits,operations,externalDependencies');
  check(p.schemaVersion===1&&p.status==='DRAFT_NOT_DEPLOYABLE'&&p.deploymentEnabled===false&&p.scope==='read-only authorization diagnostic');
  const h=p.hostingProposal,i=p.ingress,t=p.delegatedTrust,s=p.secretMountProposals,e=p.egress,l=p.runtimeLimits,o=p.operations;
  objectKeys(h,'platform,selectionConfirmed,hostPortBinding,containerListener,imageDigest,runtimeEntrypoint,localImageId,runAsNonRoot,readOnlyRootFilesystem,dropAllCapabilities,noNewPrivileges,dockerSocketMount,hostWorkspaceMount');
  objectKeys(h.hostPortBinding,'address,port');objectKeys(h.containerListener,'address,port,protocol');
  check(h.hostPortBinding.address==='127.0.0.1'&&h.hostPortBinding.port===9480&&h.containerListener.address==='0.0.0.0'&&h.containerListener.port===8443&&h.containerListener.protocol==='https-mtls');
  check(h.runtimeEntrypoint==='src/copilot/tool-main.ts'&&/^sha256:[a-f0-9]{64}$/.test(h.localImageId)&&l.cpuLimit===0.5&&l.memoryLimit==='256MiB');
  check(h.runAsNonRoot===true&&h.readOnlyRootFilesystem===true&&h.dropAllCapabilities===true&&h.noNewPrivileges===true&&h.dockerSocketMount===false&&h.hostWorkspaceMount===false);
  objectKeys(i,'publicRoutes,cloudflareChanges,callingWorkload,callerToGatewayAuthentication,tlsTermination,forwardedCertificateHeadersTrusted,clientCertificateSha256,route');
  objectKeys(i.route,'method,path,contentType,body');objectKeys(i.route.body,'');
  check(i.route.method==='POST'&&i.route.path==='/v1/tools/verify-access'&&i.route.contentType==='application/json'&&Array.isArray(i.publicRoutes)&&!i.publicRoutes.length&&i.cloudflareChanges===false&&i.tlsTermination==='tool-process'&&i.forwardedCertificateHeadersTrusted===false);
  objectKeys(t,'adapter,mockFallback,issuer,jwksUri,audience,scope,algorithms,keyIds,organisations,actorIssuers,maxTokenLifetimeSeconds,capabilityResource,resourceBindingConfirmed,policyOrigin,policyWorkloadId,policyWorkloadKeyId,requirePolicyBeforeAndAfterOperation');
  check(t.adapter==='jose-jwks-with-independent-online-policy'&&t.mockFallback===false&&t.audience==='api://copilot-tool'&&t.scope==='copilot.invoke'&&JSON.stringify(t.algorithms)==='["RS256"]'&&t.maxTokenLifetimeSeconds===120&&t.requirePolicyBeforeAndAfterOperation===true);
  objectKeys(s,'toolServerKey,toolServerCertificate,workloadClientCA,outboundTrustCA,policySigningKey,auditHmacKey,custodyProvider,readOnly,mountPfAdminCredentials,mountVaultOperatorCredentials,mountDirectLineSecret,mountConsentSigningKey');
  check(s.auditHmacKey==='/run/secrets/tool-audit-key'&&o.telemetrySink==='local-stdout-fixed-schema'&&o.auditDirectory==='/var/lib/tool-audit'&&o.auditMode==='required-pseudonymous-bounded-jsonl'&&o.auditMaxBytes===1048576&&o.auditRetainedFiles===2&&o.metricsEndpoint==='/health/metrics');
  check(s.readOnly===true&&[s.mountPfAdminCredentials,s.mountVaultOperatorCredentials,s.mountDirectLineSecret,s.mountConsentSigningKey].every(v=>v===false));
  objectKeys(e,'defaultDeny,approvedDestinations,dnsResolver,microsoftChannelAccess,graphAccess,pfAdministrationAccess,vaultOperatorAccess');
  check(e.defaultDeny===true&&[e.microsoftChannelAccess,e.graphAccess,e.pfAdministrationAccess,e.vaultOperatorAccess].every(v=>v===false));
  objectKeys(l,'bodyBytes,headerBytes,headerCount,headerTimeoutMs,requestTimeoutMs,toolDeadlineMs,policyTimeoutMs,jwksTimeoutMs,postRetries,maxConcurrentRequests,maxConnections,perWorkloadRateLimit,cpuLimit,memoryLimit');
  check(l.bodyBytes===1024&&l.headerBytes===20000&&l.headerCount===32&&l.headerTimeoutMs===5000&&l.requestTimeoutMs===10000&&l.postRetries===0);
  objectKeys(l.perWorkloadRateLimit,'requestsPerMinute,burst,identity');
  check(l.maxConcurrentRequests===16&&l.maxConnections===128&&l.perWorkloadRateLimit.requestsPerMinute===60&&l.perWorkloadRateLimit.burst===60&&l.perWorkloadRateLimit.identity==='client-certificate-sha256'&&o.readinessImplementation==='pinned-mtls-GET-/health/ready');
  check(l.toolDeadlineMs===5000&&l.policyTimeoutMs===1500&&l.jwksTimeoutMs===1500);
  objectKeys(o,'readinessImplementation,telemetrySink,auditDirectory,auditMode,auditMaxBytes,auditRetainedFiles,metricsEndpoint,externalAlertDestination,auditRetentionDays,operationalOwner,certificateRotation,hotTrustReload,logRequestBodies,logAuthorizationHeaders,logSignedUrls,logTranscriptTokens,allowCredentialRollback,smokeFixture');
  check([o.hotTrustReload,o.logRequestBodies,o.logAuthorizationHeaders,o.logSignedUrls,o.logTranscriptTokens,o.allowCredentialRollback].every(v=>v===false)&&o.certificateRotation==='reviewed-overlap-drain-replace-retire'&&o.smokeFixture==='synthetic-data-only');
  objectKeys(p.externalDependencies,'copilotTokenPost,copilotCallerAuthentication,graphSharePoint');
  check(p.externalDependencies.copilotTokenPost==='UNVERIFIED_HTTP_400'&&p.externalDependencies.copilotCallerAuthentication==='UNVERIFIED'&&p.externalDependencies.graphSharePoint==='NOT_CONNECTED');
  // This reviews only the current unresolved draft, not filled-in runtime input.
  check(s.custodyProvider==='local-vault-kv2-certificate-renderer');
  check([h.imageDigest,i.callingWorkload,i.callerToGatewayAuthentication,t.issuer,t.jwksUri,t.policyOrigin,t.policyWorkloadId,t.policyWorkloadKeyId,e.dnsResolver,o.externalAlertDestination,o.auditRetentionDays,o.operationalOwner].every(v=>v===null));
  check([i.clientCertificateSha256,t.keyIds,t.organisations,t.actorIssuers,e.approvedDestinations].every(v=>Array.isArray(v)&&v.length===0));
  check(h.platform==='existing-windows-host-with-isolated-linux-container'&&h.selectionConfirmed===true&&t.resourceBindingConfirmed===false&&t.capabilityResource==='sharepoint:approved-research');
  check(Object.entries(s).filter(([k])=>['toolServerKey','toolServerCertificate','workloadClientCA','outboundTrustCA','policySigningKey'].includes(k)).every(([,v])=>typeof v==='string'&&/^\/run\/secrets\/[a-z-]+\.pem$/.test(v)));
 }catch{throw Error('Invalid non-deploying tool review draft');}
 return{status:'DRAFT_NOT_DEPLOYABLE',readyForDeployment:false,networkCalls:0,opensListeners:false,applyAvailable:false,blockers:['runtime-deployment-acceptance','caller-authentication','private-routing-and-trust','credential-delivery-acceptance','production-load-validation','external-alerting-and-retention','operations-ownership','resource-binding','live-copilot-acceptance']};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  check(process.argv.length===2);
  const raw=readFileSync(new URL('../../infra/tool-api/deployment.review.json',import.meta.url),'utf8');check(Buffer.byteLength(raw)<=32768);
  console.log(JSON.stringify(reviewToolDeploymentDraft(JSON.parse(raw)),null,2));
 }catch{console.error('Invalid non-deploying tool review draft');process.exitCode=1;}
}
