import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {reviewToolDeploymentDraft} from '../scripts/pf/review-tool-deployment.mjs';
const draft=()=>JSON.parse(readFileSync(new URL('../infra/tool-api/deployment.review.json',import.meta.url),'utf8'));
test('review package remains non-deploying and reports unresolved work without secret values',()=>{
 const result=reviewToolDeploymentDraft(draft());assert.equal(result.readyForDeployment,false);assert.equal(result.status,'DRAFT_NOT_DEPLOYABLE');assert.ok(result.blockers.includes('runtime-deployment-acceptance'));assert.ok(result.blockers.includes('caller-authentication'));assert.ok(!JSON.stringify(result).includes('/run/secrets'));
});
for(const mutation of [
 p=>p.deploymentEnabled=true,
 p=>p.ingress.publicRoutes=['https://public.invalid'],
 p=>p.hostingProposal.hostPortBinding.address='0.0.0.0',
 p=>p.ingress.forwardedCertificateHeadersTrusted=true,
 p=>p.delegatedTrust.mockFallback=true,
 p=>p.delegatedTrust.requirePolicyBeforeAndAfterOperation=false,
 p=>p.secretMountProposals.mountVaultOperatorCredentials=true,
 p=>p.secretMountProposals.custodyProvider='host-files',
 p=>p.secretMountProposals.mountDirectLineSecret=true,
 p=>p.egress.graphAccess=true,
 p=>p.operations.logAuthorizationHeaders=true,
 p=>p.operations.allowCredentialRollback=true,
 p=>p.runtimeLimits.postRetries=1,
 p=>p.runtimeLimits.maxConcurrentRequests=0,
 p=>p.operations.readinessImplementation=null,
 p=>p.hostingProposal.hostWorkspaceMount=true,
 p=>p.delegatedTrust.maxTokenLifetimeSeconds=3600,
])test('offline review rejects unsafe draft drift without echoing configuration',()=>{
 const p=draft();mutation(p);assert.throws(()=>reviewToolDeploymentDraft(p),/^Error: Invalid non-deploying tool review draft$/);
});
