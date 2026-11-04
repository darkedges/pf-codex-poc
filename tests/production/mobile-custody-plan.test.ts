import test from 'node:test';import assert from 'node:assert/strict';
import {mobileCustodyPlan} from '../../scripts/vault/mobile-custody-plan.mjs';
test('mobile custody recipe scopes signing, provider data and read-only existing Graph material separately',()=>{
 const p=mobileCustodyPlan();assert.equal(p.approved,false);assert.equal(p.pfClientsEnabled,false);assert.equal(p.microsoftRequests,0);assert.equal(p.record.newPrivateKeys.length,5);assert.equal(p.certificateRoles.length,5);assert.deepEqual(p.policies['mobile-graph-read'],{'federated-copilot-tool-secrets/data/sharepoint-broker':['read']});assert.deepEqual(p.record.copyOnly,[{path:'federated-copilot-tool-secrets/data/portal-controller',field:'directLineSecret'}]);
 for(const key of p.transitKeys){assert.equal(key.exportable,false);assert.equal(key.allowPlaintextBackup,false);}for(const m of p.mounts){assert.equal(m.casRequired,true);assert.equal(m.maxVersions,1);}for(const role of p.certificateRoles){assert.equal(role.tokenNoDefaultPolicy,true);assert.equal(role.policies.length,1);assert.ok(role.tokenMaxTtlSeconds<=300);}assert.ok(!Object.keys(p.policies).some(k=>/root|admin/.test(k)));
});
