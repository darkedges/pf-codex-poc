import test from 'node:test';
import assert from 'node:assert/strict';
import {enrolledNetworkPlan} from '../scripts/vault/enrolled-network-plan.mjs';
const input=()=>({id:'12345678-1234-4234-9234-123456789abc',image:'sha256:'+'a'.repeat(64)});
test('enrolled network keeps tool private with separate bridge egress and role-specific mounts',()=>{const p=enrolledNetworkPlan(input());assert.equal(p.hostPorts.length,0);assert.equal(p.internalSubnet,'10.236.250.16/28');assert.deepEqual(p.toolNetworks,[p.network]);assert.deepEqual(p.bridgeNetworks,['bridge',p.network]);assert.deepEqual(p.toolSecretFiles,['tool-server-key.pem','tool-server-cert.pem','tool-client-ca.pem','tool-outbound-ca.pem','tool-policy-key.pem','tool-audit-key']);assert.equal(p.mountOperatorCredentials,false);assert.equal(p.runAsUser,'1000:1000');});
for(const change of [i=>i.id='../escape',i=>i.image='node:latest',i=>i.image='federated-copilot-tool:local',i=>i.hostPorts=['0.0.0.0:9480:8443'],i=>i.mountOperatorCredentials=true])test('network plan refuses unsafe or unreviewed input',()=>{const i=input();change(i);assert.throws(()=>enrolledNetworkPlan(i));});
