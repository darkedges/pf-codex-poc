import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {reviewRelayDeployment} from '../scripts/vault/relay-deployment-review.mjs';
const draft=()=>JSON.parse(readFileSync(new URL('../infra/copilot/relay-deployment.review.json',import.meta.url),'utf8'));
test('relay deployment review remains non-deploying with explicit unresolved authority gates',()=>{const r=reviewRelayDeployment(draft());assert.equal(r.deployable,false);assert.ok(r.unresolved.includes('external-agent-proof-custody'));});
for(const patch of [{deploymentEnabled:true},{mountDockerSocket:true},{mountExternalAgentPrivateKey:true},{publicIngressEnabled:true},{mockFallback:true}])test('unsafe deployment drift is rejected',()=>assert.throws(()=>reviewRelayDeployment({...draft(),...patch})));
