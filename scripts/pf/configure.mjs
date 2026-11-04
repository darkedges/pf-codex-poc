import { generateKeyPair, exportPKCS8, exportJWK } from 'jose';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { admin, call, read, save, load, nodes, local, root } from './common.mjs';
import { processor, client, tokenManager, exchangePolicy, accessTokenMapping, profile } from './config.mjs';

for (const name of ['human','agent','delegation','gateway-1','gateway-2']) {
  if (!existsSync(resolve(local, `${name}.private.pem`))) {
    const pair = await generateKeyPair('RS256', { extractable: true });
    save(`${name}.private.pem`, await exportPKCS8(pair.privateKey));
    save(`${name}.jwks.json`, { keys: [{ ...await exportJWK(pair.publicKey), kid: `copilot-${name}`, alg: 'RS256', use: 'sig' }] });
  }
}
// Idempotent reconciliation applies only to fixed IDs on the two pinned local admin endpoints.
async function upsert(node, collection, id, value) {
  const existing = await call(nodes[node].admin + '/pf-admin-api/v1/' + collection + '/' + encodeURIComponent(id), { admin: load(`admin-${node}.json`) });
  if (existing.status !== 200 && existing.status !== 404) throw Error(`Unexpected PF ${node} object status ${existing.status}`);
  return admin(node, existing.status === 200 ? collection + '/' + encodeURIComponent(id) : collection, existing.status === 200 ? 'PUT' : 'POST', value);
}
for (const node of ['a','b']) {
  const version = await admin(node,'version');
  save(`version-${node}.json`, version);
  const server = await admin(node,'serverSettings');
  server.federationInfo.baseUrl = nodes[node].issuer;
  await admin(node,'serverSettings','PUT',server);
  const settings = await admin(node,'oauth/authServerSettings');
  if (!settings.scopes.some(s => s.name === profile.scope)) settings.scopes.push({ name: profile.scope, description: 'Container-only Copilot invocation' });
  await admin(node,'oauth/authServerSettings','PUT',settings);
  const expressions = await admin(node,'configStore/org.sourceid.common.ExpressionManager/evaluateExpressions');
  if (expressions.stringValue !== 'true') {
    await admin(node,'configStore/org.sourceid.common.ExpressionManager/evaluateExpressions','PUT', { id: 'evaluateExpressions', type: 'STRING', stringValue: 'true' });
    const restart = spawnSync('docker', ['compose','--env-file','.local/pingfederate/compose.env','-f','infra/pingfederate/compose.yaml','restart',`pf-${node}`], { cwd: root, stdio: 'inherit' });
    if (restart.status !== 0) throw Error('Expression configuration restart failed');
    let ready = false;
    for (let i = 0; i < 40; i++) { try { await admin(node,'version'); ready = true; break; } catch {} await new Promise(r => setTimeout(r,3000)); }
    if (!ready) throw Error('PF not ready after expression configuration');
  }
  const keyId = `copilot-${node}-signing`;
  const keys = await admin(node,'keyPairs/signing');
  if (!keys.items.some(k => k.id === keyId)) await admin(node,'keyPairs/signing/generate','POST', { id: keyId, keyAlgorithm: 'RSA', keySize: 2048, validDays: 365, commonName: keyId, organization: 'Synthetic container integration', country: 'AU' });
  if (node === 'a') {
    for (const [id, issuer, aud, key] of [
      ['copilotHuman',profile.humanIssuer,'api://pf-a/human-proof','human'],
      ['copilotDelegation',profile.delegationIssuer,'api://pf-a/delegation-proof','delegation'],
      ['copilotAgent',profile.agentIssuer,'api://pf-a/agent-proof','agent'],
    ]) await upsert(node,'idp/tokenProcessors',id,processor(id,issuer,aud,load(`${key}.jwks.json`)));
  } else {
    const jwks = await call(nodes.a.issuer + '/pf/JWKS');
    if (jwks.status !== 200 || !jwks.value.keys.some(k => k.kid === 'copilot-a-signing')) throw Error('PF A JWKS not ready');
    // PF B pins PF A's published verification keys. No insecure inter-container hostname override.
    const pinned = { keys: jwks.value.keys.filter(k => k.kid === 'copilot-a-signing') };
    await upsert(node,'idp/tokenProcessors','copilotUpstream',processor('copilotUpstream',nodes.a.issuer,'api://gateway-2',pinned));
  }
  await upsert(node,'oauth/tokenExchange/processor/policies',`copilot${node.toUpperCase()}Policy`,exchangePolicy(node));
  // Create the client disabled first, so the manager's client allowlist can resolve it.
  const clientId = node === 'a' ? 'gateway-1-token-exchange' : 'gateway-2-token-exchange';
  const clientKey = node === 'a' ? 'gateway-1' : 'gateway-2';
  const c = client(clientId, `copilot${node.toUpperCase()}Policy`, `copilot${node.toUpperCase()}JWT`,load(`${clientKey}.jwks.json`));
  const preliminary = { ...c, enabled: false, defaultAccessTokenManagerRef: undefined, restrictToDefaultAccessTokenManager: false };
  await upsert(node,'oauth/clients',clientId,preliminary);
  const atm = tokenManager(node,nodes[node].issuer,node === 'a' ? 'api://gateway-2' : 'api://copilot-broker');
  await upsert(node,'oauth/accessTokenManagers',atm.id,atm);
  const mapping = accessTokenMapping(node);
  const mappings = await admin(node,'oauth/accessTokenMappings');
  const existing = (Array.isArray(mappings) ? mappings : mappings.items).find(m => m.context?.contextRef?.id === mapping.context.contextRef.id && m.accessTokenManagerRef?.id === atm.id);
  await admin(node,existing ? `oauth/accessTokenMappings/${encodeURIComponent(existing.id)}` : 'oauth/accessTokenMappings',existing ? 'PUT' : 'POST',mapping);
  await upsert(node,'oauth/clients',clientId,c);
  console.log(`PF ${node}: configured JWT validation, signed client authentication and exchange mappings`);
}
const trust = (node,audience) => ({ issuer: nodes[node].issuer, jwksUri: nodes[node].issuer+'/pf/JWKS', audience, algorithms: ['RS256'], keyIds: [`copilot-${node}-signing`], organisations: [profile.org], actorIssuers: [profile.agentIssuer], maxLifetimeSeconds: 240 });
save('exchange-config.json', { upstream: [trust('a','api://gateway-2')], downstream: trust('b','api://copilot-broker'), tokenEndpoint: nodes.b.issuer+'/as/token.oauth2', targetParameter: 'resource', clientId: 'gateway-2-token-exchange', clientKeyId: 'copilot-gateway-2', clientAlgorithm: 'RS256', clientAssertionAudience: nodes.b.issuer, scope: profile.scope, timeoutMs: 5000 });
console.log('Container exchange configuration ready; private keys remain in ignored local storage.');
