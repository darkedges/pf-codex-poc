import test from 'node:test';
import assert from 'node:assert/strict';
import { processor, client, tokenManager, exchangePolicy } from '../scripts/pf/config.mjs';
import { redactLogConfig, jwtPattern } from '../scripts/pf/logging-config.mjs';
test('container processors require signature-bound issuer/audience and all token times', () => {
  const p = processor('test', 'https://issuer.example', 'api://target', { keys: [] });
  assert.equal(p.configuration.fields.find(f => f.name === 'Require Audience').value, 'true');
  assert.equal(p.configuration.fields.find(f => f.name === 'Require Expiration Time').value, 'true');
  assert.equal(p.configuration.tables[0].rows[0].fields[0].value, 'https://issuer.example');
});
test('container clients allow signed JWT authentication and token exchange only', () => {
  const c = client('gateway-2', 'policy', 'atm', { keys: [] });
  assert.equal(c.clientAuth.type, 'PRIVATE_KEY_JWT');
  assert.equal(c.clientAuth.enforceReplayPrevention, true);
  assert.equal(c.clientAuth.tokenEndpointAuthSigningAlgorithm, 'RS256');
  assert.deepEqual(c.grantTypes, ['TOKEN_EXCHANGE']);
  assert.deepEqual(c.restrictedScopes, ['copilot.invoke']);
  assert.equal(c.restrictToDefaultAccessTokenManager, true);
});
test('each token manager has pinned next-hop audience and restricted clients', () => {
  const t = tokenManager('b', 'https://localhost:9034', 'api://copilot-broker');
  assert.equal(t.accessControlSettings.restrictClients, true);
  assert.deepEqual(t.accessControlSettings.allowedClients, [{ id: 'gateway-2-token-exchange' }]);
  assert.equal(t.configuration.fields.find(f => f.name === 'Audience Claim Value').value, 'api://copilot-broker');
});
test('PF A requires independent actor proof; PF B consumes the established signed actor chain', () => {
  assert.equal(exchangePolicy('a').actorTokenRequired, true);
  assert.equal(exchangePolicy('b').actorTokenRequired, false);
  assert.equal(exchangePolicy('b').processorMappings[0].subjectTokenProcessor.id, 'copilotUpstream');
});
test('container logs filter credential-bearing events and redact throwable layouts idempotently', () => {
  const sample='<Configuration><Appenders><PatternLayout pattern="%m%n"/><PatternLayout><Pattern>%m%ex</Pattern></PatternLayout></Appenders></Configuration>';
  const xml=redactLogConfig(sample);
  assert.equal(xml.match(/<replace /g)?.length,2);
  assert.ok(xml.includes('onMatch="DENY"'));
  assert.equal(redactLogConfig(xml),xml);
  assert.equal('invalid eyJabcdefghijk.payload.signature'.replace(new RegExp(jwtPattern,'g'),'[REDACTED_JWT]'),'invalid [REDACTED_JWT]');
});
