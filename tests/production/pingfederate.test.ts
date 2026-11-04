import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, decodeJwt, decodeProtectedHeader } from 'jose';
import { PingFederateExchange, JwksTokenVerifier } from '../../src/adapters/pingfederate.ts';
import { createGateway2Exchange } from '../../src/adapters/gateway-2.ts';
import { gateway2FromEnvironment } from '../../src/adapters/pingfederate-env.ts';

const a = await generateKeyPair('RS256');
const b = await generateKeyPair('RS256');
const client = await generateKeyPair('RS256');
const issuerA = 'https://a.example';
const issuerB = 'https://b.example';
const endpoint = issuerB + '/as/token.oauth2';
const base = { sub: 'partner:user', act: { sub: 'partner:agent', iss: issuerA }, org_id: 'partner', delegation_id: 'grant-1', execution_mode: 'interactive', scope: 'copilot.invoke' };
async function token(issuer = issuerA, claims = {}, header = {}) {
  return new SignJWT({ ...base, ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'key-1', ...header })
    .setIssuer(issuer).setAudience(issuer === issuerA ? 'api://gateway-2' : 'api://copilot-broker')
    .setIssuedAt().setNotBefore('0s').setExpirationTime(issuer === issuerA ? '120s' : '110s').setJti(crypto.randomUUID())
    .sign(issuer === issuerA ? a.privateKey : b.privateKey);
}
function setup(options: { output?: Record<string, unknown>; policy?: () => Promise<void>; response?: () => Response; telemetry?: (event: unknown) => void } = {}) {
  const posts: URLSearchParams[] = [];
  const requests: string[] = [];
  const transport: typeof fetch = async (url, init) => {
    requests.push(String(url));
    if (String(url).endsWith('/jwks')) {
      const key = await exportJWK(String(url).startsWith(issuerA) ? a.publicKey : b.publicKey);
      return Response.json({ keys: [{ ...key, kid: 'key-1', alg: 'RS256', use: 'sig' }] });
    }
    assert.equal(String(url), endpoint);
    assert.equal(init?.redirect, 'error');
    const form = new URLSearchParams(String(init?.body));
    posts.push(form);
    assert.equal(decodeProtectedHeader(form.get('client_assertion')!).typ,'client-authentication+jwt');
    const assertion = await jwtVerify(form.get('client_assertion')!, client.publicKey, { issuer: 'gateway-2', audience: endpoint });
    assert.equal(assertion.payload.sub, 'gateway-2');
    assert.ok(assertion.payload.jti);
    assert.ok(assertion.payload.exp! - assertion.payload.iat! <= 60);
    if (options.response) return options.response();
    return Response.json({ access_token: await token(issuerB, options.output), token_type: 'Bearer', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', expires_in: 120 });
  };
  const trust = (issuer: string, audience: string) => ({ issuer, audience, jwksUri: issuer + '/jwks', algorithms: ['RS256'], keyIds: ['key-1'], organisations: ['partner'], actorIssuers: [issuerA], maxLifetimeSeconds: 180 });
  const config = { upstream: [trust(issuerA, 'api://gateway-2')], downstream: trust(issuerB, 'api://copilot-broker'), tokenEndpoint: endpoint, clientId: 'gateway-2', clientKeyId: 'client-1', clientAlgorithm: 'RS256', scope: 'copilot.invoke', timeoutMs: 1000 };
  return { adapter: new PingFederateExchange(config, { clientKey: client.privateKey, authorise: options.policy ?? (async () => {}), fetch: transport, observe: options.telemetry }), posts, requests, config, transport };
}
for (const mode of ['interactive', 'autonomous']) test(`preserves identities and signs client authentication: ${mode}`, async () => {
  const s = setup({ output: { execution_mode: mode } });
  const result = await s.adapter.exchange(await token(issuerA, { execution_mode: mode }));
  assert.equal(result.claims.sub, base.sub);
  assert.deepEqual(result.claims.act, base.act);
  assert.equal(s.posts[0].get('audience'), 'api://copilot-broker');
  assert.equal(s.posts[0].get('scope'), 'copilot.invoke');
  assert.equal(s.posts[0].get('actor_token'), null);
});
for (const [name, claims, header] of [
  ['missing actor', { act: undefined }, {}], ['wrong organisation', { org_id: 'other' }, {}],
  ['wrong actor issuer', { act: { ...base.act, iss: 'https://evil.example' } }, {}],
  ['missing grant', { delegation_id: '' }, {}], ['invalid mode', { execution_mode: 'other' }, {}],
  ['scope expansion', { scope: 'copilot.invoke admin' }, {}], ['unknown kid', {}, { kid: 'evil' }],
  ['remote key injection', {}, { jku: 'https://evil.example/jwks' }],
] as const) test(`rejects upstream ${name} before exchange`, async () => {
  const s = setup();
  await assert.rejects(s.adapter.exchange(await token(issuerA, claims, header)));
  assert.equal(s.posts.length, 0);
});
for (const [name, value] of Object.entries({ sub: 'other', act: { sub: 'gateway-2', iss: issuerB }, org_id: 'other', delegation_id: 'other', execution_mode: 'autonomous', scope: 'copilot.invoke admin' })) test(`rejects downstream mutation of ${name}`, async () => {
  const s = setup({ output: { [name]: value } });
  await assert.rejects(s.adapter.exchange(await token()));
});
test('policy outage/revocation fails closed before issuance', async () => {
  const s = setup({ policy: async () => { throw Error('revoked'); } });
  await assert.rejects(s.adapter.exchange(await token()));
  assert.equal(s.posts.length, 0);
});
test('policy rechecked after issuance', async () => {
  let calls = 0;
  const s = setup({ policy: async () => { if (++calls === 2) throw Error('revoked'); } });
  await assert.rejects(s.adapter.exchange(await token()));
  assert.equal(calls, 2);
});
test('upstream errors sanitized and exchange POST never retried', async () => {
  const events: unknown[] = [];
  const s = setup({ response: () => new Response('SECRET', { status: 503 }), telemetry: e => events.push(e) });
  await assert.rejects(s.adapter.exchange(await token()), e => !String(e).includes('SECRET'));
  assert.equal(s.posts.length, 1);
  assert.ok(!JSON.stringify(events).includes('SECRET'));
});
test('configuration refuses insecure endpoints', () => {
  const s = setup();
  assert.throws(() => new PingFederateExchange({ ...s.config, tokenEndpoint: 'http://localhost/token' }, { clientKey: client.privateKey, authorise: async () => {} }));
  assert.throws(() => new PingFederateExchange({ ...s.config, clientAssertionAudience: 'http://localhost' }, { clientKey: client.privateKey, authorise: async () => {} }));
  assert.throws(() => new PingFederateExchange({ ...s.config, targetParameter: 'untrusted' } as never, { clientKey: client.privateKey, authorise: async () => {} }));
});
test('explicit PingFederate client assertion audience is configuration-bound', async () => {
  const s = setup();
  let observed = false;
  const adapter = new PingFederateExchange({ ...s.config, clientAssertionAudience: issuerB }, {
    clientKey: client.privateKey, authorise: async () => {}, fetch: async (url, init) => {
      if (String(url).endsWith('/jwks')) return s.transport(url, init);
      const form = new URLSearchParams(String(init?.body));
      await jwtVerify(form.get('client_assertion')!,client.publicKey,{issuer:'gateway-2',audience:issuerB});
      observed = true;
      return Response.json({ access_token: await token(issuerB), token_type:'Bearer',issued_token_type:'urn:ietf:params:oauth:token-type:access_token',expires_in:110 });
    },
  });
  await adapter.exchange(await token());
  assert.equal(observed,true);
});
test('resource selection for PingFederate ATM is configuration-bound', async () => {
  const s = setup();
  let observed = false;
  const adapter = new PingFederateExchange({ ...s.config, targetParameter: 'resource',requestedResource:'urn:copilot:consent:broker' }, {
    clientKey: client.privateKey, authorise: async () => {}, fetch: async (url, init) => {
      if (String(url).endsWith('/jwks')) return s.transport(url, init);
      const form = new URLSearchParams(String(init?.body));
      assert.equal(form.get('audience'),null);
      assert.equal(form.get('resource'),'urn:copilot:consent:broker');
      observed = true;
      return Response.json({access_token:await token(issuerB),token_type:'Bearer',issued_token_type:'urn:ietf:params:oauth:token-type:access_token',expires_in:110});
    },
  });
  await adapter.exchange(await token());
  assert.equal(observed,true);
});

test('client assertions use a fresh jti on every exchange', async () => {
  const s = setup();
  const original = await token();
  await s.adapter.exchange(original);
  await s.adapter.exchange(original);
  assert.notEqual(decodeJwt(s.posts[0].get('client_assertion')!).jti, decodeJwt(s.posts[1].get('client_assertion')!).jti);
});
test('online policy receives the signed token at each exchange boundary',async()=>{
  const s=setup();const original=await token();let calls=0;
  const adapter=new PingFederateExchange(s.config,{clientKey:client.privateKey,fetch:s.transport,authorise:async(claims,evidence)=>{
    assert.equal(typeof evidence?.accessToken,'string');
    assert.equal(evidence!.accessToken===original,calls===0);
    assert.equal(claims.iss,calls++===0?issuerA:issuerB);
  }});
  await adapter.exchange(original);assert.equal(calls,2);
});
for (const [name, patch, header] of [
  ['issuer', { iss: 'https://evil.example' }, {}],
  ['audience', { aud: 'api://other' }, {}],
  ['multiple audiences', { aud: ['api://gateway-2', 'api://other'] }, {}],
  ['expired', { exp: 1 }, {}], ['future nbf', { nbf: Math.floor(Date.now() / 1000) + 100 }, {}],
  ['future iat', { iat: Math.floor(Date.now() / 1000) + 100 }, {}],
  ['excess lifetime', { exp: Math.floor(Date.now() / 1000) + 1000 }, {}],
  ['missing expiration', { exp: undefined }, {}], ['missing jti', { jti: undefined }, {}],
] as const) test(`rejects signed token with invalid ${name}`, async () => {
  const s = setup();
  const payload = { ...decodeJwt(await token()), ...patch };
  const invalid = await new SignJWT(payload).setProtectedHeader({ alg: 'RS256', kid: 'key-1', ...header }).sign(a.privateKey);
  await assert.rejects(s.adapter.exchange(invalid));
  assert.equal(s.posts.length, 0);
});
test('signature tampering and symmetric algorithm substitution reject', async () => {
  const s = setup();
  const parts = (await token()).split('.');
  parts[1] = Buffer.from(JSON.stringify({ ...decodeJwt(parts.join('.')), sub: 'admin' })).toString('base64url');
  await assert.rejects(s.adapter.exchange(parts.join('.')));
  const hs = await new SignJWT(decodeJwt(await token())).setProtectedHeader({ alg: 'HS256', kid: 'key-1' }).sign(new Uint8Array(32));
  await assert.rejects(s.adapter.exchange(hs));
  assert.equal(s.posts.length, 0);
});
test('JWKS outage retries GET only and fails closed', async () => {
  let calls = 0;
  const s = setup();
  const v = new JwksTokenVerifier(s.config.upstream, s.config.scope, 100, async () => { calls++; throw Error('SECRET'); });
  await assert.rejects(v.verify(await token()), e => String(e) === 'ExchangeError: invalid_token');
  assert.equal(calls, 2);
});
test('JWKS cache supports configured overlapping rotation keys', async () => {
  const s = setup();
  const rotated = await generateKeyPair('RS256');
  let calls = 0;
  const trust = { ...s.config.upstream[0], keyIds: ['key-1', 'key-2'] };
  const v = new JwksTokenVerifier([trust], s.config.scope, 1000, async () => {
    calls++;
    return Response.json({ keys: [{ ...await exportJWK(a.publicKey), kid: 'key-1' }, { ...await exportJWK(rotated.publicKey), kid: 'key-2' }] });
  });
  await v.verify(await token());
  const next = await new SignJWT(decodeJwt(await token())).setProtectedHeader({ alg: 'RS256', kid: 'key-2' }).sign(rotated.privateKey);
  await v.verify(next);
  assert.equal(calls, 1);
});
test('policy has bounded timeout', async () => {
  const s = setup();
  const adapter = new PingFederateExchange({ ...s.config, timeoutMs: 100 }, { clientKey: client.privateKey, authorise: () => new Promise(() => {}), fetch: async url => {
    assert.equal(String(url), issuerA + '/jwks');
    return Response.json({ keys: [{ ...await exportJWK(a.publicKey), kid: 'key-1' }] });
  } });
  await assert.rejects(adapter.exchange(await token()), e => String(e) === 'ExchangeError: policy_denied');
});
for (const response of [
  () => new Response('not json'),
  () => Response.json({ access_token: 'bad', token_type: 'MAC' }),
  () => Response.json({ access_token: 'bad', token_type: 'Bearer', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', expires_in: 120 }),
  () => new Response('x'.repeat(40000)),
]) test('malformed downstream responses fail closed', async () => {
  const s = setup({ response });
  await assert.rejects(s.adapter.exchange(await token()));
});
test('missing production configuration and unknown modes never fall back to mock', async () => {
  await assert.rejects(gateway2FromEnvironment(async () => {}, undefined, {}));
  await assert.rejects(createGateway2Exchange({ mode: 'unknown' } as never));
});
test('client authentication rejection is terminal and sanitized', async () => {
  const s = setup({ response: () => Response.json({ error: 'invalid_client', error_description: 'SECRET' }, { status: 401 }) });
  await assert.rejects(s.adapter.exchange(await token()), e => String(e) === 'ExchangeError: exchange_failed');
  assert.equal(s.posts.length, 1);
});
test('outbound token request timeout fails closed without a retry', async () => {
  const s = setup();
  let posts = 0;
  const adapter = new PingFederateExchange({ ...s.config, timeoutMs: 100 }, {
    clientKey: client.privateKey, authorise: async () => {}, fetch: async (url, init) => {
      if (String(url).endsWith('/jwks')) return s.transport(url, init);
      posts++;
      return new Promise((_, reject) => init!.signal!.addEventListener('abort', () => reject(Error('SECRET')), { once: true }));
    },
  });
  // Keep the test runner alive while AbortSignal.timeout's unref'ed timer runs.
  const keepAlive = setInterval(() => {}, 1000);
  try { await assert.rejects(adapter.exchange(await token()), e => String(e) === 'ExchangeError: exchange_failed'); }
  finally { clearInterval(keepAlive); }
  assert.equal(posts, 1);
});
for (const patch of [{ iss: issuerA }, { aud: 'api://gateway-2' }, { exp: 1 }]) test('rejects downstream issuer/audience/expiry substitution', async () => {
  const s = setup();
  const adapter = new PingFederateExchange(s.config, { clientKey: client.privateKey, authorise: async () => {}, fetch: async (url, init) => {
    if (String(url).endsWith('/jwks')) return s.transport(url, init);
    const access_token = await new SignJWT({ ...decodeJwt(await token(issuerB)), ...patch }).setProtectedHeader({ alg: 'RS256', kid: 'key-1' }).sign(b.privateKey);
    return Response.json({ access_token, token_type: 'Bearer', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', expires_in: 110 });
  } });
  await assert.rejects(adapter.exchange(await token()));
});
