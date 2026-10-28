import { randomUUID } from 'node:crypto';
import { createRemoteJWKSet, customFetch, decodeJwt, jwtVerify, SignJWT } from 'jose';
import { ExchangeError, type DelegatedClaims, type TokenVerifier, type TokenExchanger } from './token-exchange.ts';

export type IssuerTrust = {
  issuer: string; jwksUri: string; audience: string; algorithms: string[]; keyIds: string[];
  organisations: string[]; actorIssuers: string[]; maxLifetimeSeconds: number;
};
export type PingFederateConfig = {
  upstream: IssuerTrust[]; downstream: IssuerTrust; tokenEndpoint: string;
  clientId: string; clientKeyId: string; clientAlgorithm: string; scope: string; timeoutMs: number;
};
export type Dependencies = {
  clientKey: CryptoKey;
  // Must consult authoritative current grant, organisation and agent state. Never a chat/header claim.
  authorise: (claims: Readonly<DelegatedClaims>) => Promise<void>;
  fetch?: typeof fetch;
  observe?: (event: { event: 'pf_b_exchange'; outcome: 'success' | 'failure'; code?: string; durationMs: number }) => void;
};
const algorithms = ['RS256', 'PS256', 'ES256'];
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 2048;
function https(value: string) {
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || u.search) throw new ExchangeError('configuration');
}
function validateTrust(t: IssuerTrust) {
  https(t.issuer); https(t.jwksUri);
  if (!text(t.audience) || !t.algorithms.length || t.algorithms.some(a => !algorithms.includes(a)) ||
      !t.keyIds.length || !t.keyIds.every(text) || !t.organisations.length || !t.organisations.every(text) ||
      !t.actorIssuers.length || !t.actorIssuers.every(text) ||
      !Number.isInteger(t.maxLifetimeSeconds) || t.maxLifetimeSeconds < 1 || t.maxLifetimeSeconds > 600) throw new ExchangeError('configuration');
}
function identity(payload: Record<string, unknown>, trust: IssuerTrust, scope: string): DelegatedClaims {
  const actor = payload.act as Record<string, unknown> | undefined;
  if (payload.aud !== trust.audience || !text(payload.sub) || !actor || Array.isArray(actor) ||
      !text(actor.sub) || !text(actor.iss) || !trust.actorIssuers.includes(actor.iss) ||
      Object.keys(actor).some(k => k !== 'sub' && k !== 'iss') ||
      !text(payload.org_id) || !trust.organisations.includes(payload.org_id) ||
      !text(payload.delegation_id) || !text(payload.jti) || payload.scope !== scope ||
      !['interactive', 'autonomous'].includes(String(payload.execution_mode)) ||
      !Number.isInteger(payload.iat) || !Number.isInteger(payload.nbf) || !Number.isInteger(payload.exp) ||
      Number(payload.exp) <= Number(payload.iat) || Number(payload.exp) - Number(payload.iat) > trust.maxLifetimeSeconds ||
      Number(payload.iat) > Math.floor(Date.now() / 1000) + 5 || Number(payload.nbf) > Number(payload.exp)) throw new ExchangeError('invalid_token');
  return payload as DelegatedClaims;
}

export class JwksTokenVerifier implements TokenVerifier {
  private entries: { trust: IssuerTrust; keys: ReturnType<typeof createRemoteJWKSet> }[];
  private scope: string;
  constructor(trusts: IssuerTrust[], scope: string, timeoutMs: number, transport: typeof fetch = fetch) {
    this.scope = scope;
    this.entries = trusts.map(original => {
      const trust = structuredClone(original);
      validateTrust(trust);
      const keys = createRemoteJWKSet(new URL(trust.jwksUri), {
        timeoutDuration: timeoutMs, cooldownDuration: 5000, cacheMaxAge: 60000,
        [customFetch]: async (url, init) => {
          // URL is pinned configuration; JWT jku/x5u never selects a network destination.
          if (String(url) !== trust.jwksUri) throw new ExchangeError('invalid_token');
          // One retry for idempotent JWKS GET only. POST issuance is never retried.
          for (let attempt = 0; ; attempt++) {
            try { return await transport(url, { ...init, redirect: 'error' }); }
            catch { if (attempt || init?.signal?.aborted) throw new ExchangeError('invalid_token'); }
          }
        },
      });
      return { trust, keys };
    });
  }
  async verify(token: string): Promise<DelegatedClaims> {
    try {
      if (typeof token !== 'string' || token.length > 16000) throw Error();
      // Unverified issuer only indexes a closed, configured registry. It never supplies a URL.
      const entry = this.entries.find(e => e.trust.issuer === decodeJwt(token).iss);
      if (!entry) throw Error();
      const { trust, keys } = entry;
      const { payload } = await jwtVerify(token, async (header, jwt) => {
        if (!text(header.kid) || !trust.keyIds.includes(header.kid) || header.jku || header.x5u || header.jwk || header.x5c) throw Error();
        return keys(header, jwt);
      }, { issuer: trust.issuer, audience: trust.audience, algorithms: trust.algorithms, clockTolerance: 5,
        requiredClaims: ['sub', 'iat', 'nbf', 'exp', 'jti'], maxTokenAge: trust.maxLifetimeSeconds });
      return identity(payload, trust, this.scope);
    } catch { throw new ExchangeError('invalid_token'); }
  }
}

export class PingFederateExchange implements TokenExchanger {
  private config: PingFederateConfig;
  private deps: Dependencies;
  private incoming: TokenVerifier;
  private outgoing: TokenVerifier;
  constructor(config: PingFederateConfig, dependencies: Dependencies) {
    try {
      this.config = structuredClone(config);
      this.deps = { ...dependencies };
      https(config.tokenEndpoint);
      if (!config.upstream.length || new Set(config.upstream.map(t => t.issuer)).size !== config.upstream.length ||
          !text(config.clientId) || !text(config.clientKeyId) || !algorithms.includes(config.clientAlgorithm) ||
          !text(config.scope) || /\s/.test(config.scope) || !Number.isInteger(config.timeoutMs) || config.timeoutMs < 100 || config.timeoutMs > 30000 ||
          typeof dependencies.authorise !== 'function' || dependencies.clientKey.type !== 'private') throw Error();
      this.incoming = new JwksTokenVerifier(this.config.upstream, config.scope, config.timeoutMs, dependencies.fetch);
      this.outgoing = new JwksTokenVerifier([this.config.downstream], config.scope, config.timeoutMs, dependencies.fetch);
    } catch { throw new ExchangeError('configuration'); }
  }
  private async policy(claims: DelegatedClaims) {
    try {
      // A timeout also applies to the required online policy call. Copy prevents mutation of verified claims.
      let timer: ReturnType<typeof setTimeout> | undefined;
      try { await Promise.race([this.deps.authorise(structuredClone(claims)), new Promise((_, reject) => { timer = setTimeout(() => reject(Error()), this.config.timeoutMs); })]); }
      finally { clearTimeout(timer); }
    } catch { throw new ExchangeError('policy_denied'); }
  }
  async exchange(token: string): Promise<{ accessToken: string; claims: DelegatedClaims }> {
    const started = Date.now();
    const observe = (outcome: 'success' | 'failure', code?: string) => {
      try { this.deps.observe?.({ event: 'pf_b_exchange', outcome, code, durationMs: Date.now() - started }); } catch { /* telemetry cannot change authority */ }
    };
    try {
      const original = await this.incoming.verify(token);
      await this.policy(original);
      const c = this.config;
      const assertion = await new SignJWT({}).setProtectedHeader({ alg: c.clientAlgorithm, kid: c.clientKeyId, typ: 'JWT' })
        .setIssuer(c.clientId).setSubject(c.clientId).setAudience(c.tokenEndpoint).setIssuedAt()
        .setExpirationTime('60s').setJti(randomUUID()).sign(this.deps.clientKey);
      const response = await (this.deps.fetch ?? fetch)(c.tokenEndpoint, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(c.timeoutMs),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: token, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          requested_token_type: 'urn:ietf:params:oauth:token-type:access_token', audience: c.downstream.audience,
          scope: c.scope, client_id: c.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion }),
      });
      if (!response.ok) throw new ExchangeError('exchange_failed');
      // Bound response consumption even if an upstream sends a streaming body.
      let raw = '';
      for await (const chunk of response.body ?? []) {
        raw += Buffer.from(chunk).toString('utf8');
        if (raw.length > 32768) throw new ExchangeError('exchange_failed');
      }
      const result = JSON.parse(raw);
      if (result.token_type !== 'Bearer' || result.issued_token_type !== 'urn:ietf:params:oauth:token-type:access_token' ||
          typeof result.access_token !== 'string' || !Number.isInteger(result.expires_in) || result.expires_in <= 0 ||
          result.expires_in > c.downstream.maxLifetimeSeconds || (result.scope !== undefined && result.scope !== c.scope)) throw new ExchangeError('exchange_failed');
      const claims = await this.outgoing.verify(result.access_token);
      for (const key of ['sub', 'org_id', 'delegation_id', 'execution_mode', 'scope'] as const) {
        if (claims[key] !== original[key]) throw new ExchangeError('invalid_token');
      }
      if (claims.act.sub !== original.act.sub || claims.act.iss !== original.act.iss || claims.exp > original.exp) throw new ExchangeError('invalid_token');
      await this.policy(claims);
      // Do not release a token that expired while online checks were running.
      if (Math.min(claims.exp, original.exp) <= Math.floor(Date.now() / 1000)) throw new ExchangeError('invalid_token');
      observe('success');
      return { accessToken: result.access_token, claims };
    } catch (error) {
      const safe = error instanceof ExchangeError ? error : new ExchangeError('exchange_failed');
      observe('failure', safe.code);
      throw safe;
    }
  }
}
