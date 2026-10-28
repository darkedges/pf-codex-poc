# Codex Implementation Backlog

## Completed in this starter

- [x] Runnable local PingFederate A and B mock token exchange chain
- [x] Typed user + actor claims carried across audiences
- [x] Local grant intersection check (user, agent, mode, scope, resource)
- [x] Short-lived mock autonomous delegation assertions
- [x] Mock Copilot+Microsoft 365 resource response with `simulation: true`
- [x] Unit tests for revocation, token tampering, issuer and audience checks
- [x] Smoke check for interactive/autonomous and default-deny cases
- [x] Codex instructions, architecture and setup documents

## Phase 1 — Production-capable identity foundation

- [x] Gateway 2 production exchange adapter: explicit HTTPS issuer/JWKS registries, pinned algorithm/kid allowlists, bounded cached JWKS rollover, `private_key_jwt`, strict PF B response validation and identity continuity. Production policy dependency is mandatory; no fixture fallback. See `docs/gateway-2-production.md`.
- [x] Isolated mock adapter keeps the dependency-free local chain working; separate production tests exercise both execution modes and rejection paths.
- Validation: `npm run keys`, `npm test` (12 tests), `npm run test:production` (44 tests), and isolated loopback demo startup plus `scripts/smoke.mjs` (interactive/autonomous 200; revoked/unapproved resource 403). Default ports were already occupied, so smoke used a separate loopback address with unchanged service ports.
- [ ] **UNVERIFIED:** live PF B client registration, assertion replay enforcement, processor mappings, revocation and TLS/key rollover. Execute the integration plan in `docs/gateway-2-production.md` before approval.
- [ ] Implement `TokenVerifier` and `TokenExchanger` adapters for PF A and B; use hardened JOSE, verified HTTPS discovery/JWKS with key rotation and pinning; support TLS/mTLS and `private_key_jwt`.
- [ ] Implement trusted issuer + organisation registry, including algorithm and audience allowlists.
- [ ] Replace mock grant fixture with transactional persistence and an authenticated policy decision API.
- [ ] Implement consent/approval evidence and grant create/revoke/renew flows, with guaranteed status enforcement.
- [ ] Replace mock autonomous proof with secure delegation authority private keys, policy and anti-replay.
- [ ] Prove local auth rejection when downstream validation is unavailable.
- [ ] Integration-test real PF processor policy mappings, `sub`, `act`, revocation and token lifetimes.

## Phase 2 — Copilot Studio

- [ ] Add Direct Line client with secured secret storage and per-conversation channel token.
- [ ] Implement OAuth card challenge handling and the *documented* secure URL token-post mechanism.
- [ ] Verify tool can read `System.User.AccessToken` and securely call a broker API.
- [ ] Ensure tool tokens are separately audienced and expiry/refresh is correct.
- [ ] Validate interactive **and autonomous** sign-in behavior in your actual Power Platform environment; fail closed if unsupported.
- [ ] Confirm Power Platform DLP, authentication and maker credential policies do not silently change execution authority.

## Phase 3 — Microsoft 365 app-only data access

- [ ] Register dedicated Entra application; prefer managed identity or certificate-based authentication.
- [ ] Admin-consent only `Sites.Selected`, then assign explicit read-only site grants.
- [ ] Build a Graph adapter with an allowlist of IDs/paths controlled by policy, not LLM input.
- [ ] Add pagination, rate limits, response filtering and site-scoped search/read tools.
- [ ] Prove a partner cannot retrieve documents outside its resource entitlements, even though broker app can see several approved sites.
- [ ] Add dedicated per-capability app identities for Exchange/Teams if required later.

## Phase 4 — Operations

- [ ] Use remote secret management, private networking, audit pipeline, metrics and traces.
- [ ] Add structured audit keyed by issuer+subject, actor, organisation, grant and resource.
- [ ] Rotate keys and certificates; implement external organisation and agent suspension.
- [ ] Deploy with pinned images, non-root, admission controls and network policies.
- [ ] Threat model and security review; document data retention and no-token-logging enforcement.

## Risk to validate first

Copilot Studio Generic OAuth SSO support for fresh *autonomous* grant-backed user tokens. The Microsoft documentation establishes token-post SSO for Direct Line, but this particular unattended trust flow must be proven in a live tenant and with supported licensing/channel policy. No workaround that skips delegated authorization is acceptable.
