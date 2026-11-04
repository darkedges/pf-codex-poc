# Authenticated consent authority

The exchange caller requests a fresh assertion from the HTTPS policy service. It no longer imports the authority key or opens the policy database. The registered agent's original issuer/subject are derived from the verified workload credential and independently matched against its signed actor proof and consent-backed grant. Human identity comes from the grant's registered owner. No Entra user is created.

## Protocol and trust

```mermaid
sequenceDiagram
  participant W as Agent / Gateway 1
  participant P as HTTPS policy + authority service
  participant S as AssertionSigner
  participant A as PF A https://localhost:9033
  participant B as PF B https://localhost:9034
  W->>P: POST /v1/assertions + body-bound workload signature
  P->>P: Consume persistent request jti; bind caller to registered actor
  P->>P: Verify actor proof, consent, mode, operation and current grant
  P->>S: Sign 60-second assertion for api://pf-a/consent-proof
  S-->>P: Signed assertion
  P->>P: Recheck grant, registry, login freshness and assertion expiry
  P-->>W: Assertion, expiresIn 60 (no-store)
  W->>A: Assertion + independent actor proof + private_key_jwt
  A-->>W: Token for api://gateway-2
  W->>B: Gateway 2 verifies token/policy and exchanges with private_key_jwt
  B-->>W: Token for api://copilot-broker, independently verified and policy-checked
```

The lab policy service binds only `127.0.0.1`; its default origin is `https://localhost:9450`. Test/portal launchers use an ephemeral loopback port. These origins are configured server-side, never derived from the Host header. PF issuer and token audiences are unchanged.

`POST /v1/assertions` accepts exactly `grantId`, `mode`, `operation`, `agentToken`, and optional `login: {idToken, nonce}`. Only interactive mode accepts login evidence and requires a current matching verified login. Autonomous mode uses active persisted human consent and rejects a supplied login. The sole configured operation is `copilot.invoke`, mapped server-side to `sharepoint:approved-research`; callers cannot select a resource or scope. An administrative grant without the actual human-consent record cannot mint an assertion.

Authenticate with the existing `Authorization: Policy <JWT>` protocol: RS256, `typ: policy-request+jwt`, registered kid, workload issuer/subject, exact endpoint audience, POST, exact body SHA-256, at most 60 seconds, and unique jti. The complete signed body binds grant, mode, operation, actor proof and interactive login evidence. Consume jti in SQLite before issuance, including failed issuance; do not retry the request automatically. Reusing jti after another service process starts, or across key rotation, still fails. The underlying actor proof remains independently verified at both the authority and PF A.

Only `policy-agent` has the `authority` role, pinned to the configured agent issuer/subject and organisation. Decision, consent and administrator roles confer no issuance permission. Registry/grant checks run before and after asynchronous signing; revocation or suspension prevents release. The authority assertion adds signed operation/resource claims. **PF A/B currently preserve the existing identity, grant, mode and scope contract; they do not propagate these additional operation/resource claims.** The future broker must independently authorise each actual resource operation. The assertion is not a reusable grant or a Graph token.

Responses use `Cache-Control: no-store`. Errors contain only `invalid_request` (400), `unauthenticated` (401, including replay), `forbidden` (403), or `unavailable` (503 for recognised signer outages). Never log request/response bodies or authorization headers. Existing structured status/duration telemetry and grant decision audits contain no credentials; authority audits identify the authenticated workload.

## Signing backends

`AssertionSigner` is a typed interface. The service requires explicit `AUTHORITY_SIGNER`; unknown/missing values fail startup. Lab launchers use the explicitly selected local backend profile; a fresh lab starts with development, while `vault:up` selects the live Vault profile. Invalid selected Vault configuration never falls back. These are lab launchers, not production deployment entry points. See the [live Vault guide](vault-containers.md).

`development` holds the ignored `consent-authority.private.pem` only inside the authority service process. The gateway/exchange path holds its own `policy-agent` request key and independent actor/client credentials. This same-user local lab **does not provide OS-enforced workload isolation**: production deployment must deny agent/gateway access to authority credentials, database files, signing-service credentials and provisioning administration.

`vault-transit` signs using the configured HTTPS Vault endpoint without loading an authority private key. Configure the ignored `.local/pingfederate/authority-transit-config.json` with:

| Field | Meaning |
|---|---|
| `origin` | Trusted HTTPS Vault origin, no path, userinfo, query or fragment |
| `mount`, `name` | Approved single-segment Transit mount and RSA signing key name |
| `version` | Explicit positive key version; automatic latest-version selection is refused |
| `kid` | Approved JWT signing key ID published to PF A |
| `publicJwk` | Trusted RSA public JWK corresponding to exactly that key version |
| `timeoutMs` | Integer 100–30000, covering HTTP request and response |

Set `AUTHORITY_VAULT_TOKEN_FILE` to an authority-only secret-manager/agent-mounted credential file. The file is read for every signing request so an external workload-auth agent can renew it; this adapter does not implement Vault login or token renewal. Provision least-privilege access only to the chosen Transit sign path, not key export/configuration. Vault key creation, non-exportability, workload authentication and file permissions require deployment verification.

The signer calls `/v1/{mount}/sign/{name}/sha2-256` with the JWS signing input, explicit key version and `signature_algorithm: pkcs1v15` for RS256. It rejects redirects, HTTP failures, oversized/malformed responses, unexpected returned key versions and signatures that fail independent JOSE verification against the pinned public key. A bounded timeout applies; signing has no retries and no development fallback. Vault details and credentials never appear in errors. See the [Vault Transit signing API](https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data).

## Rotation and live deployment gate

Workload registries support a current public key plus explicit `previousKeys` overlap. The local service reads the approved public JWKS file for each policy role at startup: the first key is current, remaining keys are accepted overlap. Deploy the new public key before switching the caller's private key/kid. After outstanding requests expire (60 seconds plus 5-second clock tolerance), remove retired keys and restart the service. Replay IDs are scoped to workload identity, not kid. Retirement takes effect on config reload/restart, not by merely modifying a file.

For authority rotation, `vault:rotate` first publishes the new public key/kid in PF A's `consentGrantProof` trusted JWKS with overlap, then selects the matching Vault version/kid/public JWK for newly started authority processes. Restart/drain old processes and wait assertion lifetime plus skew before routine `vault:retire`. Explicit retirement rejects outstanding old-key assertions immediately. `consent:configure` now preserves the selected backend's public trust. Dynamic PF-to-PF rollover remains a separate gate.

Live local Vault signing, non-exportability, least-privilege runtime tokens, TLS, outages/restart and authority/PF A key rotation are verified by nine actual-container tests and the complete post-rotation PF regression suite. **UNVERIFIED:** production workload authentication/renewal, OS isolation, production TLS/networking, HA/auto-unseal/HSM, operations and security approval. See the live guide for recovery evidence and exact validation status.

Before promotion, test with an actual protected signing service: both execution modes through PF A/B; signature/key-version checks; sign-only credential unable to export/read private material; other workloads denied signing/database access; expired/revoked Vault credentials; sealed/unreachable Vault and TLS failures; revocation/suspension during signing; request replay after authority restart; staged workload and authority rotation followed by retired-key rejection; and credential-free application, proxy, Vault and PF logs. Keep current grants/policy checks enabled throughout. No production IAM policy or tenant access was changed by this milestone.

Final local validation (2026-10-29): 38 baseline tests, 112 production/API/identity/signer tests, nine actual Vault/PF tests and all 35 PF regressions passed. The PF suite ran after the final Vault key rotation/retirement, including both execution modes, persistent replay/revocation and credential-free logs. Docker recovery is complete.
