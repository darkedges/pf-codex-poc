# Persistent delegation policy service

Gateway 2 now checks an authenticated HTTPS policy API before PF B issuance and again before releasing the issued token. The service independently verifies the signed PF token at each boundary and evaluates a transactional registry/grant database. An authenticated gateway cannot substitute unsigned human/agent claims in the decision request.

The reusable implementation is in `src/policy/`: contracts, SQLite store, signed-request API, HTTPS server, and gateway client. The [browser consent flow](browser-consent.md) now supplies independently verified real PF login and human approval evidence. The older fixture profile retains synthetic initial approval solely for isolated regression tests. Production authority custody and deployment approval remain separate work.

## Storage and identity bindings

The SQLite database contains organisations, external human references, registered agents, grants, used workload assertion IDs and audit events. It creates no Entra accounts. Principal bindings are immutable: kind, external issuer, subject and organisation. Human records explicitly list which approved PF token issuers may carry that canonical human identity. Agent identity matches both `act.iss` and `act.sub`.

Each grant binds a registered human and agent in the same active organisation to explicit modes, scopes, resources and expiry. Administrative grant expiry is capped at 30 days and cannot exceed approval-evidence expiry; those records identify the asserting workload and do not pretend a human browser approval occurred. The browser flow separately records the actual PF issuer/subject, authentication time and proof/review digests, with a one-hour or 24-hour human-approved expiry and explicit background opt-in.

Revocation is terminal for a grant ID. Renewal creates a new grant ID with fresh approval evidence; existing tokens referring to the old ID remain denied. Registry suspension denies tokens immediately at subsequent decisions. The service never automatically renews, unsuspends, reactivates or imports the old JSON grant fixture.

SQLite uses foreign keys, prepared statements, WAL mode, full synchronous commits, bounded lock waits, and `BEGIN IMMEDIATE` transactions. Decisions read current committed state without a permit cache; their audit event commits in the same transaction. Governance writes and their audits also commit atomically. An unavailable or locked database fails closed. POSIX database permissions are restricted to the owner; protect the directory and files with appropriate OS ACLs on Windows.

This is a single-host persistence implementation using Node's built-in `node:sqlite`, which is experimental in the supported Node 22 runtime. Production requires approval of the runtime, encrypted storage/backups, recovery and audit-retention procedures, and a scalability/availability decision. Do not put this database on a shared network filesystem or treat this implementation as a multi-region authority.

## Authenticated API

All routes use HTTPS and signed workload request authentication. Public verification keys, key IDs, roles and organisation permissions come from the server's configured caller registry, never from request-supplied key URLs. The local profile generates different private keys for policy decisions and administration.

| Endpoint | Required role | Purpose |
|---|---|---|
| `POST /v1/decisions` | `decision` | Independently verify a PF token and check its grant for one configured scope/resource capability |
| `POST /v1/registry/organisations` | `registry-admin` | Register an allowed organisation |
| `POST /v1/registry/principals` | `registry-admin` | Register an immutable human/agent identity and organisation binding |
| `POST /v1/registry/suspend` | `registry-admin` | Suspend an organisation, human or agent |
| `POST /v1/grants` | `grant-admin` | Create a new grant with explicit approval evidence |
| `POST /v1/grants/{id}/revoke` | `grant-admin` | Persist terminal revocation |
| `POST /v1/consents/preview` | `consent` | Independently verify browser login and return registered permissions/owned grants |
| `POST /v1/consents/approve` | `consent` | Atomically create a human-owned grant from fresh OIDC evidence and reviewed terms |
| `POST /v1/consents/revoke` | `consent` | Revoke only the verified human's own grant |

Roles are organisation-scoped. A decision workload cannot register principals, create grants, revoke grants or impersonate an administrative workload with its own key. There is no anonymous grant lifecycle API and no API for reactivating a revoked ID. The internal store methods are for trusted service/bootstrap code; unverified claims must not be passed directly to the store from public ingress.

The request header is `Authorization: Policy <signed-request-JWT>`. This is request authentication, not a delegated OAuth access token. Required JWT properties:

- RS256 signature, configured `kid`, and `typ=policy-request+jwt`.
- `iss` and `sub` equal the registered workload ID.
- A single exact `aud` equal to the configured policy origin plus endpoint path. The request Host header cannot choose that origin.
- `method=POST` and `body_sha256` equal to SHA-256/base64url of the exact request bytes.
- `iat`, `exp` and unique `jti`, with at most 60 seconds lifetime and five seconds clock tolerance. Expired assertions are refused.

Used assertion IDs persist transactionally, so replay remains denied across process restarts. Token-provided `jku`, `jwk`, `x5u` and `x5c` cannot supply trust. TLS certificates remain verified. The client refuses redirects, bounds responses and timeouts, performs no automatic POST retries, and has no local-policy fallback.

A decision request contains exactly:

```json
{
  "token": "<signed PF A or PF B access token from secure custody>",
  "capability": {
    "scope": "copilot.invoke",
    "resource": "sharepoint:approved-research"
  }
}
```

The service verifies token issuer, signature, algorithm, key ID, audience and time using the approved PF registry, then checks the canonical human/agent/organisation binding, current registry status, grant, mode, scope, resource and approval expiry. Extra `sub`, `act`, grant or header identity assertions are not accepted as proof. A resource must be both a configured capability and allowed by the active grant; arbitrary Graph URLs provide no authority.

Responses are generic: 200 permit with decision ID and grant version; 400 invalid request; 401 unauthenticated/replay; 403 denied; 409 conflicting registration/ID; 503 unavailable. Bodies and logs do not include tokens, client assertions, private keys or upstream error text. The returned decision ID identifies its durable audit row, which records canonical identities, token issuer/audience, actor issuer, workload, reason, grant version and capability metadata. Failed authentication and HTTP outcomes are represented in credential-free telemetry.

## Gateway 2 integration

`Dependencies.authorise` now receives `(verifiedClaims, { accessToken })`. The first call carries the original PF A token; the second carries the verified PF B token. Older trusted callbacks remain compatible, but the supplied `PolicyClient.authorise` requires token evidence and sends it to the independent verifier. A missing evidence token or unreachable policy service denies the exchange.

Construct `PolicyClient` with a trusted HTTPS origin, configured workload ID/key ID, private `CryptoKey`, timeout and a fixed approved capability. Pass its bound `authorise` method to `PingFederateExchange`. Load production keys and TLS material through approved secret/workload infrastructure. The lab file-based keys are solely local development inputs.

Revocation is enforced at each transaction's decision point and at the gateway's second check before release. The tests cover revocation after PF B successfully issues a token but before the second policy check. Revocation does not invalidate the PF JWT's cryptographic signature or stop an already authorised operation. Resource brokers must check current grant authority for every protected operation; issued-token possession alone is insufficient.

## Local operation and validation

The existing PF setup commands prepare the policy database and workload keys. For standalone local API work:

```powershell
npm run policy:setup
npm run policy:serve
```

The server binds `127.0.0.1:9450` and uses the trusted localhost certificate prepared by `pf:prepare`. The launcher sets `NODE_EXTRA_CA_CERTS` to the prepared CA for its native JOSE JWKS requests. Global TLS-verification bypass is refused. Standalone data lives in ignored `.local/pingfederate/policy.sqlite`; setup preserves existing revocations and suspensions.

`npm run pf:test` automatically starts an HTTPS policy process on an ephemeral loopback port, then stops only its own process after testing. Each run gets its own persisted database under `.local/pingfederate/policy-tests/<run-id>/`. Revocations remain recorded; tests never restore a revoked grant to active. A second service process reads the same database to prove durable denial. Separate databases exercise revocation during issuance in each mode. Canonical token values stay in memory; the SQLite/audit/telemetry evidence contains no access tokens.

The retained synthetic proof authority checks the same registry solely for fixture regressions. The new browser-consent authority has a different issuer and key and requires real consent evidence; interactive execution additionally verifies a current human login. Autonomous execution needs no human token. The legacy `grant.json` is unused. Production unattended signing custody remains unverified.

The original policy milestone passed 34 baseline/store, 57 production/API and 28 live tests. The [browser-consent milestone](browser-consent.md) extends coverage to real login/approval, owned revocation, consent replay/forgery, PKCE and fixture isolation. The original dependency-free simulation remains separate.

Next integration gate: build production authority custody using protected signing keys and workload identity. Production directory/MFA/session policy, policy hosting, key rotation, authenticated gateway ingress, per-tool broker checks, operations and security approval remain unverified.

The [authority milestone](authority-service.md) adds the separate authority role and authenticated assertion endpoint, plus a typed development/Vault Transit signer boundary. Production custody remains a live deployment gate. Validation now covers 38 baseline, 109 production and 35 live PF tests.

