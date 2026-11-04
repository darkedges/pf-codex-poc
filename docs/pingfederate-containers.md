# Real PingFederate container integration

Implemented and verified locally on 29 October 2026 using two PingFederate **13.1.0** containers. This follows the isolation, persistent-volume and trusted-localhost-TLS approach in `E:\development\projects\ping\pf-par-poc`. That reference project's containers and configuration are not modified. Provisioning here uses a narrowly scoped, idempotent Node administration client rather than the reference project's Terraform roots.

The real boundary is **PF A issuance → Gateway 2 production exchange adapter → PF B issuance**, with an authenticated HTTPS policy API and persistent registry at both checks. Both modes preserve `sub`, the original `{sub, iss}` actor, organisation, grant ID, scope and execution mode. The [browser consent portal](browser-consent.md) now adds actual PF A login and human-owned approval; retained fixture tests remain isolated. The default HTTP gateways, Copilot and Microsoft 365 demo remain simulations. Local test accounts/signing custody are not production approval. See the [delegation policy service](delegation-policy.md).

## Run

Prerequisites: Node >=22.16, PowerShell 7, Docker Desktop Linux engine, and a prepared/licensed `pf-par-poc` checkout with trusted localhost TLS files. Run in this project:

```powershell
npm ci --include=optional
npm run pf:prepare
npm run pf:up
npm run pf:test
npm run pf:status
```

For another prepared reference checkout:

```powershell
npm run pf:prepare -- -ReferenceProject E:\path\to\pf-par-poc
```

Preparation copies only the licensed DevOps image credentials and trusted localhost certificate/key/CA into ignored `.local/pingfederate`. It generates independent PF A/PF B admin passwords and a PKCS#12 bundle. Configuration generates separate local human-proof, agent-proof, delegation-authority and Gateway 1/Gateway 2 client signing keys. No key or password is printed. Do not copy `.local` into source control or share it as a test fixture. Keep the named PF volumes with their associated local configuration and keys.

The image is pinned by digest to `pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0`. Its getting-started server profile is downloaded from Ping Identity's server-profile repository during initial boot; this profile source remains an upstream bootstrap dependency. This is a workstation lab using licensed developer images, not an approved production image/profile pipeline.

`pf:up` creates only Compose project `federated-copilot-pf`, its two volumes and its network. Its default private subnet is `10.234.0.0/24`; if necessary, change `PF_DOCKER_SUBNET` in the ignored `compose.env` before initial creation. All four host ports bind **127.0.0.1**. It imports the trusted localhost TLS key, enables the required expressions, and reconciles fixed integration IDs through the admin APIs. First boot can take several minutes. There is no mock fallback.

| Domain | Runtime/issuer | Administration | Published JWKS | Issued audience |
|---|---|---|---|---|
| PF A | `https://localhost:9033` | [PF A admin](https://localhost:9996) | `https://localhost:9033/pf/JWKS` | `api://gateway-2` |
| PF B | `https://localhost:9034` | [PF B admin](https://localhost:9997) | `https://localhost:9034/pf/JWKS` | `api://copilot-broker` |

Token endpoints are `/as/token.oauth2` on the respective runtime URLs. The admin account is `administrator`; credentials are in the corresponding ignored `.local/pingfederate/admin-a.json` and `admin-b.json`. Do not paste their contents into chat or logs.

On **first provisioning only**, a certificate-validation exception permits importing/selecting TLS on the new loopback instance's `/keyPairs/sslServer/*` admin endpoints. It cannot access other hosts, ports or API paths. After restart, administration and all token/JWKS traffic verify TLS against the copied CA. Subsequent `pf:up` runs require verified TLS. The test launcher adds this CA through `NODE_EXTRA_CA_CERTS` and refuses `NODE_TLS_REJECT_UNAUTHORIZED=0`.

## Verified exchange profile

```mermaid
sequenceDiagram
  participant T as Local test authority / Gateway 1 harness
  participant A as PF A :9033
  participant G as Gateway 2 production adapter
  participant P as Local persisted test grant policy
  participant B as PF B :9034
  T->>T: Validate independent signed agent proof and active grant
  T->>A: Short-lived human/delegation proof + actor proof + private_key_jwt
  A-->>T: PF A signed JWT (aud api://gateway-2, 180-second lifetime)
  T->>G: PF A token
  G->>A: HTTPS JWKS GET; pinned issuer/alg/kid
  G->>P: Check human, agent, organisation, grant, mode, scope
  G->>B: subject_token + resource=api://copilot-broker + private_key_jwt
  B-->>G: PF B signed JWT (aud api://copilot-broker, 60-second lifetime)
  G->>B: HTTPS JWKS GET; validate identity continuity
  G->>P: Recheck current grant before release
```

The retained fixture harness uses separate keys/namespaces for human, autonomous and agent proof. The browser consent profile separately uses real OIDC login, persisted human approval and its own consent-authority key/issuer. Its 60-second assertions require the actual agent proof and current consented grant; interactive execution also requires a fresh matching human login. Production signing custody remains a separate gate.

PF A has separate subject processors and token types for the two modes; its exchange policy requires an independently validated actor token. It restricts the synthetic subject, agent, organisation, grant and scope and binds the mode to its processor. PF B validates the **PF A** issuer, signature, audience and times. It consumes the already-established actor chain; the gateway workload client never replaces the original actor.

PF A signs both the nested `act` object and auxiliary `actor_sub`/`actor_iss` attributes. PF B maps these signed attributes back into the same nested actor object through a fixed administrator-controlled expression. Gateway 2 validates the nested actor before exchange and compares it again after issuance, so inconsistent or substituted actor identities are refused. Expressions are fixed configuration, never constructed from prompts or request text.

PF B's JWT processor uses an **embedded, administrator-pinned snapshot of PF A's published signing JWKS**, fetched over verified HTTPS at configuration time. This avoids an insecure hostname override between containers whose certificates cover localhost. The production adapter retrieves both domains' JWKS over live verified HTTPS. After rotating PF A's signing key, explicitly review/update the configured key IDs and rerun `pf:configure` to repin PF B. Automatic PF-to-PF JWKS refresh/key rollover is **UNVERIFIED** in this lab.

Both OAuth clients have only `TOKEN_EXCHANGE`, only `copilot.invoke`, a single permitted default ATM, pinned RS256 client authentication and enforced assertion replay prevention. Each ATM has one resource URI and one allowed gateway client. Both JWT processors require audience, expiry, issued-at and not-before claims; clock tolerance is bounded to five seconds for host/container clocks.

The registry is transactional SQLite, accessed by Gateway 2 through authenticated HTTPS with independent PF-token verification. The old grant JSON is unused. Each test run retains its evidence database and terminal revocations. Real browser approval is persisted independently from fixture approval; the consent authority verifies the actual agent and grant before signing. PF itself does not query this database, so the gateway and future broker must enforce current policy. Production directory/consent policy, authority custody and deployment approval remain pending.

## Interoperability findings applied to the adapter

Live tests caught three requirements absent from the original mocked exchange:

- For this PF configuration, client assertions use `aud=https://localhost:9034` (the server base URL). `clientAssertionAudience` is now a trusted configuration field; omission preserves the previous full-token-endpoint default. It is never request controlled.
- Signed client assertions carry `typ=client-authentication+jwt`. PF rejects an explicit generic `typ=JWT` for client authentication in this setup.
- PF ATM selection uses `resource`, not the token-generator `audience` selector. `targetParameter="resource"` sends the configured receiving audience as the resource. The previous `audience` default remains available for other reviewed integrations. Wrong resources and scope expansion are rejected by PF.

These are distinct audiences: client authentication targets PF B's authorization server; the incoming access token targets Gateway 2; the output access token targets the broker. No JWT validator audience was weakened to make the tests pass.

## Commands and lifecycle

| Command | Action |
|---|---|
| `npm run pf:prepare` | Prepare private local inputs from the reference checkout |
| `npm run pf:up` | Start/reconcile the pair, trusted TLS, log redaction and exchange configuration |
| `npm run pf:configure` | Reconcile exchange objects and repin PF A's current signing JWKS in PF B |
| `npm run pf:test` | Run live positive/negative tests and save credential-free local validation metadata |
| `npm run pf:status` | Show this project's two containers and loopback port mappings |
| `npm run pf:stop` / `pf:start` | Pause/resume only this pair; start waits for trusted admin readiness |
| `npm run pf:down` | Remove only this pair/network; retain both named volumes and local secrets |

Configuration is idempotent. On reconciliation, the dedicated exchange client is disabled before its dependent objects change and re-enabled after successful mapping/ATM reconciliation. Failed configuration leaves that client disabled. Scripts stop on failures. Other Docker projects are untouched. No command deletes the PF volumes or local credentials.

Log4j2 filters suppress credential-bearing events and replace compact JWTs in pattern layouts, including throwable rendering. OAuth audit/request status events remain available. The live tests scan fresh container output for JWT credentials without printing log contents. Avoid enabling DEBUG or request-body tracing on these endpoints. Local admin-error diagnostics can contain configuration material; `.local/pingfederate/last-admin-error.json` stays private.

## Validation and remaining gates

Verified: 34 live tests, retaining both-mode exchange, identity/client/replay/expiry/audience/scope rejection, persisted revocation, policy outage and mid-issuance revocation, and adding actual PF login, human approval, wrong PKCE, background opt-in, cross-session/identity/forged-consent rejection and fixture-authority isolation. Fresh PF failure logs remain checked for compact JWTs. Offline tests and the dependency-free simulation remain separate. `.local/pingfederate/validation.json` records status and versions without credentials.

Still **UNVERIFIED / not implemented**: production directory/MFA and browser-session policy, production approval of the persistent policy service, workload-isolated authority keys, authenticated production Gateway 1/2 ingress, PF-to-PF dynamic JWKS rollover, production TLS/mTLS and operations. Copilot Studio, Entra and Graph remain disconnected. Local login/consent and exchange verification do not complete production approval gates.

References: [PingFederate token endpoint](https://docs.pingidentity.com/pingfederate/12.3/developers_reference_guide/pf_token_endpoint.html), [ATM resource URI selection](https://docs.pingidentity.com/pingfederate/13.1/administrators_reference_guide/help_beareraccesstokenmgmtplugintasklet_atmselectionsettingsstate.html), [JWT processor configuration](https://docs.pingidentity.com/pingfederate/12.2/administrators_reference_guide/pf_configuring_jwt_token_processor_20_instance.html).
