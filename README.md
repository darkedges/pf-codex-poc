# Federated Copilot Identity — Codex Starter Project

Android status: the owner has [verified a live document-grounded Copilot answer](docs/mobile-live-success.md) from the Ionic React app after fresh PF sign-in. Biometric unlock is working; recovery from an unsuccessful provider refresh still requires signing in again and remains unresolved.

A runnable **local-only identity/delegation proof-of-concept** and a Codex task plan for an external AI agent invoking Microsoft Copilot Studio through **two LLM/API gateways and two PingFederate trust domains**. Both interactive and autonomous workflows retain the original **human subject (`sub`)** and **AI agent actor (`act`)**.

> **Status: interactive PoC verified, not production deployment.** The default services remain an isolated simulation. Real PF A/B, Vault and the actual Copilot Studio tenant now pass [interactive sign-in and a Copilot-originated delegated diagnostic](docs/copilot-interactive-tool-success.md), preserving human/agent/grant identity with verified cleanup. Autonomous Copilot provider SSO and live Microsoft expiry/revocation behavior remain **UNVERIFIED**; A [single document-backed Copilot answer](docs/document-chat-live-success.md) is now live-verified using the pinned synthetic SharePoint sample; broader document/chat access remains unverified. Public PoC routes and the Microsoft credential-trace exception are explicitly scoped approvals, not production approval.

## Architecture

Browser integration preparation for `agent.copilot.darkedges.com`: [implemented components, proposed endpoints and remaining activation gates](docs/agent-portal.md). The interactive browser PoC is now [live-verified with independent identity audit and cleanup](docs/portal-browser-success.md). Its approved single-run allowance is spent; new sign-ins/checks are disabled and another live run requires a separate allowance.

```text
External user (PingFederate A) ──┐
                                  ├──> Agent -> Gateway 1 -> Gateway 2 -> Copilot Broker
External registered AI agent ────┘          │               │             │
                                        mock PF A        mock PF B      policy check
                                           │               │             ├── enterprise API (mock)
                                    Delegation Authority    └─────────────└── M365 (mock)
                                                                           │
                                                                 Copilot Studio (planned)
                                                                 Entra app-only (planned)
```

Actual production trust model: subject identity is only in external PingFederate, the AI agent is authenticated independently, PingFederate A/B exchange audience-specific tokens, a central grant/policy system authorises each tool operation, and a dedicated Entra **application** accesses centrally approved SharePoint sites using `Sites.Selected`. No external Entra guest accounts are required. Entra app access is **not** user-delegated Graph access.

## Run on a Linux remote machine

Requires **Node.js >= 22.16**. No `npm install` or external packages are needed for the self-contained simulation.

```bash
unzip federated-copilot-codex.zip
cd federated-copilot-codex
npm run keys
npm test
npm run dev
```

In a second SSH terminal:

```bash
cd federated-copilot-codex
npm run smoke
```

Expected: interactive and autonomous requests return **200** and report `subject=partner-a:user-123` and `actor=partner-a:agent-research`; revoked grants and unauthorised sites return **403**. `simulation: true` means no real Copilot/Graph access occurred.

Or, with Docker Compose (not tested in this environment):

```bash
npm run keys
# Compose publishes only gateway-1 to 127.0.0.1:9301 on the machine.
docker compose up --build -d
npm run smoke  # mock issuer and gateway 1 are bound to remote localhost
docker compose down
```

### Key files

| Location | Purpose |
|---|---|
| `AGENTS.md` | Codex project instructions, goals, guardrails and the next tasks |
| `src/services/gateway-1.ts` | External request ingress, user/agent validation, token exchange |
| `src/services/gateway-2.ts` | Cross-domain validation, PingFederate B exchange |
| `src/services/delegation.ts` | Mock short-lived autonomous delegation assertion service |
| `src/services/mock-pf-a.ts` | Mock external issuer and first token exchange |
| `src/services/mock-pf-b.ts` | Mock internal issuer and second token exchange |
| `src/services/copilot-broker.ts` | Policy-protected, synthetic Copilot+M365 tool responses |
| `src/lib/policy.ts` | Default-deny user/agent/grant/resource checks |
| `src/lib/jwt.ts` | **Mock-only** pinned-key RS256 token helpers; replace for production |
| `docs/` | Production architecture, configuration and transition plan |
| `infra/terraform/` | Infrastructure implementation plan (no live resources created) |

## Interfaces

- `POST :9201/dev/issue` — issue a *synthetic* user or agent credential in local demo.
- `POST :9301/v1/invoke` — interactive or autonomous external agent request.
- `POST :9200/v1/autonomous-assertion` — issue a 60-second grant-backed assertion (mock).
- `POST :9201/as/token.oauth2` — mock first RFC 8693-style exchange.
- `POST :9202/as/token.oauth2` — mock second RFC 8693-style exchange.
- `POST :9400/v1/execute` — mock broker; verifies PF B token and resource policy.

All mock services run on **loopback** by default. `DEMO_ONLY=true` is required. `.local/` contains local signing keys and is gitignored.

## Codex handoff

Open this directory as a Codex workspace. Codex will use `AGENTS.md`. The initial implementation objective is to replace **only one mock boundary at a time**, while keeping the subject/actor and policy tests passing.

Start with: **“Read AGENTS.md and docs/implementation-plan.md. Implement the PingFederate B JWKS validator and real token-exchange client behind an interface, preserving the mock mode and adding negative tests. Do not touch Microsoft credentials or grant broad Graph permissions.”**

See [`docs/remote-setup.md`](docs/remote-setup.md) for remote transfer, Codex usage and deployment safety.

Gateway 2 now has an isolated JOSE-based PingFederate exchange library with signed client authentication. See [production configuration and UNVERIFIED live integration plan](docs/gateway-2-production.md). Install optional production dependencies with `npm ci --include=optional` and run `npm run test:production`. The HTTP services remain demo-only.

## Actual PingFederate containers

The separate [real PF container harness](docs/pingfederate-containers.md) follows `E:\development\projects\ping\pf-par-poc` and uses its prepared local image credentials/TLS files. It creates two independent PF 13.1.0 containers with trusted HTTPS, signed client authentication and verified interactive/autonomous exchanges:

```powershell
npm ci --include=optional
npm run pf:prepare
npm run pf:up
npm run pf:test
```

PF A runtime/admin: `https://localhost:9033` / `https://localhost:9996`. PF B: `https://localhost:9034` / `https://localhost:9997`. All host ports bind loopback. `npm run pf:stop` pauses only this pair. The harness's identity authorities and grant registry are local test components; Microsoft integrations remain disconnected.

The harness now uses a [persistent registry and authenticated policy API](docs/delegation-policy.md). Gateway 2 sends signed PF token evidence for independent verification before issuance and before release. `pf:test` starts its own HTTPS policy service and proves revocation in both modes, including revocation during issuance. `npm run policy:serve` runs the standalone local API; see the policy guide for TLS setup and remaining production gates.

## Browser login and consent

The [consent portal](docs/browser-consent.md) now performs real PF A login with mandatory PAR/S256 PKCE and records human-owned approval. Both interactive and explicitly approved background execution use the actual PF A/B exchange chain and remain revocable.

The [authenticated assertion authority](docs/authority-service.md) owns consent signing behind the HTTPS policy boundary. Agent requests bind grant, mode and operation with persistent replay prevention. The [actual local Vault integration](docs/vault-containers.md) verifies non-exportable signing, both PF execution modes, outages and key rotation. Run `npm run vault:up` to select Vault, then `npm run vault:test`; local launchers preserve the selected backend. All nine live Vault tests and 35 post-rotation PF regressions pass. Production custody/isolation and deployment remain UNVERIFIED. See the guide for final validation and Docker recovery evidence.

```powershell
npm run pf:configure
npm run consent:serve
```

Open [Delegated access](https://localhost:9460). The local test user is `partner-a:user-123`; its generated password stays in `.local/pingfederate/login-password`. The portal launches its own policy process and uses loopback HTTPS only. Production directory, session/key custody and deployment approval remain pending; Microsoft integrations are still disconnected.

## Direct Line adapter

The [real PF-to-relay-to-private-tool integration](docs/copilot-real-relay.md) now passes **15 live local checks**, including original human/agent continuity, one-use proof, owner revocation and independent policy audit. Its one grant is revoked and temporary resources removed. All 318 baseline and 381 production tests pass. No Microsoft conversation was used; persistent relay deployment and actual Copilot-originated tool invocation remain unverified.

The [enrolled relay caller is now active in the private tool, and its runtime/audit loader is prepared](docs/copilot-relay-activation-runtime.md). Seven checks against the actual running tool pass. The monitor remains allowed, the service is ready and no host port is published. All 318 baseline and 370 production tests pass. The persistent relay is not started; real issuance/container wiring and actual Copilot tool invocation remain unverified.

The earlier [Vault enrollment and private Docker candidate milestone](docs/copilot-relay-vault-network.md) passed 22 live Vault and 14 isolated network checks while preserving the original trust. The later activation above now permits the enrolled relay caller; persistent relay installation remains pending. No new Microsoft conversation was used.

The [provider-to-tool relay preparation](docs/copilot-tool-relay.md) adds a short-lived, single-use binding from the exact PF A user token to independently verified broker authority, separate connector-key authentication, full tool-proof identity comparison and fail-closed policy/audit/result checks. Its [HTTPS/lifecycle composition](docs/copilot-tool-relay-hosting.md) now passes loopback relay-to-private-mTLS-tool tests, including session closure and transport/admission failures. All 310 baseline and 361 production tests pass. The connector remains a non-deploying draft; persistent relay runtime installation, caller activation and actual Copilot tool invocation remain unverified.

The latest approved [60-minute PF A token test](docs/copilot-sixty-minute-success.md) succeeded: one token POST returned **HTTP 200**, and the published agent reported **User.IsLoggedIn=true**. Original request/response values are retained privately in Vault. All 297 baseline and 318 production tests pass. All nine conversation reservations are consumed. Copilot-originated delegated tool use, autonomous provider SSO and Copilot expiry behavior remain UNVERIFIED.

The [Generic OAuth provider-token mismatch](docs/copilot-provider-token-fix.md) is corrected: provider sign-in uses PF A user proof while delegation stays on separate PF B credentials. Historical [post-publication three-minute-token capture](docs/copilot-post-publication-capture.md) returned HTTP 400 with exact body `"Token is expired"`; the [five-minute attempt](docs/copilot-five-minute-attempt.md) stopped locally before posting. Preserve these distinct results alongside the latest successful one-hour run; the precise minimum lifetime and earlier rejection causes remain unresolved. Unsupported autonomous provider SSO fails closed.

The [persistent Docker service runbook](docs/tool-service-runbook.md) includes stop/recovery procedures and a bounded burst acceptance test. `npm run tool:container-test -- --load` passed 40 private-Docker checks. [Local Vault custody](docs/tool-vault-custody.md) uses certificate authentication and single-use read tokens. The [enrolled consent-backed canary](docs/enrolled-tool-canary.md) passes 47 live checks for both PF execution modes, expiry and revocation. The [local service controller](docs/local-tool-controller.md) passes 18 lifecycle/command/crash checks and 14 policy regressions. Following the user's Windows-owner/one-day tool-journal selection, it is running privately with independent mTLS readiness verified. PF B remains disabled; no automatic restart, public tool port or Microsoft/Graph connection is enabled.

The [tool monitoring and restricted audit](docs/tool-observability.md) provide authenticated aggregate metrics, bounded identity-reference journals and fail-closed audit writes. `npm run tool:operations-report` reads the latest completed Docker test's authoritative revocation counts without exposing identities. No external alert destination or persistent deployment is configured.

The tool image now includes [authenticated readiness/liveness and bounded admission](docs/tool-readiness-admission.md): a signed PDP health probe, pinned JWKS/credential checks, per-certificate throttling, global concurrency/connection caps and draining. All 37 private Docker integration checks pass; the persistent service remains unstarted.

The [private tool-container integration](docs/tool-container-network.md) uses the built runtime against actual PF JWKS and independent grant-policy decisions, with no host ports or Microsoft calls. `npm run tool:container-test` previews the run; `-- --run` executes both modes, rejection cases and actual expiry, then revokes grants and removes test containers/network.

The [verified tool Docker runtime](docs/tool-docker-runtime.md) now builds on the selected existing Docker host, with a secure file-based loader, mandatory mTLS and no mock fallback. Seven disposable no-network Docker smoke checks pass. Compose is loopback-only and remains unstarted pending private dependency routing and remaining deployment controls.

The [tool deployment review package](docs/tool-api-deployment-review.md) records the proposed isolated hosting, private endpoints, workload authentication, secret mounts, monitoring and unresolved production gates. `npm run tool:deployment-review` checks the non-deploying draft offline; it creates no services/resources and always reports not ready for deployment.

The [protected tool API](docs/protected-tool-api.md) now has an actual local PF/Vault/policy-to-HTTPS harness: `npm run tool:http-test` previews and `npm run tool:http-test -- --run` executes 27 interactive/autonomous, expiry, certificate rollover and rejection checks. It uses loopback mTLS, restores the tool client disabled, revokes test grants and contacts neither Microsoft nor Graph. Production deployment and Copilot-originated tool calls remain UNVERIFIED.

Latest tenant checkpoint: the operator completed PF login and Microsoft's validation-code step, then received the [published diagnostic](docs/copilot-signin-verification.md)'s exact positive response confirming `User.IsLoggedIn=true`. Manual sign-in/runtime status are operator-observed; delegated SSO, autonomous execution, expiry and tool acceptance remain UNVERIFIED. The diagnostic does not read or display the token.

The dedicated [PF A public login client and Generic OAuth settings](docs/copilot-generic-oauth-settings.md) are ready: actual public authorization-code/JWT validation and replay/credential/redirect rejection pass. Only that human-login client is enabled; the tool-exchange client remains disabled. Save and publish the documented authentication settings in Copilot Studio before claiming tenant federation. The latest checks pass 112 baseline and 35 original PF tests; actual Copilot authentication remains UNVERIFIED.

The [live channel probe](docs/copilot-channel-probe.md) verified real token generation and conversation transport with negative credential checks. `npm run copilot:probe` can repeat this potentially billable diagnostic using private local configuration; it does not verify PF SSO or bypass the production adapter's identity/policy checks.

The actual Sandbox environment and published agent are available; see [Power Platform environment scripts](docs/power-platform-environment.md) for the separate provisioning workflow. Do not apply the original draft to create a duplicate environment. [Dedicated Copilot PF profiles](docs/copilot-pf-staging.md) verify public-host metadata, actual login and bounded tool issuance through local TLS in both modes, then return to disabled. The [tool verifier and online policy boundary](docs/copilot-tool-authority.md) now pass actual PF revocation/suspension/outage tests in an explicit isolated profile. Edge connectivity, deployed tool ingress and live Generic OAuth remain UNVERIFIED.

The [Direct Line adapter and HTTPS API factory](docs/direct-line-adapter.md) implement server-side conversation binding, per-conversation channel tokens, OAuth challenge validation, controlled token posting and independent SSO-token verification. Run `npm run test:copilot` for 85 local contract/negative tests; the full production suite now has 216 tests. The existing simulation stays dependency-free and separate. Copilot Generic OAuth acceptance, deployed tool ingress and production hosting remain **UNVERIFIED**; no production integration listener was deployed.

Repeatable browser sessions are [implemented locally and prepared for bounded activation](docs/portal-repeatable-sessions.md). The [deployment review](docs/portal-repeatable-session-review.md) proposes five freshly consented sessions in one fixed hour; live multi-session acceptance is UNVERIFIED and prior one-shot allowances remain spent.
