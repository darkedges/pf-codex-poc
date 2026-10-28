# Federated Copilot Identity — Codex Starter Project

A runnable **local-only identity/delegation proof-of-concept** and a Codex task plan for an external AI agent invoking Microsoft Copilot Studio through **two LLM/API gateways and two PingFederate trust domains**. Both interactive and autonomous workflows retain the original **human subject (`sub`)** and **AI agent actor (`act`)**.

> **Status: simulation, not production integration.** Real PingFederate, Direct Line Generic OAuth SSO, Microsoft Entra ID, Graph and SharePoint are **NOT CONNECTED**. The integration adapters and approvals must be built and tested before exposing real data. Do not put this mock service on a public network.

## Architecture

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
