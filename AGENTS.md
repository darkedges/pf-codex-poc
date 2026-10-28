# Codex Instructions — Federated Copilot Delegation

## Mission
Develop an audited, least-privilege federated identity integration allowing an external AI agent, acting for a PingFederate-authenticated user, to invoke an internal Microsoft Copilot Studio agent through two separately managed LLM/API gateways and PingFederate domains. Support interactive and autonomous grant-backed execution. Microsoft 365 access is via a **resource-scoped Entra application**, never by pretending a PingFederate token is a Graph delegated user token.

## Read first
1. `README.md`
2. `docs/architecture.md`
3. `docs/implementation-plan.md`
4. `docs/threat-model.md`

## Hard constraints
- External human users do **not** have Entra identities and must not be silently provisioned.
- Preserve `sub` (original human), `act.sub` (registered agent), `delegation_id`, organisation, execution mode and audiences at all security boundaries.
- Do not trust `sub`, `act`, grant ID, scopes or resource supplied in a chat prompt or unverified header.
- A grant is NOT an access token. Autonomous execution needs independently validated, short-lived issuance under an active grant.
- Never accept arbitrary Graph URLs, unrestricted SharePoint sites, broad Graph app permissions, client-controlled scopes or unbounded searches.
- Graph app-only authorisation belongs to the broker app; external user and agent restrictions must be checked separately.
- Secure Direct Line and Generic OAuth SSO are product-specific integrations and need live tenant verification. Do not claim they work merely because the mock passes.
- Do not add real PingFederate, Entra, Copilot Studio, certificate or client secrets to git, tests, logs, prompts or generated fixtures.
- Fail closed on missing authority, expired credentials, revoked grants, unknown resources and external service failures.
- No public ports, production IAM policy changes or tenant-wide admin grants without explicit approval.

## Environment
Node.js >=22.16, TypeScript ESM with Node's type stripping; **no npm dependencies for demo**. `npm run keys`, `npm test`, `npm run dev`, and `npm run smoke` are the baseline commands. Local mock JWT primitives in `src/lib/jwt.ts` are intentionally limited to development and must be replaced with mature JOSE validation for production.

## Delivery workflow
- Keep each change small and testable. Add a failing test before changing trust/policy behaviour.
- Add negative tests for every positive identity flow.
- Keep mock and real adapters isolated; `mock` must never be the fallback in a production configuration.
- Document real endpoints and token audiences in diagrams and configuration docs.
- When a capability is unverified, label it `UNVERIFIED` and write an integration test plan.
- Use a secret manager and workload federation/certificates for production credentials.
- Update `docs/implementation-plan.md` after each task and record decisions in `docs/decisions.md`.

## Recommended task order
1. Introduce config + interfaces for PF A and B exchange; use `jose` and trusted HTTPS issuer/JWKS, validate issuer/audience/alg/kid, fail closed and verify client credentials.
2. Implement persistent grant, external identity and agent registry + reliable revocation; prove subject/actor binding and autonomous assertion custody.
3. Build authenticated API endpoints with separate gateway client identity, mTLS/private_key_jwt and secure outbound service calls.
4. Build a Copilot Direct Line adapter, then verify Generic OAuth SSO secure-token-post behaviour with an actual tenant, *including autonomous sessions and token expiry*.
5. Build a Graph broker with Entra app-only token using certificate or managed identity. Pin approved site IDs and use `Sites.Selected` with read-only grants.
6. Build a tool API and end-to-end integration harness with real environments, policy audit and security review.
7. Introduce IaC for secure networking and approvals, monitoring, token/key rotation and deployment promotion.

## Definition of done for a production adapter
- There is a typed interface, unit tests, negative tests, timeouts, retries with bounded idempotency, structured logs without credentials, telemetry and explicit error contracts.
- No host/issuer/URL chosen from untrusted request data.
- Every verified token is audience-specific, with issuer and signature checked against the approved trust registry.
- Credentials and config come from secret managers/env, never the repository.
- Live tenant behaviour is documented and security-approved.
