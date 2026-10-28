# Architecture Decision Record

## ADR-001 — External PingFederate remains source of truth
Decision: Human identities remain only in the external PingFederate identity domain. No Entra guest identities are created for this solution. Local references are entitlements, not login accounts.

## ADR-002 — Subject and actor are preserved separately
Decision: `sub` = human; `act.sub` = external AI agent. Gateway workload client is recorded independently. All exchanges narrow audiences.

## ADR-003 — Microsoft 365 app-only resource access
Decision: approved SharePoint/Microsoft 365 resources are accessed via a dedicated Entra application with selected resource grants. The broker enforces external user and actor permissions, not Graph user's delegated permissions.

## ADR-004 — Interactive and autonomous must share grant policy
Decision: both modes bind user, agent, grant, scope, resource and organisation. Autonomous modes require explicit, renewable grants and short-lived trusted proof, not token replay.

## ADR-005 — Copilot integration is conditional on live testing
Decision: use secured Direct Line and Generic OAuth SSO as initial target, but document unattended token-post behavior as UNVERIFIED until production-relevant tests pass. Fail closed if unsupported.

## ADR-006 — Mock adapters must never activate in production
Decision: demo requires `DEMO_ONLY=true`; all mock principals, keys and resources are synthetic; production adapters require security review and explicit configuration.

## ADR-007 — Gateway 2 production exchange boundary (2026-10-29)

Use the maintained `jose` package only in the production adapter; the simulation remains runnable without installing packages. An explicit factory selects the adapter and never catches production configuration or validation errors to choose mock. The current HTTP service remains demo-only and refuses production selection: production hosting needs independently authenticated ingress and an authoritative policy client, which are separate backlog items.

Configure exact HTTPS issuer, JWKS URL, receiving audience, organisation, actor issuer, algorithm and key-ID allowlists. Never perform discovery against a token-provided URL. Validate both the upstream JWT and the returned PF B JWT, preserving human, actor issuer/subject, grant, organisation and execution mode, and preventing scope/lifetime expansion. Gateway client identity is a separate signed assertion; it never becomes `act.sub`.

Require an injected online policy check before issuance and again before token release. It must check active grant, registered agent, organisation and mode, including autonomous assertion custody at the upstream authority. No in-memory fixture enters this production path. Resource/tool checks remain the broker's responsibility.

Use a fresh 60-second `private_key_jwt` with unique `jti` per request. Do not retry token issuance because a lost response can still represent successful issuance. Retry only failed idempotent JWKS network reads once, within the same timeout. Redirects are refused. Native TLS certificate verification stays enabled. mTLS, metadata discovery, durable replay control, production HTTP hosting and live PF behavior remain unimplemented or UNVERIFIED as documented.

Errors expose stable codes only. Optional structured telemetry reports outcome, error code and duration without tokens, key material or upstream error bodies; the production host must route this to its audit/metrics pipeline.
