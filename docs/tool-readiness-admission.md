# Tool readiness and request admission

Implemented and locally verified 2026-10-30. These controls are part of the tool image; the persistent Compose service remains unstarted. They do not resolve Microsoft SSO, production secret custody or the Copilot caller path. Graph/SharePoint remain disconnected.

## Authenticated health contract

Both routes require a valid client certificate chaining to the approved CA **and** an allowlisted SHA-256 workload fingerprint. Neither route requires a human access token. Unknown certificates are rejected before dependency checks. Health responses contain only a Boolean and disable caching.

| Request | Response | Meaning |
|---|---|---|
| `GET /health/live` | `200 {"live":true}` | The process is responding; no dependency calls or tool invocation |
| `GET /health/ready` | `200 {"ready":true}` | Current runtime credentials/configuration and pinned JWKS/PDP checks succeeded |
| `GET /health/ready` | `503 {"ready":false}` | A dependency, credential, trust or deadline check failed |

GET bodies are rejected. Query-selected/alternate paths are not health routes. Rate limiting, overload and draining can return their fixed admission errors on either route. An untrusted/missing client certificate fails TLS or receives sender denial, not public health information.

Readiness checks run in parallel with a 2.5-second overall deadline:

1. Confirm the fixed mounted credentials and runtime JSON still match the loaded snapshot, reject leaf symlink redirection, and check loaded certificate validity. A changed/missing file makes readiness fail; it does not hot-reload trust. Drain/restart to activate reviewed credential changes.
2. Fetch the exact approved HTTPS JWKS URI without redirects, with bounded response size. Require a usable public RSA signing key with an approved kid and at least 2048 bits. Unexpected private key material or malformed/unknown keys cannot yield ready.
3. Send a fresh signed `POST /v1/health` with empty JSON to the configured PDP. The PDP authenticates the decision-only workload, method, exact audience, signature, body digest, expiry and persistent replay ID. It returns only `{"ready":true}`. This exercises authenticated database/replay-store access without a human token or grant change; authentication replay bookkeeping is written.

The PDP health route cannot create/revoke grants, mint assertions, evaluate a user operation or access documents. Admin-only callers cannot use it. The private lab bridge now forwards exactly three fixed routes: JWKS, decisions and signed PDP health. Caller-bound `decisionOrigin` applies to `/v1/decisions` and `/v1/health` only; it does not expand admin/consent authority.

Concurrent readiness probes coalesce into one check, with success/failure cached for at most one second. The cache is a health result, **never an authorization decision**. Tool requests continue to independently verify each JWT and check live policy before execution and result release. Ready does not establish that any particular grant, user or operation is permitted.

## Bounded request admission

The runtime JSON now requires a closed `admission` object; null/missing/unknown/unsafe settings reject startup. The review defaults are:

```json
{
  "maxConcurrentRequests": 16,
  "perWorkloadRequestsPerMinute": 60,
  "maxConnections": 128
}
```

The factory's compatibility defaults are equally bounded; the secure runtime requires explicit configuration. Configurable bounds are 1–256 active requests, 1–600 requests/minute per workload and up to 1024 connections, with connection capacity at least the request cap.

Admission occurs after certificate verification and before bearer parsing, body reads, dependency calls or operations. Rate buckets are keyed by the pinned client certificate fingerprint, not a caller header, human ID or access token. Rotating a bearer cannot reset the workload budget. Only the configured finite fingerprint set has buckets; unapproved certificates allocate no state.

The token bucket allows an initial burst equal to the minute rate and refills continuously using a monotonic clock. Limits are per process, not distributed cluster quotas. Admitted failures and health requests consume the workload's rate budget. Concurrency rejection consumes no token and creates no queue. Limits remain held until the handler finishes; release is idempotent and occurs on errors as well as success.

| Rejection | Response |
|---|---|
| Global active request cap reached or service draining | `503 {"error":"overloaded"}`, `Retry-After: 1` |
| Workload rate budget exhausted | `429 {"error":"rate_limited"}`, bounded numeric `Retry-After` |
| Unapproved workload | `403 {"error":"sender_denied"}` |

Overload/rate rejection closes keep-alive rather than queueing an unbounded rejected body. The server also caps connections, headers, body sizes and request/handshake duration; Compose retains CPU, memory and PID restrictions. POSTs are never retried automatically. SIGTERM/SIGINT begins draining before listener closure, with a bounded shutdown deadline.

`tool_http` telemetry contains only a fixed operation label and status. Existing `protected_tool` events retain fixed outcome/code/duration. Unknown paths become `other`; Authorization, tokens, certificate data, signed URLs, bodies and client-selected text are not emitted. Telemetry failures do not change authorization. External sink/alerts and retention ownership remain deployment work.

The runtime now also exposes authenticated `GET /health/metrics` with aggregate counters/health flags and requires [restricted pseudonymous audit output](tool-observability.md). Audit write failures block operation/result release and make readiness fail. Ordinary telemetry remains separate and does not control authorization. No external alerts or production retention policy are configured.

## Evidence and remaining gates

Tests cover concurrency saturation without queueing, capacity recovery, independent workload buckets, monotonic refill, unknown-workload rejection, draining, unsafe configuration, authenticated health without human tokens, dependency failure/recovery, credential drift, readiness coalescing/deadlines, and the signed PDP health contract including replay/admin rejection.

The private Docker suite additionally verifies readiness against actual PF JWKS and the independent policy process. When the backend stops, readiness fails while liveness stays healthy and protected requests are denied; restoring the same backend restores readiness and protected operation. Existing interactive/autonomous, revocation, identity, certificate and real token-aging checks still pass.

Final evidence: **31 actual private-Docker checks, 282 production tests, 207 baseline tests and seven disposable Docker packaging/startup checks pass**. The actual PF/Vault/PDP run completed at 11:29:10–11:32:52 UTC on 2026-10-30 (22:29:10–22:32:52 AEDT). All grants, temporary credentials, containers/network and PF client states were independently confirmed cleaned/restored. No Microsoft/Graph request or host port was used, and the persistent Compose service remains unstarted. The final packaging rebuild also rejects null admission configuration in a no-network disposable container.

These are functional bounded-load checks, not production capacity/DoS/HA approval. Monitoring must use a separately approved workload certificate and polling interval. No Docker healthcheck with embedded credentials or anonymous bypass is provided. Production load sizing, audit/alert sink, operational ownership, secret custody and private deployment approval remain outstanding.
