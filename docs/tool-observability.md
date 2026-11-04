# Tool monitoring and restricted audit

Prepared 2026-10-31 (Australia/Sydney). This is local operational instrumentation for the verified tool runtime. It configures no external notification, log shipping, production retention policy or persistent service. Copilot SSO remains UNVERIFIED; Graph/SharePoint remain disconnected.

## Separate operational output and identity evidence

Standard output contains projected, fixed-schema `tool_http`, `protected_tool`, `tool_tls_rejected` and readiness-transition events. Extra input fields are discarded. No subject, agent, grant ID, token, request body, certificate, private key, signed URL or error message is serialized to that stream. HTTP paths become fixed operation labels; an unknown path becomes `other`. The stdout callback cannot authorize a request, and telemetry failure does not bypass policy.

The verified runtime additionally requires a restricted local audit sink. `TOOL_AUDIT_DIR` must name an existing absolute dedicated writable directory (Compose target `/var/lib/tool-audit`). The server root filesystem and secret mounts remain read-only. Compose requires an explicit `TOOL_AUDIT_SOURCE`; it does not create a missing host path or mount the workspace.

The protected secret mount now also requires `tool-audit-key`: 32 random bytes encoded as 64 hexadecimal characters, managed separately from JWT/PDP credentials. Never put its value in JSON, environment variables, source, logs or chat. Production needs approved secret custody, versioning and a key-retention procedure; the lab generates a disposable key and removes it after verification.

## Audit semantics and bounds

Each protected execution gets a server-generated UUID. After JWT verification the audit records an attempt; successful result release requires a second record after final policy/expiry checks. Denials are recorded with a fixed code and verified identity references when available. Unverified tokens have no identity evidence. Unknown fields and raw token values are not serialized.

The identity fields are domain-separated HMAC-SHA256 references for the receiving issuer/original human subject, actor issuer/subject, organisation, grant and issuer, plus the verified mode and fixed tool audience. The original identities remain in token verification, independent policy enforcement and the authoritative restricted PDP audit. Tool audit references are privacy-preserving correlation data, not replacement identity or permission claims. Key rotation changes references; preserve the approved key-version mapping under restricted custody when production correlation is required.

The audit writes one projected JSON line at a time, synchronously checks the write and synchronizes it to storage. It requests mode 0600 when creating files, rejects nonregular/hard-linked/symbolic-link leaf paths, and rejects a partial final record rather than silently truncating it. Only `tool-access.jsonl` and `tool-access.jsonl.1` are used, each at most 1 MiB. Rotation removes only the previous fixed archive and retains the current file as the new archive; there is no recursive deletion or unbounded log queue.

Failure to write the attempt prevents the operation. Failure to write the completion record withholds its result and returns `503 audit_failed`; it also contributes an aggregate audit-failure counter. Already executed external side effects cannot be undone by a post-operation failure: this runtime exposes only the read-only diagnostic. A success record is execution/authorization evidence, not proof that a client received an HTTP response.

Readiness checks current audit access as well as credentials/JWKS/PDP. Audit failure makes readiness false; restoring the valid evidence file permits recovery. Missing evidence is not silently recreated by a running writer. Startup can create a new journal; partial-record recovery and archive retention need operator review.

These are single-process local files, not signed/tamper-proof/WORM audit storage or a distributed writer. Host administrators can alter them. Windows host ACLs, encryption at rest, external append-only shipping and retention/access ownership require deployment review; requesting a POSIX create mode does not prove Windows ACL isolation. Bounded file retention is a PoC disk limit, not an approved retention duration.

## Authenticated monitoring

`GET /health/metrics` uses the same validated/pinned mTLS workload identity and admission limits as liveness/readiness. It requires no human bearer and invokes no user operation. It returns only:

- Finite per-process counters for requests, throttling, overload, sender/TLS rejection, tool success, invalid tokens, generic policy denial, tool/audit failure and readiness transitions.
- Readiness state (`unknown`, `ready`, `not_ready`) and current audit access status.
- Minimum remaining lifetime of loaded server/CA certificates, with a seven-day expiry flag.

It exposes no identity references or high-cardinality caller labels. Counters saturate safely and reset on restart; they are not distributed quotas or business event totals. Metrics do not force a fresh dependency probe: readiness remains `unknown` until an authenticated readiness check runs. Certificate monitoring covers loaded server/trust material, not every unobserved client leaf certificate represented only by a fingerprint. Production monitoring must include the selected PKI's client-certificate lifecycle.

`policyDenied` is deliberately generic: it can mean revocation, suspension, another policy denial or a failed policy dependency. It is **not** labeled a confirmed revocation. The independent PDP's `grant.revoke` audit event is the authoritative source for actual grant revocations.

## Read-only operations report

`npm run tool:operations-report` inspects only the latest completed isolated Docker test, without credentials, network access or mutations. It aggregates counts from the authoritative PDP database and retained restricted tool journal, then reports cleanup status. It prints no rows, identifiers, tokens, filesystem paths or private material. Historical runs without the new journal report `available: false` rather than implying audit coverage.

This is a local test-evidence report, not a production monitor or external alert subscription. A production collector must be separately authenticated and approved, with a monitoring certificate, protected sink, operator/recipient, thresholds, polling interval and retention policy. None is selected or contacted by this implementation.

## Verification

Tests cover audit projection/rotation, failure and recovery, raw credential/identity exclusion, failure before operation and before result release, signed policy/revocation behavior, bounded monitoring labels and the distinction between generic denial and confirmed revocation. The private Docker harness exercises authenticated/unauthenticated metrics, real policy-denial counters, audit-path failure blocking operation/readiness, evidence-preserving recovery and token exclusion from the actual journal.

Persistent Compose deployment, external alerts, production custody and retention remain pending. The local diagnostics do not establish live Copilot federation or Microsoft data access.


Final local evidence (2026-10-31 Australia/Sydney): **37 private-Docker checks, 283 production tests, 210 baseline tests and seven Docker packaging/startup checks pass**. The final actual run was recorded at 2026-10-30 15:07:45–15:11:52 UTC (2026-10-31 02:07:45–02:11:52 AEDT). Cleanup independently confirmed grants revoked, clients restored, disposable credentials removed and all labeled containers/network removed. The operations report shows five authoritative grant-revocation records, zero active test consents and a restricted journal with projected attempt/success/denial records. It contains no raw token or original human/agent strings. No Microsoft/Graph call, host port, external alert or persistent deployment was used.

A preceding long run stopped during owner-session revocation after token-aging checks; all its grants were revoked during final cleanup. The harness now rechecks terminal state using a read-only database connection and obtains fresh owner proof for the exact grant when required. This neither extends lifetimes nor changes authorization. Failed and completed receipts remain separate.
