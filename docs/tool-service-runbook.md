# Persistent local tool service — operational runbook

Updated 2026-10-31 (Australia/Sydney). Existing Windows/Docker host and local Vault custody selected. **The Vault KV mount, certificate role, tool-only read policy and dedicated local runtime credentials are enrolled and verified.** The persistent policy launcher now preserves an isolated registry/replay database without fixture grants. Verification leaves services stopped; no public route or alert subscription is activated. See [persistent backend and enrollment](persistent-tool-backend.md).

## Persistent activation prerequisites

The disposable private-network tests already prove actual PF/Vault/PDP/tool behavior, readiness, audit failure and recovery. Their backend, policy database and certificates are intentionally torn down. They cannot be used as a persistent service dependency or promoted by copying a run directory.

Before a concrete start plan can be applied, identify:

| Required item | Acceptance condition |
|---|---|
| Tool image | Tested immutable local image ID/digest from the review record; no moving-tag production promotion |
| Runtime config | Explicit reviewed issuer/JWKS/kids/org/actor trust, policy origin/workload/key ID, tool audience/scope, client-certificate pins and bounded admission; no null authorities |
| Persistent PDP/authority | Dedicated lifecycle and durable registry/consent state; default-deny trust and restart/lease/revocation handling verified |
| Private backend transport | Fixed JWKS/decision/health routes, DNS/SAN/CA agreement and explicit trust in any TLS termination; no test-ephemeral policy port or bypass of internal-network restrictions |
| Server/caller certificates | Server SANs match actual names used by callers (host loopback and/or private Docker DNS); selected caller certificate(s), CA/pins, ownership and rotation procedure |
| Secret delivery | Selected provider and tested read-only tool-only delivery; no PF admin, Vault operator, Direct Line, authority signing or Entra credentials in this container |
| Audit | Dedicated existing writable directory, host ACL/ownership reviewed, retained HMAC key/version under protected custody, approved retention/access procedure |
| Operations owner | Named service/key/audit owner, monitoring certificate and incident/alert route; external messaging needs a separately selected destination |

The existing PF B tool client remains disabled outside controlled tests. A persistent issuance/client-enablement plan must be reviewed as part of activation; running the resource tool does not implicitly authorize enabling token issuance indefinitely. No external human is provisioned in Entra.

## Selected credential delivery

The user selected the existing local Vault integration for this PoC. A shared Windows host remains a custody trust boundary; this does not establish production security approval.

`infra/tool-api/vault-runtime-read.hcl` is installed and grants read-only access to exactly one KV v2 record. Certificate authentication produces a one-use, 120-second reader token without the default policy. Dedicated local server/caller/backend certificates and a separate tool PDP key are enrolled; the six-file snapshot and runtime config pass the loader. The tool receives only rendered files, never the reader certificate/key, root token, CA private key or authority signing lease. Use the non-destructive enrolled test now that credentials exist. Private backend transport, audit ownership/retention and activation acceptance remain gates.

The renderer uses a dedicated Windows directory restricted to the current account and SYSTEM, rejects reparse points and verifies child ACLs. Select one complete snapshot explicitly and mount it read-only. Do not mount the workspace or a whole `.local` tree. These host files are the delivery mechanism from Vault, not an alternate credential authority. Rotation requires reviewed drain/replacement and retired-file handling; no automatic fallback or service activation is implemented.

## Offline planning and validation

1. Run `npm run tool:deployment-review`. It remains non-deploying and identifies unresolved gates.
2. Review the immutable image and runtime JSON privately. Never use a Docker inspect dump of environment/credentials as an artifact.
3. Supply only explicit absolute source paths for `TOOL_CONFIG_SOURCE`, `TOOL_SECRET_SOURCE` and `TOOL_AUDIT_SOURCE`, plus the reviewed immutable `TOOL_IMAGE`, when rendering `docker compose -f infra/tool-api/compose.yaml config`. The sources must already exist; Compose must not create missing host paths.
4. Confirm exactly `127.0.0.1:9480:8443`, non-root UID 1000, read-only root/config/secrets, only the audit directory writable, internal network, no Docker socket, bounded resources/logs and no automatic restart loop. Rendering is not activation.
5. Complete the persistent backend/secret-delivery and owner selections above, then present the exact concrete start/recovery plan for activation. Do not use the synthetic test secret mount, change the review flag, disable mTLS/TLS, or attach a general egress network to get a green status.

## Start acceptance after a concrete deployment is ready

Use only synthetic identities/grants for the first canary. Readiness and metrics calls require an approved mTLS monitoring workload; they do not need a human token. Verify liveness, current readiness, audit access and loaded certificate lifetime before one fixed tool diagnostic. Independently verify grant/audience/subject/actor binding and policy audit, then exercise wrong token/certificate/resource, revocation, dependency outage, audit outage and recovery. No Copilot conversation is part of this activation acceptance.

`npm run tool:container-test -- --load` adds a bounded burst experiment to the disposable harness. It narrows that test process to four active requests and eight tokens/minute, sends 64 requests with at most 32 callers in flight, checks explicit 429/503 rejection and eventual recovery, and records only aggregate counts/latencies. It does not change the review defaults, create an unbounded queue or establish production throughput/SLA approval. Its policy and audit checks remain enabled under load.

Verified 2026-10-31 (Australia/Sydney): all **40 private-Docker checks** and **216 baseline tests** pass. In the recorded burst, all 64 requests completed: 8 accepted, 56 rejected with overload status, no unexpected responses and no network errors. Total measured batch time was 1,278 ms and all-request p95 was 834 ms, including TLS/client time. This burst exercised the concurrency rejection path; it produced zero 429s. Separate HTTPS/unit tests cover rate rejection/refill. The test then confirmed counters and a new authorized diagnostic after recovery. Eight total successes do not imply eight simultaneous handlers; requests can complete in successive waves under the four-handler cap.

The run completed at 2026-10-30 15:28:11–15:32:50 UTC (2026-10-31 02:28:11–02:32:50 AEDT). All test grants, credentials and labeled Docker resources were cleaned up and PF clients restored. No host port or Microsoft/Graph request was used. The production runtime was unchanged in this milestone; its prior 283 production tests remain the separate runtime regression evidence. These local measurements do not resolve production sizing or the pending credential-storage selection.

## Day-to-day operation

- Poll authenticated readiness/metrics at a selected bounded interval using the monitoring workload. `unknown` readiness is not ready, and generic policy denial is not a confirmed grant revocation.
- Review certificate/key expiry and audit capacity. The local journal retains only two bounded files; export/retention must be defined before real data is authorized.
- Use the restricted PDP audit as the authority for grant revocations. The current `tool:operations-report` is only a read-only completed-test report, not a live production monitor.
- On 429, reduce the caller's request rate; on overload, reduce concurrency. Do not automatically replay tool POSTs. Investigate readiness and audit status before restarting.

## Stop, recovery and rollback

Drain the service before listener shutdown and preserve the bounded audit evidence. Stop only the exact Compose project/service being operated; do not stop unrelated Docker workloads. Revoke canary grants and restore a temporarily enabled issuance client to its agreed disabled state. Independently verify those terminal states.

If audit access fails, keep results blocked. Preserve the journal/held evidence, correct the path/permission/storage fault and verify readiness plus one newly authorized diagnostic; do not truncate a partial record or substitute stdout. If credentials/trust are uncertain, keep the service unavailable until reviewed.

Rollback uses only the last reviewed image/config with credentials that remain valid. Never restore a revoked certificate/key, relax audiences/issuer policy, select mock mode, reset Microsoft test budgets or grant tenant-wide access as a recovery shortcut. Windows autostart and automatic container restart remain unconfigured until the persistent dependency/lease recovery procedure is accepted.

Microsoft secure-token-post rejection, Copilot calling-workload authentication and resource-scoped Graph/SharePoint deployment remain independent gates.

## Enrolled transport checkpoint

The [enrolled private Docker path](enrolled-tool-network.md) now passes 23 live readiness/transport/denial/outage checks using the actual Vault-held local credentials and persistent policy profile. The verification opens no host ports, creates no grant and removes its containers/network/temporary credential copies afterward. This resolves the local transport proof; the persistent Compose service is still unstarted. Next is a consent-backed canary through this enrolled path and the remaining continuous-operation/audit acceptance.

## Enrolled consent checkpoint

The [consent-backed canary](enrolled-tool-canary.md) now passes 47 combined live checks using actual PF login, both modes, independent policy identity audit, real token expiry/renewal and owner revocation. Parent and independent final checks confirm terminal grants, restored PF clients and removed verification resources/leases. Readiness and consent-backed diagnostic acceptance are now locally verified; continuous activation and operational/audit acceptance remain pending. Microsoft token-post/caller behavior and Graph access remain separate gates.

## Controller and operations checkpoint

The [local controller](local-tool-controller.md) now supplies concrete configure/serve/status/stop/recover commands. Eleven live lifecycle checks and seven live command/crash checks pass, plus all fourteen policy integration regressions. Owned process/network/lease recovery preserves service audit bytes and selected credentials; services are stopped after verification. The current Windows service/audit owner and retention selection was requested and remains pending; no operations config is saved and actual journal deletion stays disabled. Do not infer continuous activation or a Windows autostart task from controller availability.

## Current local activation

The user subsequently selected their Windows account and one-day tool-journal retention. The controller is now configured and running in a hidden background process, with independent enrolled mTLS readiness verified and no published tool ports. PF B stays disabled and no grants were created. Use tool:service -- --status / --stop / --recover and the [controller guide](local-tool-controller.md) for restart/maintenance. It stops before its bounded authority lease expires and has no automatic restart or Windows autostart. One-day maintenance covers this service journal only and runs during controller maintenance while stopped; consent/PDP audit and offline retention remain separate policies.
