# Active private relay caller and prepared runtime

Follow-up: [real grant-backed relay integration](copilot-real-relay.md) now passes 15 actual PF/private-tool checks, including owner revocation and identity audit. The reusable issuer custody implementation is available and exercised in a bounded local harness. It has not been installed as the permanent runtime's issuance/control-plane composition, and no live Copilot tool request was made.

Completed 31 October 2026. The enrolled relay certificate is now an approved caller of the existing **private** tool, alongside the original monitoring certificate. **The persistent relay listener is not started, its issuance authority is not wired, and actual Copilot-originated tool execution remains UNVERIFIED.** No Microsoft conversation, Graph request or public route was created.

## Controlled caller activation

`validateServiceCallerTrust` preserves the original monitor-only startup path when no relay activation exists. With an activation receipt, the controller independently fetches the relay's current KV record through its read-only renderer, validates its certificate/key material, and requires the exact enrolled version, client fingerprint and complete selected configuration hash. It accepts exactly `[monitor, enrolled relay]`, with no duplicate, substituted or additional caller. Secret/pin rotation must be explicitly selected; an unexpected version/configuration change fails startup rather than silently following the latest credential.

The prepared plan `793157b9-5d36-45b6-a2a6-bc5c1c427669` compared the passing candidate's configuration with the active monitor-only configuration, saved a rollback copy and changed only the caller array. The controller was stopped through its instance-bound CLI and restarted hidden under the existing Windows owner/one-day tool-journal settings. Its original eight-hour authority lease was retired normally; no automatic renewal/restart was enabled.

The first activation helper exceeded its startup observation window and retained its recovery lock rather than act on uncertain process ownership. The new controller subsequently reported ready. Independent reconciliation checked the exact prepared configuration and activation receipt, fresh Vault version/fingerprint, live controller status and owned tool/backend labels with no host ports, then recorded activation complete and released the lock. The original failure receipt remains alongside the reconciled result. The helper's startup window is now 120 seconds, with process-specific failure metadata; its rollback path still refuses uncertain ownership or externally changed configuration.

Evidence is retained under `.local/tool-vault/relay-activation-793157b9-5d36-45b6-a2a6-bc5c1c427669`. Selected trust is `.local/tool-vault/relay-tool-activation.json`. The source configuration backup is `previous-tool-runtime.json` in the activation directory. Do not manually remove the activation receipt while leaving the extra caller in the runtime configuration; that combination intentionally fails startup.

## Actual running-tool verification

**Seven checks passed** against the running private Docker tool at **15:51:48 AEDT on 31 October**:

- Selected relay identity matches the active version-pinned trust.
- The target is the current owned, running private tool with no published host ports.
- The relay certificate passes CA/hostname/leaf-pinned mTLS readiness, including the existing signed dependency checks.
- Missing client certificates, invalid tool proof and body-supplied human/resource values are rejected.
- The tool container identity and no-port configuration remain unchanged by verification.

Only a short-lived internal Docker probe received a temporary copy of the relay's client key/certificate and public CA/pin. It received no connector key, Vault/operator/authority token or CA maintenance key. Probe containers and files were removed. This proves caller activation/connectivity; no grant or delegated operation token was created, so it is not a successful delegated tool call.

The monitoring caller remains configured and the controller's own readiness probe succeeds. The service is ready. The new bounded authority lease expires at `2026-10-31T12:48:08.236Z` (**23:48:08.236 AEDT on 31 October**); policy shutdown occurs approximately 30 seconds earlier. PF A login stays enabled and PF B tool exchange disabled.

## Runtime and durable audit preparation

`src/copilot/relay-runtime.ts` loads an explicitly selected verified profile, exact eight-file snapshot and bounded public configuration. It rejects missing authority dependencies, mock mode, relative/noncanonical paths, symlinks/hard links, extra secret files, invalid/mismatched certificates and TLS bypass. Windows path comparison respects case-insensitive identity while retaining canonical-target checks. It loads the connector-key **digest**, never the original connection key.

The runtime composes existing independent broker/provider/tool verifiers, issuer-qualified mapping, current policy and issuance dependencies with the HTTPS relay/Direct Line lifecycle factory. Local credential/configuration/audit readiness is checked before broker authorization during operations; changed snapshot/configuration contents fail closed. This local readiness is not an external service-health or authority-issuance proof. Loading opens no listener or network connection.

`RelayAuditJournal` records only fixed event/request-ID/phase/timestamp fields with a keyed HMAC integrity tag. It excludes tokens, signed URLs, identity strings and arbitrary input fields. Synchronized append, strict record validation and two bounded 1 MiB files provide fail-closed auditing: a wrong key, modified/truncated record, hard link or expired journal blocks use/result release. Rotation may remove records earlier than the retention threshold. One-day retention follows the selected PoC setting; expired files require explicit **stopped-only** whole-file maintenance via `pruneStoppedRelayAudit`. No offline deletion job or active truncation is installed. These local bounded journals do not claim external tamper-proof storage or replace the independent PDP/tool identity audit.

The actual enrolled version-1 snapshot was loaded successfully and audit append/integrity checks passed in a separate restricted validation directory. Its validation dependencies explicitly deny all authority/network operations, and were not called. They are not a deployed runtime or mock fallback. The receipt records `authorityWired=false`, `listenerStarted=false` and zero authority/Microsoft calls.

Prepared files:

- `.local/tool-vault/relay-runtime.json`: selected public profile and fixed private Docker origin `https://tool-api:8443`.
- `.local/tool-vault/relay-service/environment.json`: selected snapshot/configuration/audit paths, verified mode and one-day retention; no raw connector key.
- `.local/tool-vault/relay-service/operations.json`: copied current Windows owner/retention selection.
- `.local/tool-vault/relay-service/preparation.json`: explicit local-only validation/remaining-gate receipt.

The host-side validation did **not** test Docker DNS reachability from a persistent relay process. The configured private origin is for the future reviewed container composition. No listener was started merely to make this profile appear ready.

## Commands and remaining gates

```powershell
npm run relay:activate-caller
npm run relay:verify-active
```

The first command previews activation actions. `-- --prepare` and `-- --apply <plan-id>` are guarded one-time workflow steps; activation is already complete, so do not remove/reset receipts to repeat them. The second command repeats only bounded local workload checks, creating no grants or Microsoft conversation. `npm run relay:prepare-runtime -- --prepare` is also completed and refuses overwriting the selected profile.

All **318 baseline and 370 production tests pass**. New tests cover eight activation trust substitutions, authenticated journal rotation/tampering/retention and strict runtime loading/drift/audit failures. The actual enrolled snapshot and seven running-tool checks are separate evidence from these synthetic unit/contract tests.

Next is a bounded local integration of the relay's **real** grant-backed issuance dependency and private container/control-plane hosting, with original human/actor continuity and revocation verified end to end. Then prepare the exact public ingress and connector deployment for approval, including secure system-token input handling and trace secrecy. Do not start a persistent relay with the deny-only validation dependencies, expose the private tool, enable production IAM or claim Copilot acceptance from these checks. All nine prior Microsoft conversation reservations remain consumed.
