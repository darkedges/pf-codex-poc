# Credential-free relay header diagnostics

Activated on 1 November 2026 Australia/Sydney for the existing Windows/Docker PoC. No public diagnostic route or additional port was created. Response status/body and authorization checks are unchanged.

Each HTTP observation contains only a fixed event name, numeric status and two credential-header state enums: `missing`, `multiple`, `oversized`, `malformed` or `present`. `present` means one nonempty, bounded, whitespace-free header value; it does not mean cryptographically valid or authorized. No header value, prefix, length, fingerprint, body, identity, exception text or URL is recorded.

The managed application sends these observations over existing controller IPC. The controller projects the finite fields again before writing `.local/tool-vault/relay-service/callback-diagnostics.json`, with its own instance ID and timestamp. It retains at most 16 observations and drops observations older than one day on the next write. This is bounded local operational metadata, not the authoritative identity audit. There is no offline deletion job while the controller is stopped. Match the diagnostic instance to current service status before attributing records to a running process.

Diagnostic IPC can arrive before readiness. The controller now waits for an explicit matching-instance ready message, ignoring diagnostics and foreign ready messages; child failure/exit/deadline still fails closed. Readiness listeners and timer are removed on completion.

## Verification

The HTTP regression first failed for absent diagnostic fields, then passed after implementation. Tests cover missing, duplicated, malformed and present headers, no raw synthetic credential strings, unchanged deny/allow/replay behavior, strict IPC projection and readiness ordering/failure cleanup. Full suites passed: 449 production and 369 baseline tests.

Restarted only the owned managed relay on existing loopback ports; main PF/tool services preserved. Five actual local denied requests verified the running implementation:

| Probe | Status | Provider / caller states |
|---|---|---|
| Correct caller key, synthetic unbound provider | 403 | present / present |
| Wrong caller key, synthetic unbound provider | 401 | present / present |
| Missing provider header | 401 | missing / present |
| Missing caller header | 401 | present / missing |
| Whitespace-bearing provider value | 401 | malformed / present |

No Microsoft requests, PF token issuance, new grants or tool invocations were used in these probes. Historical allowance hashes remained unchanged. Evidence: `.local/copilot/relay-microsoft-review/header-diagnostics-local-verification.json`.

## Microsoft connector probe

Use the repaired connection's existing Test operation with `synthetic-unbound-provider-check2` and fixed `{}` body. No real token or chat conversation is needed. Inspect only fresh observations after the local verification window. This nonempty synthetic provider has no binding: with intact headers and the correct caller key it must fail with 403 before PF verification or tool use. A fresh 401 with both states `present` therefore identifies caller-key rejection for this controlled probe; missing/malformed states identify header delivery problems. This inference does not apply generally to a bound real-token request, where later token verification can also return401.

If Microsoft reports a response but no fresh relay observation appears, do not infer header failure from an older record. Investigate caching/routing or whether that request reached this instance. Never enable raw header/body tracing or paste tokens to diagnose it. The original and follow-up automated conversation/token-POST allowances remain consumed.
