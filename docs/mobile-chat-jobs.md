# Asynchronous foreground chat

The opt-in mobile job runner separates question execution from the phone's ten-second HTTP timeout. It is wired through the Fetch-style API and the Ionic client, with no listener or live executor activated.

| Request | Authentication | Response |
| --- | --- | --- |
| `POST /v1/mobile/chat/messages` with `{question}` | Fresh exact-body foreground proof and current resource consent | `202 {status:"pending",jobId}` when jobs are configured |
| `POST /v1/mobile/chat/result` with `{jobId}` | A separate fresh exact-body foreground proof for this path | `{status:"pending"}` or one-use `{status:"complete",answer}` |
| `POST /v1/mobile/chat/cancel` with `{jobId}` | A separate fresh exact-body foreground proof for this path | `{status:"cancelled"}` |

The existing synchronous executor remains supported explicitly. Configuring both execution modes is rejected. Missing execution or resource-consent dependencies still deny access. The phone accepts synchronous responses for compatibility; it never substitutes a local answer for a failed live request.

## Authority and lifetime

The job retains the original branded server evidence, not a copy or a new identity reconstructed from polling. It verifies the signed question body and allows only one active job per foreground session. It rechecks device/session state and resource authority before execution, after execution, and before returning the answer. A new unlock invalidates the old foreground authority. Polling cannot renew the original evidence or select another user, grant, scope or resource.

Jobs expire within the original evidence deadline and at most 55 seconds from admission, including validation. Capacity is explicit and capped at 64. An executor that ignores cancellation continues to occupy execution capacity until it settles; timing out cannot open an unlimited number of background operations. Completed answers are held only in memory until one successful read or expiry. Concurrent readers cannot consume an answer twice, and one original request-evidence object cannot start a second job. Restart drops all jobs; there is no recovery replay or durable message history.

The Ionic transport submits once, polls once per second with fresh proofs, and has an overall 55-second deadline. Failed requests are not retried. Lock/background cancels local polling and clears local chat; the server may finish an already accepted operation until its original deadline. Client disconnection cannot retract a Microsoft request already transmitted. The authenticated cancel route aborts cooperative execution, but does not claim to undo external effects. No phone cancellation capability or job identifier is sufficient without a valid foreground proof.

## Verification and next integration

Tests use the actual HTTPS transport, API, temporary device SQLite store, cryptographic foreground proofs and persisted resource consent with an explicitly synthetic executor. Separate tests cover substitution, copied evidence, replay, cross-session reads, concurrent consumption, admission cancellation, timeout, uncooperative execution, capacity and revocation. New result/cancel routes do not allow those proofs to issue chat authority: issuance still requires the original chat-message evidence.

Live asynchronous Copilot execution is **UNVERIFIED**. Remaining work includes protected provider-token renewal, the actual document/chat executor, approved-site cataloguing and supervised hosting. Before activation, verify a real answer with fresh PF exchanges and provider SSO, test foreground lock/revoke/expiry during a pending turn, verify no answer reaches the new unlock, and confirm request bounds and credential-free telemetry. No public routes, PF clients, permissions, Vault custody, phone installation or billing settings were changed for this milestone.
