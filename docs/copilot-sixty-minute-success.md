# Successful interactive Generic OAuth token POST — 31 October 2026

The user explicitly approved a 60-minute PF A login token and one further test. The dedicated `copilotLoginJWT` manager now issues 3600-second user tokens; the lab provider trust explicitly permits 3600 seconds. Shorter trust configurations continue to enforce their own limits. The verifier and Direct Line provider-profile configuration have an absolute one-hour ceiling; broker/tool/grant/session lifetimes were not extended. The generic deployment example retains a five-minute provider limit and must not be mistaken for this explicit lab profile.

## Verified live result

| Field | Observed value |
|---|---|
| Capture/run ID | `02df9eab-a72a-4ff4-812c-5b4cfae141f7` |
| POST invocation | `2026-10-30T21:49:57.347Z` / 31 October 08:49:57.347 AEDT |
| Microsoft response | **HTTP/1.1 200 OK**, empty body, Content-Length 0 |
| Microsoft request ID | `e5c1cc7e0ec2d2555167fe0fdc0025a4` |
| Card observation to cURL invocation | **59.557 ms**, including pre-send Vault retention |
| PF A token expiry | `2026-10-30T22:49:43.000Z` |
| Published runtime diagnostic | `Authentication status: signed in. Copilot reports User.IsLoggedIn=true. Delegated tool access has not been verified.` |

Exactly one newly opened Direct Line conversation and one token POST were used, with no POST retry. The client used `content.tokenPostResource.sasUrl` from that conversation's OAuth card without reconstruction or reuse, posting JSON containing only the configured PF A user token. Actual local issuance first proved `exp-iat=3600`, signature/issuer/audience/scope and human binding. The token is subject-only login proof, not delegated tool authority.

**Interactive Generic OAuth token posting and the published signed-in Boolean are verified for this run.** This successful result does not establish Microsoft's exact minimum token lifetime or conclusively identify the object responsible for earlier expiry errors. It also differs from the preceding locally rejected five-minute attempt: that attempt sent no token POST. Earlier three-minute-token POSTs did reach Microsoft and were rejected.

Copilot-originated delegated tool execution, exact `System.User.AccessToken` continuity, autonomous provider SSO and token-expiry behavior inside Copilot remain **UNVERIFIED**. The independent local delegated-tool operation and revocation denials passed; they do not establish that Copilot called the tool. Production deployment/security acceptance remains separate.

## Retention, isolation and cleanup

Encrypted Vault record `federated-copilot-tool-secrets/provider-debug/02df9eab-a72a-4ff4-812c-5b4cfae141f7`, version 2, retains the original token, complete signed URL, application request headers/body and raw response. Presence-only verification confirmed all originals. Automatically generated request headers were not captured. The record remains until operator deletion; the one-day service audit-journal policy does not delete it. No raw credential was written to a plaintext capture or shared in chat.

Explicit operator clipboard retrieval:

```powershell
npm run copilot:retained-capture -- --copy-private 02df9eab-a72a-4ff4-812c-5b4cfae141f7
```

The assistant has not exported this record to the clipboard or submitted it externally. Independent cleanup confirmed the test grant revoked, temporary signing/writer leases and policy retired, credential files removed, PF A login enabled/PF B tool client disabled, and all prior ledger hashes unchanged. Existing private service was preserved.

The fixed `--run-hour-1` mode has a separate one-use `hour-provider-vault-capture` ledger and requires exactly 3600-second issuance before channel creation. All nine conversation reservations are consumed, including the earlier conversation that stopped locally. No automatic repeat is authorized.

## Verification and implementation details

All **297 baseline and 318 production tests pass**, including failing-first one-hour acceptance, rejection above 3600 seconds, enforcement of shorter trust, wrong-audience/expired/future-nbf proof, and consumed-budget negatives. Actual local PF issuance and six synthetic Vault checks passed before this Microsoft attempt.

The live worker now reuses the provider verifier from initial acquisition when checking the same token at the adapter boundary. Each call still performs JOSE signature and claim verification against the pinned public trust; it can reuse the already retrieved approved JWKS within its bounded cache rather than requiring a second cold public fetch. Broker verification and issuer-qualified identity binding remain separate. Sanitized stage markers distinguish future provider-verifier and binding rejection without recording credentials. This does not retroactively identify the cause of the prior generic local rejection.
