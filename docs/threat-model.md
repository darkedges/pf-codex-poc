# Initial Threat Model and Production Gates

| Threat | Required mitigation | PoC status |
|---|---|---|
| JWT tampering or wrong audience | Verify signature, issuer, `aud`, alg and times | Simulated and tested |
| External agent impersonates another human | Verify human token/short-lived assertion independently; match active grant | Simulated and tested |
| Revoked grant still usable | Online policy check on every protected operation | Simulated, in-memory only |
| Cross-partner resource leakage | Default-deny partner/user/agent/resource entitlement intersection | Simulated for one partner |
| Compromised gateway client | Separate client auth, keys, sender constraints, key rotation | Not implemented |
| Token substitution or key confusion | Hardened JOSE + pinned issuer/JWKS, vetted algorithms and key rollover | Not implemented; demo RSA helper only |
| Autonomous agent uses stale human login | Grant-backed assertion with expiration, lifecycle and signed issuer | Local mock only |
| Malicious document prompt injection | No model control over tokens, tool permissions, site IDs or audience | Architecture only |
| Graph app-only excessive privilege | `Sites.Selected`, explicit selected-site read grants, resource broker | Not connected |
| Direct Line session fixation | Bind channel conversation to authenticated subject/actor/grant | Not connected |
| Leaking a token into prompts or audit | Token redaction and separate secure custody | Demo does not log credentials |
| User or org offboarding races | Event-driven revocation plus online checks / kill switch | Not implemented |
| SSRF via Graph URL or tool parameter | No arbitrary URLs, pinned endpoints and allowlisted site IDs | API has closed operation set |

## High-priority review questions

- What is the authoritative consent evidence for autonomous execution, and what does it allow the agent to do when the user is offline?
- Can current Copilot Studio Generic OAuth and Direct Line channel policies support the unattended token-post flow without an interactive user session?
- What are the maximum approved Microsoft data categories and the data residency/retention rules?
- Who can revoke a grant immediately? What happens to running jobs and cached Microsoft Graph responses?
- Is each partner's identity namespace immutable and unique across both PingFederate servers?

## Do not ship with

`DEMO_ONLY=true`; hardcoded sample principals/grants; local `.local` signing keys; unsigned internal requests; plaintext gateway communications; unauthenticated mock token endpoints; or a Copilot mode that silently bypasses user authentication.
