# Microsoft Generic OAuth token-post rejection — support draft

Latest corrected-provider evidence (2026-10-31): the user authorized one new PF A user-token request captured through cURL. Microsoft returned HTTP 400 and exact body `"Token is expired"`; request ID `7da611c1417a7063c88ae1f2bbbcf00d`. Token lifetime remaining was 174 seconds, challenge lifetime 57/58 seconds, and the measured parsed-card-to-cURL interval was 161.787 ms. See [actual capture and cleanup](copilot-provider-capture.md). This is the first corrected-provider test; earlier four PF B-token attempts remain historical. All five individual allowances are consumed, with no retry. Microsoft acceptance and the identity of the expired object remain unverified.

Important client correction (2026-10-31): the historical attempts below posted the PF B delegated tool JWT, while the agent's recorded Generic OAuth provider is PF A. Those failures did not test the correctly configured provider user-token flow. The [local correction](copilot-provider-token-fix.md) now separates provider sign-in from tool authority and passes a real PF A acquisition check without contacting Microsoft. No new live allowance was consumed; the HTTP 400 cause remains unproven. Include this finding before using the historical support packet.

Prepared 2026-10-30 (Australia/Sydney). **Draft only; not submitted.** Manual PF sign-in and the current agent's `User.IsLoggedIn=true` diagnostic work. This incident concerns the separate Generic OAuth secure token-post flow.

Update 2026-10-31: the user confirmed no case exists. A [sanitized support bundle](copilot-support-bundle.md) now consolidates all four historical attempts and the newer independently verified local service/canary evidence. The older initial trace below is retained as history; the latest request ID is `320cc71fbead2f79d8b9e025737fc8ed` in the retry section. No additional Microsoft request or submission was made.

## Request to trace

| Field | Value |
|---|---|
| Service | Microsoft Bot Framework Token Service |
| Method and destination | `POST https://token.botframework.com/api/sas/postToken` — signed query deliberately omitted |
| HTTP response | 400 Bad Request |
| Response category | Expiry-related text, classified to fixed label `expired`; original response body not retained |
| Microsoft request ID | `c28843b0bdc85a5d4004f46700b19b94` |
| Run window, UTC | 2026-10-29 20:57:29–20:57:34 |
| Run window, local | 2026-10-30 07:57:29–07:57:34 AEDT |
| Environment | Federated Copilot PoC, `c72f8bf6-020d-e210-8662-fa461a415ec2`, Australia |
| Agent | Federated Delegation Test, bot `1d18f6de-66d3-f111-a05b-6045bd40333e`, schema `cra8f_FederatedDelegationTest` |

## Measurements from the failing interactive request

- Fresh OAuth card received from the pinned bot in the bound Direct Line conversation.
- Secure challenge expiry was a Unix-seconds value. Only relative timing was recorded, not the actual query value.
- On card receipt: approximately **58 seconds remaining against host time**, **59 seconds against the provider response Date**.
- Immediately before the failing POST: approximately **58 seconds remaining against both host and provider time**.
- The separately issued PF B JWT had approximately **119 seconds remaining** at the POST. It passed independent JOSE signature/issuer/audience/key/lifetime validation and an independently authenticated online grant-policy check. A local policy-protected diagnostic also accepted its original human/actor/organisation/grant/mode before transmission.
- An earlier credential-free Microsoft Date check showed host/provider time aligned to the nearest second.

These measurements do not establish which internal token or record the service considered expired. They make simple local elapsed-time expiry an unlikely explanation for this particular attempt. No server-side exception trace is available to us.

## Protocol and reproduction

The client uses the existing current-agent Direct Line secret to generate a conversation-scoped token, starts a conversation and submits the fixed `/federation-status` diagnostic message. The current agent requires manual Generic OAuth sign-in. The channel emits an `application/vnd.microsoft.card.oauth` attachment containing `content.tokenPostResource.sasUrl`.

The backend validates the bot/conversation/activity batch and exact approved destination, obtains a fresh consent/grant-backed PF B access token with human/actor/grant/mode continuity, independently verifies it and checks live policy. It submits JSON `{ "token": "..." }` with `Content-Type: application/json` to the fresh secure URL. No Direct Line Authorization header is sent to the token-post endpoint, no sign-in URL is followed, redirects are rejected and POSTs are not retried.

This follows Microsoft's [Generic OAuth token-post documentation](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-sso-3p) and the JSON body shown in its [Okta sample](https://github.com/microsoft/CopilotStudioSamples/blob/main/sso/okta/public/index.html). The sample's fetch continuation does not check HTTP status; our client explicitly rejects non-success status instead of claiming authentication completed.

The PF token is synthetic lab data, issuer `https://pf-b.copilot.darkedges.com`, audience `api://copilot-tool`, scope `copilot.invoke`, and maximum lifetime 120 seconds. It is separate from the PF A human-login token and broker-audience token. Signed actor/grant claims cannot be inferred from a chat prompt or channel user ID.

Two earlier approved attempts (interactive and autonomous) also returned HTTP 400; the autonomous request classified expiry-related, request ID `5319621832974d895c07d7d18f2aad02`, run window 2026-10-29 20:50:27–20:50:34 UTC. Their timing was not recorded, so do not retroactively attribute the measured 58/119-second remaining lifetimes to them.

## Questions for Microsoft

Please trace the specific request ID and identify the underlying rejection. Which object was considered expired: the signed URL, OAuth state/sign-in record, connection/session binding, or posted access token? Which expiration value and service clock were used? Does the service require additional connection, user-binding or origin configuration for this backend Direct Line token-post pattern? Please provide the relevant supported requirement and a sanitized exception category without returning credentials, tokens or signed URL values.

## Cleanup and boundaries

The initial three explicitly approved attempts and the later single operator retry are all consumed: four total. No automatic retries or extra conversations occurred. Every test grant is independently confirmed revoked. PF A's human login client remains enabled and unchanged; PF B's temporary tool client is disabled again. No public route, tenant authentication/IAM policy or Graph/SharePoint access was added.

Local interactive and autonomous token/policy/revocation evidence is separate from Microsoft acceptance. We have not verified successful Generic OAuth token-post sign-in, exact token continuity inside Copilot, autonomous Copilot execution, tenant expiry handling or a Copilot-originated protected tool call.

This draft contains no authorization code, validation code, cookie, SAS URL/query value, channel secret or access token. Do not attach an unredacted HAR or raw browser/network dump.

## Protocol review after service recovery — 2026-10-30

Rechecked Microsoft Learn's Generic OAuth SSO article (last updated 2026-03-19). Its supported-channels section explicitly includes any client working with the Direct Line API. A browser-only requirement is therefore not established by that document. The exact saved authentication connection and Microsoft service-side SAS/session validation remain possible investigation points, not confirmed causes.

Added offline production-adapter regressions proving that a challenge with percent-encoded signed query values is posted without rewriting its query bytes, using POST, JSON with exactly one token property, no channel Authorization header or cookie, and redirects rejected. A synthetic expiry-related HTTP 400 closes the session, sends exactly once, does not release the accompanying bot message and does not expose the vendor body in telemetry. All 230 production tests pass. These are local protocol checks, not new live Microsoft evidence; no additional conversation, token post or PF client enablement occurred.

Next external action: open a Microsoft support case for the existing Copilot Studio/Power Platform environment and supply the request ID and run window above. Request a service-side trace of the SAS/state/connection expiry check. This document is ready to attach and has not been sent. A further live attempt is useful only after a concrete diagnostic or configuration correction is identified and a new bounded attempt is explicitly approved.

## Explicitly approved single retry — 2026-10-30

Following explicit operator approval, one fresh interactive conversation and one token POST ran at 2026-10-30 08:41:03–08:41:14 UTC (19:41:03–19:41:14 AEDT). Microsoft again returned HTTP 400, expiry-related text (raw body not retained), request ID `320cc71fbead2f79d8b9e025737fc8ed`. At POST, challenge lifetime was approximately 57 seconds against host time / 58 seconds against provider Date; independently verified PF token lifetime was 119 seconds. Local protected-tool verification passed; grant revocation subsequently denied local tool and channel access. Read-only database inspection confirmed the one consent-backed grant revoked; independent PF administration checks confirmed human login enabled and tool client disabled. The separate one-attempt retry budget is consumed; earlier budgets remain unchanged. No successful Microsoft token-post or Copilot tool acceptance is claimed.

Preflight initially stopped before any conversation because the local Vault runtime lease had expired. The existing Vault setup command refreshed its sign-only lease; no development signer fallback was used. The approved diagnostic then ran once. This adds a second fresh-lifetime request trace to the support case; it does not identify the expired Microsoft-side object.
