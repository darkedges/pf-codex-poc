# Mobile API and Android return-link preparation

Status: **local request/response integration verified; not hosted or connected to live Copilot**. No public routes, PF clients/callbacks, credentials, billing or installed phone app changed. The installed immutable v4 APK remains the local device test. The intermediate build was compiled and verified, not delivered as a live APK.

## Implemented transport

`src/mobile/http-api.ts` exposes a Fetch-style `Request` → `Response` handler. It does not open a port or trust proxy forwarding headers. Deployment must put it behind the reviewed TLS listener and enforce raw HTTP/header admission before converting requests into Fetch objects.

| Method/path | Purpose |
|---|---|
| GET `/v1/mobile/config` | Fixed consent-terms hash |
| POST `/v1/mobile/login/start` | Phone-key/claim-hash-bound browser sign-in |
| GET `/mobile/callback` | Server-only PF authorization-code redemption |
| GET `/mobile/return` | Credential-free fallback status if Android does not handle the link |
| POST `/v1/mobile/enrollment/claim` | One-use return-code claim and fresh foreground-key binding |
| POST `/v1/mobile/enrollment/complete` | Fingerprint-protected enrollment proof |
| POST `/v1/mobile/session/challenge` | Resume challenge under existing enrollment |
| POST `/v1/mobile/session/complete` | Fingerprint-protected resume proof |
| POST `/v1/mobile/chat/messages` | Exact-body signed request; requires separately configured real delegation executor |

API requests accept only the configured HTTPS host and exact routes. POST requires Android WebView origin `https://localhost` or the same configured website origin, JSON content type, no cookies/Authorization bearer header, flat string fields and the exact field set. Duplicate keys are rejected after decoding JSON escapes; nested authority objects, extra identity/scope fields and arbitrary query parameters are rejected. Bodies are capped at 16,000 bytes. These origins are transport restrictions, not device attestation or user authentication.

Requests are bounded to 16 in flight, 120 admissions per minute per handler and a configured 1–30 second deadline (10 seconds default). A timed-out dependency retains its concurrency slot until it settles. Aborting during authorization prevents later executor entry. The executor must respect cancellation and independently check active delegation and resource policy before read/release; a transport deadline cannot undo an already completed remote call. Additional edge/network rate controls remain deployment work.

Responses use no-store, no-referrer, no-sniff and restrictive CSP headers. CORS allows only fixed headers/methods, never cookies or arbitrary-origin reflection. Error responses are sanitized: malformed/unsupported requests are 400/415, denied authority is a generic 401, rate/concurrency limits are 429/503, deadline is 504. A 401 is not a claim that a particular token expired. Optional telemetry contains only a fixed route label, status and elapsed milliseconds, never URL queries, request bodies, proof headers or raw exceptions. Hosting must also suppress sensitive default access/error logging.

The chat executor is absent by default. A correctly enrolled/signed request returns `mobile_chat_not_configured` until the real authority/PF/Copilot composition exists. There is no mock answer fallback. The local integration test injects an explicitly labelled fixture diagnostic solely to test request authorization.

## App-side transport and return link

`apps/mobile/src/http-transport.ts` uses only fixed HTTPS paths, exact signed request bytes, omitted cookies, refused redirects, bounded response bodies, request cancellation and a ten-second timeout. It makes no automatic retries. Provider authorization links must match the configured endpoint. It never sends PF/Direct Line/Graph tokens. Live UI activation still requires a reviewed CSP network allowlist; the current test UI keeps `connect-src 'none'`.

`apps/mobile/src/app-return.ts` validates the exact HTTPS origin/path and one canonical opaque handoff, handles initial-launch and foreground link events once, and ignores malformed/foreign links without logging them. Attach this only while a phone-bound login secret is pending. A cold start without that secret must require a new sign-in. Pending-login handling/browser launch are not yet wired into the test UI.

The built Android manifest declares only `https://agent.copilot.darkedges.com/mobile/return` with autoVerify. Actual Android verification remains **UNVERIFIED** until the exact association file is served and tested on the phone. `src/mobile/android-links.ts` generates the public association for the fixed package and an operator-pinned public certificate. The locally verified debug signer fingerprint is:

`4D:8B:41:27:44:CC:5A:82:1C:A0:93:C2:65:A6:B4:FA:28:31:7A:52:0E:C5:F9:44:50:01:83:9D:9A:14:C6:8A`

This is public certificate data, not a private key. A future release signer needs a separately reviewed fingerprint; do not add arbitrary signers. Candidate association JSON is prepared locally, not published.

The OIDC client now accepts `/mobile/callback` only under explicit server-side `callbackPath: '/mobile/callback'`. Existing callers retain `/callback` by default. Unknown profiles, mismatched paths and unsafe callback URLs are rejected. This source change does not register a real PF redirect or enable a client; those remain deployment approval gates.

## Verification and remaining work

826 backend production, 372 simulation and 21 mobile tests pass. The real app WebCrypto signer and HTTPS transport now exercise the real API handler, handoff, JOSE verifier and durable authority in process: config → browser start → callback → claim → device proof → request → lock/resume → replay/revocation denial. Hardware, browser/PF transport and the final chat diagnostic remain explicit fixtures in that test. No local test is claimed as live Microsoft acceptance.

Android assemble, seven JVM tests and lint pass (zero errors, 15 existing resource/dependency warnings). The merged manifest contains the exact return-link rule. APK signature/public signer independently verified. Web typecheck/build passes with the existing bundle-size warning. No phone install or biometric operation occurred this milestone.

Next: implement external-browser launch and bounded native pending-login state, enrollment-reference custody and invalidation recovery; connect authoritative registry/delegation checks and the real multi-turn/document executor; compose the existing infrastructure into a supervised runtime. Prepare a concrete review for public listener/routes/association, PF callback/IAM activation and ongoing demo authority before deploying. Preserve spent historical allowances, resource boundaries, revocation and the existing budget.
