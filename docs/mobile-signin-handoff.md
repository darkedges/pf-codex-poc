# Mobile sign-in handoff and request signing

Status: **local protocol integration verified; live phone enrollment UNVERIFIED**. The [API handler, HTTPS client and Android return-link source wiring](mobile-api-integration.md) are now implemented/tested, but no listener, public association, PF callback change or persistent service is deployed. The installed v4 app remains the original local test UI. New modules are deliberately not wired into that UI until runtime composition and verified return links exist.

## Implemented components

| Component | Responsibility |
|---|---|
| `src/mobile/login-handoff.ts` | Server-only PKCE/state/nonce transaction and one-use phone-bound return code |
| `src/mobile/device-authority.ts` | Recent verified PF enrollment, durable absolute 30-day device binding and revocation |
| `apps/mobile/src/live-device-session.ts` | Live-purpose device proof, local verification, session binding, cancellation and no-retry failure |
| `apps/mobile/src/foreground-proof.ts` | Non-exportable in-memory WebCrypto P-256 request key and exact-request JWTs |
| Android `MobilePresencePlugin` / `MobileChallenge` | Separate Keystore alias `com.darkedges.federatedcopilot.mobile-presence.v1`, per-use strong biometrics and restricted live-purpose signing |

The new native signer keeps the existing hardware-enforcement, strong-biometric-only, enrollment-invalidation and background-cancellation checks. Its domain is `federated-copilot/mobile-presence/v1\n`; it accepts only `enroll:` or `resume:` plus a 32-byte base64url nonce. It cannot sign JWTs or the local spike protocol. The old `DevicePresence` alias/domain remains separate. Browser access to either native signer is denied. Merely registering the new plugin neither creates a key nor grants authority.

## Server-private browser flow

The phone prepares a fresh 32-byte claim secret and sends its hash plus its live device public key. The server creates independent state, nonce and PKCE verifier, then invokes only its configured OIDC client. The authorization URL must match the deployment-pinned HTTPS endpoint. Client input cannot select issuer, redirect host, actor, organisation or capabilities.

The callback consumes state before redeeming the authorization code. It uses the original PKCE verifier/nonce and returns only a random handoff in the fixed HTTPS URL `/mobile/return?handoff=...`. Neither the provider token nor authorization code enters that return URL. The server holds the returned ID token only in transient memory for at most 120 seconds; `MobileDeviceAuthority` independently verifies it before enrollment. No raw token is persisted or logged.

After the app returns to foreground, it creates a new temporary request key. The handoff claim requires the initiating secret, fixed terms hash and that public request key. The server binds them to the original device key and consumes the handoff before issuing an enrollment challenge. Fingerprint-protected device signing then completes enrollment. Failure consumes the attempt; the controller does not automatically retry the credential-bearing completion.

Pending browser sign-in lasts at most five minutes; returned handoffs at most two minutes. The broker admits at most 64 combined pending/returned/in-flight operations. Expired entries are pruned and process restart discards all incomplete browser transactions. Closing the broker blocks new work and prevents an in-flight callback from returning a new handoff. Durable device enrollment lives separately in SQLite. Dependencies still require their configured bounded timeouts; the existing OIDC client supplies its HTTPS timeout and pinned destinations.

## Lock and session behavior

`LiveDeviceSession` has no network implementation, chat generator or storage fallback. Its injected transport must use fixed reviewed HTTPS endpoints. It verifies the native signature locally before completing the server challenge and checks response shape, expected enrollment, deadlines and generation. Background cancellation rejects late callbacks and clears the foreground request key/session. Each request signs exact raw JSON bytes with ES256, the server session identifier, one-use JTI, fixed method/path/origin audience, bounded expiry and body hash. The session identifier alone cannot authorize a call. Provider tokens and grant IDs are absent from the phone request.

The existing APK UI still uses `DeviceTestSession`; these new modules are not a claim of working live sign-in or chat. Do not distribute the intermediate build as a new live APK. Its debug build version was not promoted, and the immutable delivered v4 artifact remains untouched.

## Verification

- 816 backend production tests pass, including actual WebCrypto app enrollment/resumption through the browser-handoff core, real JOSE OIDC verification and durable server request/replay/revocation checks. The test's OIDC browser transport and device hardware are fixtures, not a live PF/browser/device run.
- 16 mobile tests pass: real signature encoding, exact request binding, wrong purpose/key, missing biometrics, background cancellation, failure without retries, and browser denial.
- Android assemble, seven JVM unit tests and lint pass: zero lint errors, 15 existing resource/dependency warnings. Web typecheck/build passes with the existing bundle-size warning. No APK was installed and no fingerprint prompt was automated.
- Existing simulation checkpoint remains 372 passing; root simulation interfaces were unchanged in this milestone.

## Remaining integration gates

Implement fixed HTTPS handlers with strict body/header parsing, admission controls, timeouts and sanitized audit. Add external-browser launch and a pending-login secret held separately from foreground session keys; loss on process death must require a fresh sign-in. Implement and verify Android App Links against the exact package/signing certificate, then add the matching server association route. The OIDC callback/client configuration must be reviewed before live IAM changes. Reject unexpected app-return URLs and never use a web-view login or arbitrary deep link.

Wire authoritative current-policy checks and a separately reviewed resumed-interactive delegation path before PF issuance; registered-key evidence remains `hardwareAttestation: UNVERIFIED`, not fresh PF login. Complete key invalidation/re-enrollment recovery. Integrate multi-turn Copilot and approved-site retrieval, then prepare the concrete persistent deployment review. Existing spent allowances, budget and SharePoint boundary remain unchanged.
