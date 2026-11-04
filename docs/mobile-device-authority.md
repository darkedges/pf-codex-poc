# Mobile device enrollment foundation

Status: locally verified backend core; live Android/PF/Copilot resumption is **UNVERIFIED**. No listener, route, PF issuance, Microsoft call or service was deployed. The installed v4 APK remains a labelled local device test.

## Enrollment and resumption

`src/mobile/device-authority.ts` is a server-private BFF component. Initial enrollment requires independently verified recent PF OIDC login, fixed deployment terms and a signature by a separate P-256 device key. The existing trusted issuer/JWKS verifier is injected server-side. Raw ID tokens stay in the server callback and are neither persisted nor returned to the phone.

Enrollment preserves original human issuer/subject/audience/authentication time and deployment-pinned agent, organisation and capabilities. It expires absolutely 30 days after successful explicit enrollment. A fresh login and explicit device enrollment can renew the same owner's key; another owner cannot claim or revoke it. Unlock never extends the deadline. Foreground sessions last at most 15 minutes, never outlive enrollment, and replace the previous session for that device.

Each unlock binds a new ephemeral foreground request key into a server-held one-use challenge. Device signatures use `federated-copilot/mobile-presence/v1\n`, separate from the APK's local-test protocol and key purpose. Enrollment challenges expire within 120 seconds and before initial OIDC expiry; resume challenges within 60 seconds. Invalid signatures consume their challenge.

A session ID alone grants no access. ES256 request JWTs require exact type `fc-mobile-request+jwt`, session issuer/subject, deployment-origin audience, at most 60-second validity, one-use JTI and exact method, URL and raw-body hash. Only chat and the three [fixed resource-consent operation paths](mobile-resource-consent.md) are accepted. Evidence preserves its request purpose/hash; an access-status proof cannot authorize chat or approval. Extra authority claims and embedded keys are denied. The foreground key is intended to remain only in phone memory and be discarded on background/lock. Replay consumption is durable across database handles and precedes awaited policy checks; a spent proof is not retried automatically.

Revocation, enrollment/session expiry and independent current-policy denial prevent use, including revocation during an awaited check. The current-policy adapter must resolve stored human, registered actor, organisation and resource entitlements from authoritative registries; chat/header fields cannot choose them.

## Storage and evidence limits

SQLite records contain public keys, auth provenance and consumed hashes, not tokens or chat text. A deployment-profile seal rejects foreign state, profile changes or seal removal. Operators must supply an absolute path in a protected service directory and secure the database plus WAL/shared-memory sidecars. This core does not establish Windows ACLs or defend against an administrator editing records.

Admissions are bounded: 128 devices/pending challenges/foreground sessions, bounded login/replay records and a 2 MiB main database limit. Spent challenge/login/replay entries are pruned only after expiry plus one day. Enrollment revocation state is retained; capacity exhaustion fails closed. WAL/recovery/backup and operational retention remain deployment checks. This store is separate from the one-day audit journal.

Internal evidence is explicitly `registered-device-key` with `hardwareAttestation: UNVERIFIED`. A public key and valid signature prove registered-key possession, not remote biometric/hardware enforcement. Original PF authentication time is preserved, never made artificially recent. Enrollment consent IDs are not PDP delegation IDs. No PF issuer accepts this new evidence yet; it must not substitute for `VerifiedLogin`.

Actual resumed-interactive issuance still needs an independently checked active delegation and short-lived audience-specific proof through policy/Vault/PF. Graph remains app-only through the existing Sites.Selected broker and exact approved-site boundary.

## Verification and next steps

Fourteen local tests use actual JOSE OIDC verification and ECDSA signatures. They cover wrong issuer/nonce/owner/terms/key/purpose/route/body/audience, reused login nonce, challenge/request replay, expiry, separate database handles, profile drift/seal removal, renewal, revocation and an in-flight revocation race. Nonce reuse and active seal removal were reproduced failing-first. Full checkpoint: **810 production and 372 simulation tests pass**.

Owner reports physical fingerprint unlock and completion of the message/background/reopen fresh-chat check on Pixel 6 Pro/Android 17. These are user-observed checks, not captured biometric data or remote attestation; no message/biometric contents were collected.

Next: introduce the separate native live-purpose key and in-memory request signer; add BFF PKCE/state/nonce login and reviewed App Link handoff; define device assurance and current-authority adapters; integrate fresh delegation/PF proof with multi-turn Copilot and the approved-site catalog. Verify actual phone revocation, enrollment changes, process restart, provider SSO and token renewal. Add HTTP admission controls, bounded dependency calls and sanitized telemetry before hosting. Prepare a concrete persistent-service/routes/IAM review before deployment. Old disposable approvals remain spent; no window or budget was extended.
