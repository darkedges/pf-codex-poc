# On-phone sign-in diagnostics

Latest owner checkpoint, 4 November 2026: the owner reports that PF sign-in now succeeds, a biometric prompt appears and later biometric unlock seems to work after the v8 update. This is owner-observed phone progress. A mobile document answer, new-conversation isolation, provider refresh and revocation still require verification; no full acceptance or startup-task installation is inferred from the report.

V6, version 0.2.1 / Android versionCode 6, adds a local sign-in diagnostics panel. It does not fix or claim acceptance of the unresolved phone sign-in flow.

Install the signed update in place. Open the app, tap Sign in once, then expand **Sign-in diagnostics · v6** and select **Copy diagnostic report**. If clipboard access is unavailable, touch and hold the read-only report, select all and copy. Share only that report. No Wi-Fi ADB connection is required.

The report holds the latest explicit sign-in attempt in app memory: build version, UTC start time, relative event timing, fixed stage/outcome values, allowlisted native error codes and bounded HTTP failure status. Stages identify session locking, biometric availability, key creation, native pending login, backend initiation, browser launch/return, claim, enrollment and resource entry. Background/cancel events distinguish interrupted attempts. Starting another explicit sign-in clears the prior report; process termination also loses it.

No error message, URL, callback, request/response payload, key material, provider token, claim/handoff secret, device ID, enrollment/session ID, question or document text is recorded. There is no upload, analytics endpoint or automatic report transmission. Bridge logging and WebView debugging stay disabled. Native errors outside the fixed code allowlist are omitted; a fixed stage still identifies where they occurred.

The report is diagnostic data, never identity or authorization evidence. Existing device signatures, human/actor/resource binding, replay protection, current-grant checks and no-retry rules remain mandatory. Backend configuration and IAM are unchanged.

The v6 release uses the same demo signing certificate as v5. SHA256: `fbc55cbc0bd4128eac0abeb4d8843e3c9d2c21c6615b2f2f0d6639ba8a7d8e65`. Public download is an exact v6 path on the existing APK service, valid for the service's 24-hour window, with v5 retained and no directory listing. Public download bytes are verified before sharing the link.

Verification: failing-first diagnostics tests; 45 mobile tests, 27 backend device/controller integration tests, 12 native unit tests, web typecheck/build and Android assemble/lint pass. Lint retains 15 existing warnings and zero errors. Two APK endpoint tests cover exact paths, unsupported versions, methods, queries and expiry. Actual report copy and the failing sign-in stage still require owner phone observation.

## V7 browser request receiver fix

Version 0.2.2 / versionCode 7 fixes an immediate browser TypeError in the HTTPS transport. The native window.fetch function had been stored as an object property and invoked with the transport as its receiver. An isolated real Chromium check using only a synthetic data URL reproduced TypeError for that call and success when bound to the global object. A failing-first test now enforces the correct receiver; the transport binds fetch to globalThis. No destination, CORS, TLS, timeout, replay or permission check was relaxed.

The v6 owner report showed all native prerequisites passing, followed by backend_login failure after 9 ms with no HTTP status. This defect explains a pre-network failure; actual phone completion still needs observation. V7 retains the local diagnostic report. Tests: 46 mobile, 27 backend device/controller integration, two exact-download endpoint tests, Android build/lint and 12 native tests pass. The same signing certificate is retained. APK SHA256: 07fba86a560d3cba0621a3fab00c91c5111176f3f2bfa52f58be2c6a31528249. Install over v6, tap Sign in once and report the next outcome or diagnostic report.

## V8 Android browser selection

The owner's v7 report confirms backend_login now passes and browser_launch fails with the former generic mobile_browser_unavailable code. A fresh bounded PF PAR initiation was checked using only Boolean URL comparisons; its output meets the native host/path/client/request-URI policy. No actual phone browser package is visible while the owner is off-network.

V8 (0.2.3 / versionCode 8) replaces the MAIN/APP_BROWSER preflight that rejected a null/chooser result with documented HTTPS VIEW/BROWSABLE discovery and manifest visibility. Public resolved intent-filter APIs admit only generic HTTPS handlers with no host/path/scheme-specific restriction, exported/enabled and outside this package; duplicate packages are removed. A valid default is preferred, a single eligible browser is launched directly, and otherwise an explicit chooser contains only the eligible browser packages. The sensitive PF URL is never used for discovery or logging; existing pinned URL, one-use transaction, device-key and return checks remain.

Native failures now distinguish state, URL rejection, no eligible browser and launch failure using fixed codes. Four new native tests cover absent-default choices, unsafe/self/disabled/duplicate activities, no candidates and restricted-filter exclusion. Failing-first compilation and subsequent successful verification are retained locally. All 47 mobile, 16 native and two download endpoint tests pass; web/Android build and lint pass. SHA256: 99dc70d92ff72f4bed312341f3981b66148fef8681a5d9c7db96a5309107ff64. Signature matches prior releases. Public v8 is added only to the existing APK route; all previous releases remain. Phone launch/callback acceptance still needs owner observation.

## V9 server-time anchor for resource request proofs

The owner clarified that v8 completes PF login, return, native biometric enrollment and enrollment-reference saving but returns HTTP 401 during resource access. Read-only server records contain no consumed request-proof replay entries. Comparing the report's completion time with server enrollment creation indicates the phone clock was approximately six seconds ahead, inferred from rounded/report timing plus response delay. Do not label the initial phone observations as full chat acceptance.

V9 (0.2.4 / versionCode 9) returns serverTime with successful signed-device enrollment/resume completion and anchors foreground JWT timestamps to that authenticated server time plus monotonic elapsed time. It keeps original PF auth_time, absolute enrollment/session deadlines, exact purpose/body/route, current-policy, replay consumption and zero server JWT clock tolerance. Missing/implausible anchors or overlong sessions fail closed. Consent-response lifetime checks use the same learned server clock after completion. Device challenges still have their existing short validity and strict binding.

Regression reproduces the ahead-phone case and proves later wall-clock changes do not affect request proof time; server tests still deny unadjusted future proofs. All 900 production, 49 mobile and 16 native tests pass, plus two exact-download tests. Android/web build and lint pass. The source repair is limited to the serverTime completion metadata; original pinned source/manifest/approval are preserved under the private clock maintenance history with an exact before/after reconstruction and unchanged IAM/allowances. The owned service was restarted, invalidating foreground sessions but retaining device enrollment and consent history. Older APKs expect the former completion shape and should be updated before further use.

Same-certificate immutable v9 SHA256: 1038099b91bdfc593a2514cb38a51a3598e25267371f904f43925ca17babc33f. Exact public artifact bytes are verified. Phone resource approval, chat appearance and document answer still require owner observation. If unlock does not enter chat, start a new explicit sign-in and copy the v9 diagnostic report.

## First-question backend replay-window repair

After v9 allowed resource approval and chat entry, the first questions failed before PF issuance. The approved 180-second mobile actor assertion reached a generic replay registrar capped at 65 seconds. The backend now uses a separate registrar for exactly the four mobile authority/exchange callers, with a bounded 185-second retention limit, only when the explicit 180-second profile is selected. All original signature/grant/identity/replay checks and generic one-minute bounds remain. Existing v9 can continue after a fresh fingerprint unlock; no APK update is needed. Two prior questions remain spent. No Graph/Copilot request was made by those failures or replayed during repair; actual mobile answer acceptance remains pending.
