# Federated Copilot — Android device-test milestone

**Status: user-observed fingerprint unlock passed on the owner's Pixel6Pro/Android17 with installed v4.** The owner reports the Android fingerprint dialog followed by the empty **A clean slate** test-chat screen. Startup key-policy/capability and installed version were independently verified; the completed signature is inferred from the implemented screen transition, not separately captured. No biometric interaction or PF enrollment was automated. Cancel/background/reset cases remain separate pending physical checks.

This is the first milestone of [the Android migration plan](../../docs/ionic-android-migration-plan.md): a real Ionic React/Capacitor shell and native Android biometric-protected key operation. Every screen identifies it as **DEVICE TEST**. It has no PF session, Copilot/Direct Line connection, SharePoint access or30-day server enrollment yet. Its chat replies are explicitly local test messages, not Microsoft responses. Do not use it to demonstrate live federation/document access.

## Prepared APK

- File: `.local/mobile/releases/federated-copilot-device-test-v4.apk` under the repository root.
- Package: `com.darkedges.federatedcopilot.demo`; Android versionCode4/versionName0.1.3.
- SHA-256: `8057c6baa7b448ace36fed245b34b10c0f27ee30c4b916cb7d6a7e4596b4a6fd`. See `.local/mobile/releases/device-test-build-v4.json`. APK signing was independently verified, and the update preserves the existing key/data.
- Android11/API30 minimum; compiled/targeted with the installed Android16/API36 SDK. Testing on the owner's Android17 Pixel6Pro remains required.
- Local debug signing only. Signing key is outside git in the owner/SYSTEM-protected `.local/mobile/signing` directory. It is not a production/app-link identity or any backend credential.

When ready to install through ADB, connect and authorize only the intended USB phone, then run from the repository root:

```powershell
$adb = Join-Path $env:LOCALAPPDATA 'Android/Sdk/platform-tools/adb.exe'
& $adb devices -l
& $adb -d install -r (Join-Path $PWD '.local/mobile/releases/federated-copilot-device-test-v4.apk')
```

Open **Federated Copilot** manually. The current v4 update was installed/launched over the owner's authorized wireless ADB connection after diagnosing the immediate v2 key-policy rejection. Fixed-field startup diagnostics confirm the existing hardware key meets policy and strong biometrics are available; the owner has now observed a fingerprint prompt and successful empty-chat transition. If multiple devices are attached in a future update, select the intended device explicitly rather than installing on an arbitrary target.

## Native boundary

`DevicePresencePlugin.java` creates a non-exportable P-256 Android Keystore **test** key. It requires a strong biometric for each signing operation, rejects software-backed or improperly configured keys, excludes device-PIN/password fallback and requests invalidation after biometric enrollment changes. It never exports a private key. JavaScript receives only public SPKI metadata and a signed one-use test challenge.

The native challenge parser accepts only the local-spike namespace and signs a fixed domain prefix. It cannot sign arbitrary JWTs, URLs or another protocol's input. A fresh challenge and exact public-key binding are checked in the controller, then the DER ECDSA signature is independently verified with WebCrypto. This demonstrates a local cryptographic operation; it is not remote hardware attestation or PF authentication and grants no backend authority.

Android has two per-use metadata representations. The legacy API reference documents `-1`, while Keystore2 initializes an absent authentication timeout to `0`. The owner's Android17 Pixel was measured reporting `0`, with hardware-backed, hardware-enforced strong-biometric-only authentication and enrollment invalidation all true. The initial legacy-only check incorrectly rejected that valid key before the prompt. A failing-first device-derived regression now accepts exactly `-1` or `0`, continuing to reject positive time windows and unknown negatives; all other hardware/authentication checks remain required. [Legacy KeyInfo contract](https://developer.android.com/reference/android/security/keystore/KeyInfo), [Keystore2 implementation](https://android.googlesource.com/platform/frameworks/base/+/228306b008a97eab6841a1cb9c93b750f2e18bb2/keystore/java/android/security/keystore2/AndroidKeyStoreSecretKeyFactorySpi.java).

App background/lock cancels pending native authentication, invalidates the controller generation, discards messages and blocks late callbacks. Every successful unlock starts a new empty in-memory test chat. Browser use has no mock biometric fallback. The packaged test page disallows web network connections, contains no remote credentials and implements no backend calls. Android backup/data transfer is excluded and the activity uses `FLAG_SECURE` to protect screenshots/recents. A separate browser render was used for layout inspection; native screenshots are intentionally protected.

## Verification performed

- Production web build/typecheck passed, using isolated pinned mobile dependencies and its own lockfile.
- Eight mobile tests passed: actual ECDSA proof/domain/key validation; invalid DER; cancel/unavailable/invalid proof; late callbacks and duplicate unlock; content clearing/new chat; input bounds/snapshot isolation; software/substituted keys; browser fallback denial.
- Five JVM/native tests passed: challenge domain/input validation and both legacy/Keystore2 auth-per-use representations with negative time-window/unknown cases. Native plugin compiled against the installed SDK.
- App assemble/unit/lint build passed. Lint: **0 errors,15 warnings**, relating to generated icon/resources and template dependency/configuration choices; no error suppression was added.
- APK signature and package/permission metadata independently verified.
- A real Chromium412×915 mobile viewport rendered with no horizontal overflow; clicking unlock in the browser remained locked with the expected hardware-required error. Desktop UI tools failed at kernel initialization, so the render used an isolated headless browser profile with no user cookies.
- Existing root simulation: **372 tests passed**, unchanged. Root backend package/dependencies were not changed; the prior796 production-backend checkpoint is unchanged, not rerun for this isolated addition.

Build tooling initially hit the upstream Windows immutable-cache move failure in Gradle8.14.3. The maintainer identifies9.1.0 as the fixed release; the wrapper is pinned to9.1.0 with its official SHA-256. JDK21 and SDK36 were already installed. No antivirus/security exclusion or cache-output fabrication was used. [Upstream fix confirmation](https://github.com/gradle/gradle/issues/38921).

## Build again

From `apps/mobile`:

```powershell
npm ci --ignore-scripts
npm test
npm run build
npm run android:build
```

The Windows build helper uses the existing Android Studio JDK and Android SDK, disables SDK auto-download, keeps Gradle state inside `.local/mobile/gradle`, protects the local debug-signing directory, synchronizes built assets and runs app assemble/unit/lint checks. Generated SDK paths, caches, signing material, web assets and APKs are excluded from git. A build output is not automatically installed or connected to any tenant.

## Physical acceptance still required

1. On the Pixel6Pro/Android17 with a strong fingerprint enrolled, select **Test fingerprint unlock**. Confirm a real Android biometric prompt and an empty test chat after successful fingerprint verification.
2. Cancel the prompt; confirm no chat opens. Confirm there is no device-PIN fallback in this prompt.
3. Send local test messages, background the app, then return and unlock: no old messages should appear. Test backgrounding while the biometric prompt is open to reject a late result.
4. Verify failed/locked-out biometrics and changed enrollment fail closed. The test build does not replace an invalidated key silently; recovery/reset belongs to the forthcoming verified enrollment flow. PF fallback is not connected yet.
5. Repeat after force-stop/reopen and OS restart. Verify the screen is protected in app switcher/screenshots. Record only outcomes, never fingerprint information or private material.

The owner has now confirmed fingerprint unlock and the message/background/reopen fresh-chat exercise. Remaining physical negative/recovery cases above are still pending.

Backend enrollment, browser handoff, native live-purpose signing and request signing have [local protocol verification](../../docs/mobile-signin-handoff.md). The [native browser lifecycle and separate live-preview UI](../../docs/mobile-browser-lifecycle.md) are now composed and build successfully, with 827 backend, 32 mobile and 12 native tests passing. SDK bridge logging and WebView debugging are disabled in the verified candidate.

The default build remains `device-test`. Explicit `VITE_MOBILE_MODE=live` selects the live-preview UI and pins its CSP to the existing agent API host; unknown modes fail instead of falling back. The [auto/manual consent and revoke controls](../../docs/mobile-consent-controls.md) now use the signed resource endpoints, with a remembered native preference. Latest checks:835 backend,39 mobile,12 native tests; web/native builds pass. The preview server/runtime is not deployed or connected to real delegated Copilot access. No new APK was installed. The installed immutable v4 remains the local device test, and historical PoC allowances remain spent.

## V6 sign-in diagnostics update

Version 0.2.1 / versionCode 6 is the live diagnostic update. The expandable Sign-in diagnostics panel holds only the latest attempt's fixed steps, timings, error codes and HTTP failure status in memory. Tap Sign in, expand the panel and copy the report; if clipboard access is denied, select its read-only text manually. No report is uploaded automatically. See ../../docs/mobile-signin-diagnostics.md for verification and the exact privacy boundary. Sign-in itself remains under investigation.

## V7 browser request fix

Version 0.2.2 / versionCode 7 retains diagnostics and binds the fetch dependency to the browser global receiver. This corrects a real-browser TypeError before the backend request could be transmitted. The receiver regression, 46 mobile tests, backend integration and native build checks pass. Install over v6 and repeat sign-in once; actual phone completion remains a verification step.

## V8 browser selection update

Version 0.2.3 / versionCode 8 adds HTTPS browser discovery and a browser-only chooser when no eligible default resolves, plus fixed granular native launch error codes. The PF URL and one-use transaction policies remain. 47 mobile and 16 native tests pass, as do assembly/lint and exact download tests. Install over v7, tap Sign in and choose a browser if prompted. If it fails, copy Sign-in diagnostics v8. On-phone acceptance is still pending.

## V9 resource request clock repair

Version 0.2.4 / versionCode 9 uses serverTime from successful device completion to sign foreground requests against the server clock, advancing with monotonic elapsed time. This repairs an observed resource-access 401 with about six seconds of relative clock skew while retaining zero server tolerance, replay and expiry checks. Install the same-certificate update before using the changed completion protocol. Existing enrollment remains on the server; try biometric unlock. If entry fails, start a new sign-in and copy the v9 report. Chat/document acceptance is still pending.
