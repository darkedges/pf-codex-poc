# Mobile consent controls

Status: **locally integrated and built; live phone/runtime acceptance UNVERIFIED**. The installed v4 device test remains unchanged. No public service, PF/Entra/Vault setting, real permission grant, Microsoft request or billing change occurred.

## User flow

The live-preview welcome screen now has **Automatically approve configured document and chat access**, enabled by default. The preference is stored separately in app-private native preferences, excluded from backup/transfer. Local sign-in recovery resets the live enrollment reference/key without resetting this choice. The preference is convenience state, not an identity, grant, scope or permission to select another site.

After initial sign-in or fingerprint unlock, the controller loads the native choice, fetches fixed server terms, and sends a signed permission-status request. It verifies the same terms hash and absolute enrollment expiry throughout. Existing valid approval opens a fresh empty chat. Missing approval is submitted automatically only when the stored choice is enabled. With the choice disabled, the app displays the server's terms and waits for **Approve access**; **Not now** locks without creating approval. Turning auto-approval off does not revoke earlier permission, which the UI states explicitly.

Unknown native preferences, failed writes, mismatched terms/expiry or failed approval never default to success. Preference writes are serialized so rapid changes persist in order; session entry waits for pending writes. A failed last write blocks automatic entry until the choice is successfully saved. Initial metadata reads cannot overwrite a newer user choice.

The chat screen has separate **Lock** and **Revoke access** controls. Revocation cancels pending client requests, sends a new signed revoke request, confirms the server's revoked status, discards the foreground signing key and clears messages. The app does not claim success from local deletion alone. A revoked enrollment reaches the blocked-access screen on subsequent unlock and cannot restore access through auto or manual approval. **Sign in again** starts the new enrollment/consent flow; old grants remain revoked.

## Release and cancellation checks

Chat cannot open before approval status is established. Backgrounding during browser sign-in still preserves only its bounded native pending secret; backgrounding during consent/approval clears foreground authority. Generation checks reject late approval, status, chat and pending-return results. A saved preference does not reopen a session.

The API revalidates resource consent after executor completion as well as before execution. If revocation happens while an answer is being prepared, the answer is not released even when the client did not abort. This supplements the executor's independent current-policy/identity checks; it does not prove Microsoft-side session/cache revocation. That still needs live integration verification.

## Verification

- 835 backend production tests pass. The actual controller, WebCrypto signer, transport, handler, JOSE verifier and temporary policy/device stores now exercise both auto and manual consent, empty-chat resume, real policy revocation and rejection of a previously signed request. Browser/hardware and final answer execution remain explicit fixtures, not live Microsoft evidence.
- 39 mobile tests pass, including remembered opt-out, ordered saves, manual approval, revoked-state blocking, unknown preference/terms failure and background cancellation during automatic approval.
- Live-preview Android assemble, 12 native unit tests and lint pass with zero errors/15 existing warnings. Native preference persistence itself remains unverified on the phone. SDK logging and WebView debugging remain disabled; no provider token, signing key, handoff or conversation is stored in preferences.
- Web typecheck/build passes with the existing bundle-size warning. A 412×915 isolated Chromium render shows the default checkbox and no horizontal overflow, and browser sign-in remains denied by native guards. The desktop computer-use helper failed kernel-assets initialization; this check used an isolated headless browser profile, never the signed-in browser or phone. The temporary loopback preview was stopped.
- An existing 100-ms signer fixture timed out once under concurrent build/test load. Its isolated test and the complete suite passed on recheck without changing test or production timeouts. Existing simulation checkpoint remains 372 passing; no simulation interface changed.

The new APK is an intermediate live-preview build, not a promoted delivery artifact; it retains the existing debug package/version and was not installed. Next is protected runtime composition: approved resource-consent storage and audit, actor/authority custody, real PF A/B exchange, current broker policy, multi-turn Copilot and approved-site retrieval, followed by the concrete activation review. The UI does not enable these services or expand spent test allowances merely by building successfully.
