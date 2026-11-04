# Portal sign-in form policy correction

Prepared correction to the approved `portal-browser-first-live-v1` deployment. The portal is stopped; its unused durable allowance and original activation expiry are preserved.

The rendered page currently sends `Referrer-Policy: no-referrer`. For a browser HTML form submission, this can produce `Origin: null`; the strict origin check then returns HTTP 403. See [MDN's browser behavior documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy). This is a code-level cause; confirmation of the user's failing hostname/path is pending.

Exactly two runtime source files change: `src/consent/agent-portal.ts` and `src/consent/agent-server.ts`. HTTP 200 form pages use `Referrer-Policy: same-origin`. Redirects, callbacks and error responses retain `no-referrer`. Cross-origin referrer disclosure stays blocked. Exact Origin, CSRF, secure cookie, callback, token, issuer, audience and policy checks stay unchanged. Do not accept missing/null Origin.

Two regression tests failed before the change and now pass. All 20 targeted portal/controller/HTTPS tests pass, including foreign/null-origin rejection. Tests use synthetic credentials and do not invoke Microsoft or real PF login. A real browser retry is still needed to confirm the reported 403 is resolved.

Activation amendment: archive the original manifest, approval and activation-start receipts byte-for-byte; replace only the two source hashes in the active manifest with the prepared candidate's hashes; record explicit amendment approval binding that candidate. Retain the original review hash, scope, original approval timestamp, all limits, trial database, counters, activation start and expiry. Rebind only `activation-start.manifestSha256` to the new approved manifest. Never create a new trial or extend the window. Original expiry remains **2026-11-01T04:54:36.553Z (15:54 AEDT)**; refuse activation if expired or any allowance is already reserved/spent.

Reverify every candidate source/public-trust hash, unchanged tunnel and callbacks, ready dependencies, disabled PF tool client, stopped ownership and untouched trial. Restart staged mode, reverify public HTTPS/no-store/denied paths and fresh tenant connectivity, stop staged mode, then resume live mode under the original expiry and PF lease. No DNS, tunnel, PF callback, credential, Microsoft publication or billing changes are included. No automated human sign-in or additional Microsoft test is authorized. The owner may continue the existing unused single attempt.

The immutable original activation review remains unchanged. This amendment requires approval because its original approved packet explicitly requires exact source hashes and an immutable manifest; the current source correction cannot be silently substituted into that approval.
