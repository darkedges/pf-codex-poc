# Vault-retained provider capture

The user authorized one additional interactive test after retention verification. It ran once on 2026-10-31 Australia/Sydney, using one conversation and one token POST with no retry. All six historical and current test reservations are now consumed. Copilot acceptance remains **UNVERIFIED**.

## Result

- Capture: `cef2aa7a-3c83-4cca-94fc-07c47b096c02`
- POST invocation: `2026-10-30T20:55:38.379Z` (31 October 07:55:38.379 AEDT).
- Measured parsed-card-to-cURL invocation: **558.440 ms**, including pre-send Vault retention. This is not packet-level timing.
- Verified configured-provider user token: issuer `https://pf-a.copilot.darkedges.com`, audience `api://copilot-login`, scope `copilot.login`, expiry `2026-10-30T20:58:29.000Z`.
- Response: **HTTP/1.1 400 Bad Request**, exact JSON-string body `"Token is expired"`.
- Microsoft request ID: `a8116811560181d308fe82e201805ef7`.

The response does not identify which Microsoft object expired. No support case, tenant setting, public route or Graph access was changed.

## Private originals

Vault KV record `federated-copilot-tool-secrets/provider-debug/cef2aa7a-3c83-4cca-94fc-07c47b096c02`, version 2, contains the original application request URL (including expiry, id, state and hmac), request headers/body with the actual PF A token, and complete HTTP response returned by cURL. Automatically generated request headers were not captured.

The record remains in the existing encrypted Vault until operator deletion. **Automatic deletion is not configured**; the separate one-day tool-service journal policy does not apply to this debug secret. Plaintext artifacts contain only redacted values and a Vault reference.

Run from the project directory to check presence without printing originals:

```powershell
npm run copilot:retained-capture -- --inspect cef2aa7a-3c83-4cca-94fc-07c47b096c02
```

To copy the original private request and response to the local Windows clipboard:

```powershell
npm run copilot:retained-capture -- --copy-private cef2aa7a-3c83-4cca-94fc-07c47b096c02
```

This explicit operator action uses process stdin and prints no raw values or plaintext file. Clipboard content contains credentials and the original signed URL. It is for inspection; copying does not authorize replay or external submission. The assistant has not copied it to the clipboard.

## Verification and cleanup

Request retention must succeed before transmission; Vault failure blocks the POST with no plaintext fallback. A five-minute, two-use writer can only create/update the exact capture path, without read, list, signing or administrative access. CAS version 1 preserves the request before sending; version 2 adds the original response. Vault auditing must be enabled without raw/non-HMAC credential fields. The ordinary tool reader cannot read debug records.

Six synthetic live Vault checks passed before the Microsoft run, with no Microsoft calls. Offline tests cover CAS ordering, unavailable storage, path/header constraints, consumed allowances and exact private packet reconstruction. After the actual run, independent checks confirmed version 2 with token, all signed query values and raw response present. The test grant was revoked, temporary writer/signing credentials and policy retired, temporary files removed, PF A login restored enabled and PF B tool client disabled. Historical allowance ledgers were unchanged and the existing private controller was preserved.

Final verification: all **293 baseline tests pass**, including the five retention/allowance/private-reconstruction tests. Windows ACL access is required for the existing audit-filesystem checks.
