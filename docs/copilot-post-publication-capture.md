# Post-publication provider capture — 31 October 2026

The operator reported successful publication at **8:27 AM on 31 October 2026**, after correcting the refresh endpoint, then explicitly approved one new test. Publication was operator-observed; the client does not independently attest the deployed configuration/version. The reported configuration uses Generic OAuth 2, PF A client `copilot-studio-generic-oauth`, scope `copilot.login` and PKCE S256. Copilot-to-PF PKCE remains unverified; the local provider-token acquisition is separate from Microsoft's authorization-code redemption.

## Actual result

| Field | Value |
|---|---|
| Capture ID | `f8515c8a-3f7a-4b7c-b54c-f9803bb8d79f` |
| POST invocation | `2026-10-30T21:30:44.175Z` / 31 October 08:30:44.175 AEDT |
| Response received | `2026-10-30T21:30:46.622Z` |
| Microsoft request ID | `a8f3656a85111fe5fdcc8df8759c7bbd` |
| Response | **HTTP/1.1 400 Bad Request** |
| Exact body | `"Token is expired"` |
| Content type / length | `application/json; charset=utf-8` / 18 |
| Parsed OAuth card to cURL invocation | **4893.039 ms** |
| PF A token remaining at invocation | 169 seconds rounded down |
| Challenge remaining at invocation | 53 seconds against host clock; 51 against response Date |

The fresh provider token was independently signature/binding-verified for `https://pf-a.copilot.darkedges.com`, audience `api://copilot-login`, scope `copilot.login`, expiry `2026-10-30T21:33:34.000Z`. Read-only inspection of its retained original confirmed `nbf=2026-10-30T21:30:34.000Z`, already 10.175 seconds before invocation, with 169.825 seconds until `exp`. The measured delay includes pre-send Vault retention and does not measure packet-level delivery. The returned expiry category still does not identify which Microsoft object expired. **Copilot acceptance and delegated tool handoff remain UNVERIFIED.**

The new `--run-published-1` harness mode has a separate one-use `published-provider-vault-capture` ledger. Tests first demonstrate consumed-allowance rejection and immutable prior history. This run reserved one new Direct Line conversation and sent exactly one token POST, using the exact fresh OAuth-card URL without reconstruction or retry. All seven historical/current reservations are now consumed; this command cannot authorize another run.

## Retention and cleanup

Original application URL, headers/body with the PF A token, and raw response are retained in encrypted Vault at `federated-copilot-tool-secrets/provider-debug/f8515c8a-3f7a-4b7c-b54c-f9803bb8d79f`, version 2. Automatically generated request headers were not captured. Presence-only inspection independently confirmed the token, all four signed query values and raw response. Retention is until operator deletion, not the one-day service-journal policy. Plaintext evidence remains redacted.

Explicit local operator retrieval, without printing values:

```powershell
npm run copilot:retained-capture -- --copy-private f8515c8a-3f7a-4b7c-b54c-f9803bb8d79f
```

The assistant has not copied this new capture to the clipboard or submitted it externally. Independent cleanup confirmed test grants revoked, PF A login enabled/PF B tool client disabled, temporary signing/writer leases and writer policy retired, credential files removed, and all previous budget hashes unchanged. The existing private controller was preserved.

Before the run, all **294 baseline tests** and six synthetic live Vault retention checks passed, with no Microsoft requests in those checks. Local tool verification and post-revocation denials also passed during the run. No licensing, tenant setting, Graph permission or public route was changed by the test.
