# Verified interactive Copilot delegated diagnostic

**Passed on 1 November 2026 at approximately 07:18 AEDT** (31 October 2026,20:18 UTC). This verifies the interactive PoC in the actual tenant; it is not production approval.

Run: `be3928f1-86f5-460c-9a55-c200df59b079`.

## What passed

One approved fresh Direct Line conversation received its OAuth card. The adapter posted the configured PF A user token to that card's exact secure URL; Microsoft returned **HTTP200** and the published signed-in diagnostic succeeded. The same token was registered privately with independently validated human OIDC, broker and registered-agent evidence, and delivered by the published connector through **PfUserAccessToken**.

The fixed diagnostic reached both connector stage markers and returned **Delegated tool access verified.** The relay recorded exactly one successful origin request with both credential headers present. Actual PF A/B exchanges and the private Docker tool completed; the independent policy database contained exactly two permitted tool decisions preserving the expected original human, registered acting agent and actor issuer, organisation, grant, interactive mode, resource and `api://copilot-tool` audience. The relay's one-use exact provider-token binding and retained-proof checks were required; no prompt-supplied authority or mock fallback was used.

| Evidence | Result |
|---|---|
| New Direct Line conversations | 1 |
| Secure token POSTs | 1, HTTP200 |
| Runtime signed in | True |
| Connector started / returned | Both observed |
| Fixed delegated diagnostic result | Verified |
| Independent policy identity continuity | Verified |
| Successful relay origin requests | Exactly1 |
| Platform error reported | No |
| Cleanup | Verified |
| Graph requests | 0 |
| Local raw credential retention | None |

Cleanup revoked the owned test grant, restored the PF B tool-exchange client disabled, preserved the enabled PF A login client, pre-existing grant states/versions and all historical allowance files. Tool and relay services remained ready. The new allowance is consumed; no automatic retry was run or authorized.

## Repair that enabled the result

The earlier connector-specific requests omitted the provider header. An explicit passthrough policy did not help and was removed. Changing the provider parameter from X-PF-User-Access-Token to **PfUserAccessToken**, updating the fixed system-variable mapping, and explicitly selecting that transport at the managed relay restored delivery. Synthetic connector probes first confirmed header presence/key acceptance with expected403; this real signed-in test subsequently verified exact token continuity and actual tool execution. The original header remains the default for isolated local adapters. Mixed or alternate headers are rejected in the managed profile; authority checks were not relaxed. See [transport details](copilot-provider-header-transport.md).

## Evidence and scope

- Runner receipt: `.local/tool-vault/microsoft-tool-be3928f1-86f5-460c-9a55-c200df59b079/verification.json`.
- Separate read-only confirmation of policy, grant/client cleanup and exactly one origin success: `independent-confirmation.json` in the same directory.
- Approval, publication/action hash and preserved predecessor budget hashes: `.local/copilot/relay-microsoft-review/simple-header-1-approval.json`, `publication-simple-header-1-confirmation.json`, and `simple-header-1-preparation.json`.
- Consumed ledger: `.local/copilot/live-sso-tool-diagnostic-simple-header-1-budget.json`.

This result covers one synthetic human/agent consent and one fixed interactive diagnostic. Autonomous Copilot provider SSO, live Microsoft expiry/revocation behavior and production deployment/workload isolation remain **UNVERIFIED**. Graph/SharePoint remain **NOT CONNECTED**. The user's explicit PoC exception for Microsoft token-bearing tool traces remains in force; successful execution does not establish credential redaction or production suitability.
