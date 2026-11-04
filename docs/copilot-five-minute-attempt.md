# Five-minute provider-token attempt — 31 October 2026

The user explicitly requested one further test after increasing the dedicated PF A login token lifetime to 300 seconds. The isolated `--run-longer-1` harness validates exactly that issuance lifetime before opening a conversation, uses a separate one-use `longer-provider-vault-capture` reservation, and preserves every prior ledger. The intended limit was one conversation and at most one token POST, with no retry.

## Observed outcome

- Run/capture directory ID: `e147a8f5-6223-40ee-9eb8-637dcaa9b562`.
- Started `2026-10-30T21:44:08.694Z` / 31 October 08:44:08.694 AEDT.
- A new Direct Line conversation opened and returned a fresh OAuth card. The last observed challenge had 56 seconds remaining against the client clock and 57 against the channel response Date.
- The local adapter rejected the provider-verification/binding stage with **`invalid_token`**, before calling the token-post transport.
- **One conversation; zero token POSTs.** This is a local rejection, not another Microsoft HTTP 400 and not a five-minute-token acceptance result.
- Consequently there is no new secure-token-post response/request ID or original request/response Vault capture. No provider credential was sent to the Microsoft token-post endpoint.
- Local policy/tool verification and post-revocation token/channel denials passed.
- Completed cleanup at `2026-10-30T21:44:41.156Z`.

The existing error contract combines provider-verifier failure, structural/date checks and trusted identity binding into the same sanitized `invalid_token` category. Evidence does not identify the exact substep or prove a network timeout. Initial provider acquisition and binding had already passed before opening the conversation.

A subsequent **PF-only** diagnostic acquired a fresh 300-second token and passed independent public-JWKS reverification using a second verifier. It made no Microsoft request, did not change token lifetime/trust, and did not reproduce the failure. This does not establish the cause of the earlier adapter rejection.

## Verification and cleanup

All **296 baseline tests** passed before the attempt, including negative tests proving the new allowance is independent, cannot be replayed and leaves consumed history unchanged. The actual local-container provider test proved exactly 300-second issuance and rejection at the separate delegated-tool boundary. Six synthetic live Vault retention checks passed before egress.

The parent independently confirmed test grants revoked, temporary signing/writer leases and writer policy retired, credential files removed, PF A login enabled/PF B tool client disabled, and previous ledger hashes unchanged. The existing private service was preserved. This conversation allowance is consumed; all eight conversation reservations are now used. No automatic replacement conversation is authorized, even though no token POST occurred. Copilot acceptance remains **UNVERIFIED**.
