# Review: corrected bounded document container verification

Status: PREPARED, NOT RUN. This is one fresh attempt with the same bounded local purpose. The original allowance remains spent and unchanged.

## Original result and correction

Run5830dc4a-964c-497f-a06b-4e56173e9900 passed authenticated document policy health, then failed before any PF token POST, login redemption or consent creation. Both staged clients were returned disabled and the temporary host stopped. Original counters:0 PF token POSTs,0 consents,0 Microsoft requests; cleanup confirmed. The exact40-file source/public-config packet, approval, budget and result are preserved under .local/tool-vault/document-deployment/verification-initial-spent. Original verification-budget.json is never reset.

Code inspection and a local reproduction identified the browser redirect guard: the wrapper forced redirect:error over LocalBrowser's explicit manual mode, preventing the browser from receiving PF login/resume302 responses. The corrected closed transport preserves manual handling only for local PF A browser requests. LocalBrowser validates every next destination. OAuth token POSTs and all other requests still never auto-follow redirects, and reserve before each token POST. Three regression/negative tests verify manual redirects, token-post no-follow/reservation, rejected origins, exhausted reservation, fixed public-key delivery and deadline denial. A fixed operation/method/status diagnostic now identifies the last network stage without recording URLs, queries, bodies or credentials. This correction is locally verified; the next actual sign-in remains unverified.

## Exact fresh allowance

Start the same document policy host on127.0.0.1:9453 for at most240 seconds, using the existing protected localhost TLS certificate/key and CA. Use the document-only handle on the existing authoritative database with its approved OIDC bindings and five-minute consent. Register only the three newly enrolled document workload public keys in this temporary instance; no seed/copy/registry/admin changes. Authority signatures use the separate document Transit cert-auth signer and one-use leases, never root credentials.

Temporarily enable only document-gateway-1 and document-gateway-2, after independent disabled-state checks and durable enable intent. Use one fresh real PF login for the existing synthetic user through the existing local PAR/PKCE/OIDC client and stored lab password. Create one new five-minute interactive document consent. This is an operator-approved synthetic-account test, not evidence of another end user's manual consent.

Read document client and policy keys only through their existing dedicated Vault readers. Use only agentKeyPem from the existing portal-executor record through its existing reader for independent registered-agent authentication; do not copy it or use that record's other private keys. PF operator credentials are used only to enable/disable the two exact staged clients. The signing authority never receives them.

At most two positive actual Vault/PF A/PF B chains use the same240/180/120/60-second descending actor/authority/PF A/PF B lifetimes within300-second consent. Preserve all signature, identity, audience and no-extension checks. Authority public-key verification uses the exact previously pinned closed trust-registry transport, not a simulated assertion or unknown URL. This does not verify a hosted authority JWKS endpoint.

Verify actual client-assertion replay rejection, then wait beyond the first real PF B token's expiry plus five-second tolerance. Confirm denial at the authenticated policy consumer while its grant is active, issue one fresh replacement, revoke the owned grant, confirm denial of the still-unexpired replacement and of new authority issuance before any further PF POST. This does not claim PF itself rejected an expired incoming subject token.

Hard ceiling remains one fresh login, one fresh consent, two positive chains,12 total PF token POST reservations including redemption/negative replay,240 seconds. Failure spends this fresh allowance; no retry, reset or renewal. The final negative issuance check requests only the authority endpoint, so it cannot produce a third PF chain even if the negative check fails. The new budget is verification-fresh-budget.json. No older budget is modified.

Finally reconcile/revoke only the single owned document consent by verified-login hash if approval response was lost, independently disable only the two tracked clients, and stop the temporary policy host. Unknown/foreign state or cleanup failure retains evidence for recovery. Output only fixed stages, counts and sanitized status. Zero Microsoft/Entra/Graph/Direct Line/Copilot requests, document downloads, public routes, publication/billing changes or new persistent-service availability claims.

Review/command: node --experimental-strip-types scripts/pf/verify-document-live.ts --run, with the existing PF CA in NODE_EXTRA_CA_CERTS. A new source/public-config/history manifest and separate approval at most24 hours old are required before credential access. Existing staging/custody remain unchanged. Browser document chat is not activated by this test.

Independent read-only checks confirm both clients disabled, no loopback9453 listener or owned locks, and zero token/grant counters. The existing OIDC client is enabled with its expected local callback; public discovery advertises the expected local issuer/authorization/PAR endpoints. Full production752 tests pass after the local transport correction; simulation372 last passed with the preceding isolated chat work. None of these checks retried sign-in or created a consent/token. Exact first-run cleanup/history is pinned in the fresh manifest.

Approve with **Approve corrected document container verification**. The earlier single-run allowance is spent despite its zero-token result, so another run needs explicit approval.
