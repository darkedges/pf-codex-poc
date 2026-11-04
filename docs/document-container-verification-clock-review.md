# Review: clock-safe document container verification

Status: PREPARED, NOT RUN. This permits one fresh local test consent; all older budgets and revoked grants remain spent/unchanged. No Microsoft request or document read.

## Verified progress and remaining failure

The corrected run37813bc0-0d26-4446-92cc-9f3032fa5517 completed actual authenticated policy health, one fresh PF login/document consent, and a real Vault-to-PF A-to-PF B chain accepted by the independently authenticated policy consumer. It used3 PF token POSTs. The next strict identity checker stopped before replay/expiry/revocation checks. The raw token and exception category were not retained, so the exact original exception cannot be established from that trace.

Independent read-only checks confirm matching public PF pins/issuer/audience, successful public-key import, and PF A roughly2 seconds/PF B roughly3 seconds ahead of the host at observation time. A failing-first local test reproduces the extra checker rejecting a correctly signed, approved proof whose nbf is within the production verifier's five-second tolerance. The new verified-token activation helper waits for actual iat/nbf before release/use, bounded by that existing five-second ceiling and the request deadline. It never relaxes not-before or expiry, and rejects larger future times, expiry and cancellation. The issuer and reader recheck current authority afterwards; no Graph credential or network read can precede activation. The live failure is consistent with this measured skew, but its original missing exception is not invented as fact.

Corrected unit token fixtures also use descending absolute expiries instead of equal lifetimes generated across possible clock-second boundaries. Fixed-category stage/error/claim diagnostics now avoid another unclassified strict-check failure without logging credentials. These local fixes do not themselves prove live expiry/revocation.

The previous grant is independently confirmed revoked, both document clients disabled, loopback9453 stopped and owned locks absent. Preserve the original40-file initial packet and45-file corrected packet, approvals, budgets, results and cleanup receipts under verification-initial-spent and verification-corrected-spent. Never reset verification-budget.json or verification-fresh-budget.json. The new file is verification-clock-budget.json.

## Exact fresh test

Run the same document policy service on127.0.0.1:9453 for at most240 seconds, using existing protected localhost TLS key/certificate/CA, document-only handle on the authoritative policy.sqlite and approved OIDC aliases. No database copy/seeding, registry/admin mutation or diagnostic policy change. Use only the three enrolled document workload public identities and the document Transit signer with dedicated cert-auth/one-use leases.

Temporarily enable only the two already staged document-gateway clients after disabled-state readback and durable intent. Use one fresh actual PAR/PKCE/OIDC login for the existing synthetic user with the stored lab password, then one new five-minute interactive document consent. This is an operator-approved synthetic-account test, not a new end user's manual-consent claim. It does not restore the revoked consent.

Read the two document PF client keys and three policy caller keys only through their existing readers. Use only agentKeyPem from the existing portal-executor record via its existing reader, with no copy/reuse of other fields. PF administrator credentials only enable/disable these two exact clients and are not delivered to the policy service.

At most two positive actual Vault/PF chains retain the descending actor240/authority180/PF A120/PF B60-second limits under300-second consent. All signature/issuer/audience/identity/current-policy and non-increasing expiry checks remain mandatory; the new wait ensures the proof is actually active before release. Authority verification uses the previously pinned closed public-registry transport; no assertion is simulated or unknown key accepted. Hosted authority-JWKS discovery is not verified by this test.

Verify actual client-assertion replay rejection, expiry of the initial actual PF B token beyond five-second tolerance while consent remains active, one fresh replacement, then revocation denying the still-unexpired replacement and any new authority issuance before another PF POST. This tests actual PF-issued expiry at the policy consumer, not a separate expired-subject request to PF.

Ceiling: one fresh login, one fresh consent, two positive chains,12 PF token POST reservations including redemption/negative replay,240 seconds. Reserve before every POST; failure consumes the allowance and no automatic retry/reset/renewal. The final negative issuance request goes only to the authority endpoint, preventing a third PF chain even if it unexpectedly succeeds.

Always reconcile/revoke only the single owned document consent by verified-login hash if needed, disable/read back only the tracked clients and stop the host. Cleanup failure preserves evidence for recovery. Save only fixed status/counts/stages/codes and safe hashes; no token, password, signed URL or raw Vault data. Zero Entra/Graph/Direct Line/Copilot/secure-token-post request or document download. No public route, publication, billing/trial change or chat activation.

Command: node --experimental-strip-types scripts/pf/verify-document-live.ts --run with the existing PF CA in NODE_EXTRA_CA_CERTS. Source/public-config/history manifest plus explicit fresh approval are required before credential access. The earlier spent grant cannot be reused, so another consent/run needs explicit approval.

The test now accepts only explicit403/forbidden policy denials for expiry/revocation, requires the PF replay response to be invalid_client with400/401, and rechecks authenticated policy health before declaring success. Outages or authentication failures cannot masquerade as successful negative checks. Local activation/consumer tests prove no Graph credential or document request occurs before actual validity. Full production758 tests pass; simulation372 is the unchanged last passing baseline. No new live grant, token or Microsoft request was made while preparing this correction.

Approve with **Approve clock-safe document container verification**.
