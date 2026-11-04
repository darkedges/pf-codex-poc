# Single visible login and default-on consent — PoC review

Status: implemented and tested locally; **live single-login behavior is UNVERIFIED**. The earlier [document answer](document-chat-live-success.md) remains verified under its original three-sign-in flow. Its complete source packet, successful receipt, journals and owned stop are preserved under `.local/tool-vault/document-chat/successful-document-chat`. Its allowance remains spent. The answer-only worker was stopped and cleanup confirmed before source changes.

## User experience

The sign-in page now shows **Automatically approve chat and sample-document access**, checked by default as requested. Before submitting, the user sees that signing in with this selected approves one question and one read of `federated-copilot-poc.txt`, for the fixed research agent and approved resource. Chat permission lasts at most one hour, document permission five minutes, and both are revoked after the attempt. The existing Microsoft trace notice remains visible.

Submitting the sign-in form records the explicit boolean once in the server's durable session journal before login starts. The choice cannot be changed after login, supplied by a GET, duplicated, replayed, or used to supply scopes, identities, grants or another resource. No new journal schema or migration is needed. The secret-holding parent requires a recorded choice before granting either permission. The user may clear the checkbox to retain the two manual approval screens.

With the checkbox selected, validated OAuth callbacks advance through setup and the two separate fixed approvals automatically. They never submit the question or perform a document read. After setup the user still types and submits the question. A changed human, stale proof, nonce/state mismatch, failed policy check or uncertain consent response stops the flow; known owned consent is revoked on an automatic setup failure and unresolved ownership remains fail-closed for recovery. No automatic retry or fallback.

## One login does not merge token trust

The first OIDC request still forces fresh authentication with `prompt=login,max_age=0`. Only after independently verifying its returned ID token may this isolated chat runtime request the second OIDC proof using `max_age=300` and no forced login prompt. The unchanged verifier still requires fresh `auth_time`, signature/issuer/audience/nonce, and a new token hash for document consent. The Generic OAuth user token remains separate and independently bound to the same human. Existing OIDC clients default to forced authentication unless they explicitly opt into this reuse mode.

The target is **one visible credential entry**, followed by automatic redirects that reuse a short PF browser session. There are still two independent OIDC code exchanges and a provider code exchange. No consent database uniqueness rule, identity check, grant separation, short-lived issuance, current-policy check or revocation rule is relaxed.

## Exact additional PF changes requested

These changes are temporary and owned, in addition to the four exchange-client flag operations in the [original bounded review](document-chat-live-review.md):

| PF A object | Reviewed prior value | Temporary value |
|---|---|---|
| `consentHTMLForm`: Session State | `None` | `Per Adapter` |
| Same adapter: Session Timeout | `60` minutes | `5` minutes |
| Same adapter: Session Max Timeout | `480` minutes | `5` minutes |
| `copilot-consent-portal`: bypassApprovalPage | `false` | `true` |
| `copilot-studio-generic-oauth`: bypassApprovalPage | `false` | `true` |

Only the two identity clients' PF approval pages are bypassed; their scopes remain exactly `openid` and `copilot.login`. Delegated chat/document consent remains in the portal, automatically applied only under the disclosed checkbox choice. Clearing it restores portal review screens even while those identity-only PF pages are bypassed. No token-exchange approval, Graph permission, client key, redirect, scope, authority entitlement or global session setting changes.

Ping documents `Per Adapter` as session reuse within that adapter instance, with explicit idle and maximum session lifetimes. This plan sets both to five minutes and does not enable globally shared sessions. [Ping HTML Form Adapter documentation](https://docs.pingidentity.com/pingfederate/12.2/administrators_reference_guide/pf_config_html_form_adapt_instance.html).

The SSO lease preflights all three objects, records only exact hashes and narrow prior/target setting values, then performs guarded readback. It excludes only server write timestamps and the provider's randomized primary encrypted-secret bytes from relevant fingerprints; all other policy fields stay pinned. It refuses foreign object drift, changed ownership or tampered restoration instructions. It does not store PF ciphertext or new credentials. Normal completion/stop restores all five original settings as well as the exchange-client flags. A failed cleanup retains evidence/locks and blocks restart. Existing browser adapter cookies can remain until their five-minute expiry; local sign-out is not a PF single logout. Each new portal run still forces fresh initial authentication.

## Bounded live verification requested

Approve **one new manually operated session in one fixed 45-minute window**, with default-on consent and one synthetic-sample question. First independently verify source/public hashes, existing callbacks, original session settings, private readiness and public page. The user should enter credentials once, observe automatic setup, then submit the known sample question. Record the observed number of credential prompts; do not infer it from code or protocol counts. The unchecked manual path is locally tested, not an additional live allowance.

All original request/data limits remain: one 201-byte sample read, one Entra app token, two exact Graph GETs, one constrained SharePoint download, one Direct Line token/conversation, one fresh-card provider-token POST, two activity POSTs, seven expected PF token POSTs with a ceiling of twelve, fifty Direct Line GETs maximum and one question. No new routes, public ports, Graph permissions, publication, credential custody or billing policy. Use the existing Vault readers and the same scoped one-hour legacy signing lease/owned loopback hosts. No automatic renewal/restart. Failure consumes the attempt and does not authorize another.

Local verification: **796 production tests and 372 simulation tests pass**. New tests cover default-on and manual flows, pre-login immutable choice/RPC checks, CSRF/duplicate-field and identity substitution, automatic setup cleanup, opt-in session reuse only after verified login, stale authentication rejection, bounded adapter settings, ownership/configuration drift and restoration-instruction tampering. Existing mocks remain isolated; no live PF session setting was changed and no Microsoft request or new grant was issued while preparing this feature.

This PoC still has the previously accepted Microsoft trace exception and shared Windows-account/crash-recovery limits. Broad search, business data, multi-turn/autonomous chat and production consent compliance are not included. Whether the actual PF/Copilot browser flow requires exactly one visible credential prompt remains **UNVERIFIED** until the approved test.

Approval phrase: **Approve single-login document chat deployment**.
