# Review: first browser integration at agent.copilot.darkedges.com

Status: **PREPARED, NOT APPROVED OR APPLIED**. The staged local service is already verified. This packet requests the new public exposure and a fresh, independently bounded live allowance. Earlier Vault enrollment approvals do not authorize these actions. Keep this document and its hash manifest immutable after approval; record subsequent outcomes separately.

## Exact approved scope if accepted

1. Create or verify one proxied Cloudflare CNAME: `agent.copilot.darkedges.com` → `a979d27b-f2cd-45cf-aada-b44c850e3a0e.cfargotunnel.com`, in existing `darkedges.com`. Refuse conflicts; never overwrite another record. Use only the configured Cloudflare credential. It previously lacked DNS permission; if still denied, the owner must create this exact record manually. No alternate credential search, wildcard DNS change or certificate purchase.
2. Add one host/path route to the existing locally managed `federated-copilot` tunnel, preserving the existing PF A/B and relay rules byte-for-byte and the final deny-all. Route only `/`, `/login`, `/callback`, `/approve`, `/provider-login`, `/provider-callback`, `/check`, `/revoke`, `/logout` to `https://127.0.0.1:9466`; deny all other paths for this host. Require HTTP Host `agent.copilot.darkedges.com`, TLS name `localhost`, the pinned portal-origin certificate and TLS verification. No public listener, policy/Vault/admin/handoff/status/metrics route is added. Restart only the owned cloudflared2026.10.5 connector; a failed readiness check may require one rollback restart. PF/relay routes can be briefly interrupted during these restarts.
3. Add exactly these callbacks to the existing local PF A clients, preserving all original redirects and other settings:

| Client | Additive callback |
| --- | --- |
| `copilot-consent-portal` | `https://agent.copilot.darkedges.com/callback` |
| `copilot-studio-generic-oauth` | `https://agent.copilot.darkedges.com/provider-callback` |

No issuer, audience, signing key, client ID, scope, PKCE/PAR requirement, lifetime, existing callback or client authentication method is changed. The Generic OAuth encrypted secret is carried through the existing client object in memory; no plaintext secret is logged, persisted in the packet or changed. Settings fingerprints exclude the server-managed modification date and re-encrypted secret representation, while retaining creation date and security configuration. Read-back cannot alone prove plaintext secret equality; actual configured-provider sign-in remains part of the live verification. The encrypted-secret field is documented in the [Ping Identity client schema](https://registry.terraform.io/providers/pingidentity/pingfederate/latest/docs/resources/oauth_client).
4. Start the reviewed live portal under the selected Windows account using the existing Vault readers, certificate, independent agent/PF/policy checks and separate web worker. All current reviewed files, public trust, current channel binding and exact tunnel configuration must match the manifest. There is no browser-accessible approval/reset API. The first activation intent starts a fixed **one-hour maximum** window, also bounded by the existing service/signing lease. Restart cannot extend it.
5. Temporarily enable only the dedicated PF B `copilot-sso-exchange` tool client under a persistent, exclusive ownership lease. It must initially be disabled and match its reviewed configuration. Write ownership before the enable request. Verify and restore disabled state after the trial finishes, on shutdown/startup failure or during explicit dead-process recovery. Never write the human login client during this lease. Refuse drift/foreign ownership, retain recovery state if restore cannot be confirmed, and never reset the trial. Forced process termination may require explicit recovery; no automatic privileged restart/renewal is installed.

## One live allowance for the whole deployment

| Item | Maximum |
| --- | --- |
| New human consent/grant approval attempt | 1 |
| Direct Line conversations | 1 |
| Fresh OAuth-card token POST | 1 |
| Successful delegated tool diagnostic | 1 |
| Activation window | 1 hour from first intent, or dependency lease expiry if earlier |

One allowance covers every browser, process and restart together. Reserve it before requesting human consent; a failed or lost approval response can consume the attempt before any Microsoft request. Increment counters before the corresponding remote call. No automatic retry or fresh conversation after failure, and no rearming a spent row. Preserve all11 consumed historical budget files. This is not a new dollar spending limit or billing policy.

The user performs PF sign-in, reviews interactive permission, completes the configured-provider sign-in for the same account, then clicks the single fixed access check. No free-text Copilot chat, autonomous execution, Graph/SharePoint, external Entra identity provisioning, tenant-wide grant, new subscription/billing policy or support-plan purchase is authorized. Do not post credentials in chat.

Use a new Direct Line conversation and that conversation's OAuth card. Extract its exact `content.tokenPostResource.sasUrl`; do not reconstruct/reuse it. POST only `{"token":"<same-human configured PF A provider access token>"}` to the pinned Microsoft origin/path. The user token, SAS values, channel credentials, raw activities and exception bodies must not enter local logs, receipts, HTML/browser storage or fixtures.

Accept success only with fresh runtime signed-in status, both fixed connector stages, the fixed positive diagnostic, exactly two current identity-preserving tool-policy permits for the owned grant, and final online authorization. Preserve original human, registered actor/issuer, organisation, grant, interactive mode, resource and audience throughout. Close/revoke the owned grant independently on completion/failure, lease expiry or worker loss; never revoke unrelated grants or refresh expired human proof.

## Verification and containment

Before enabling sign-in, verify the reviewed staged page publicly over HTTPS with no-store and denied unapproved paths. Confirm both callback read-backs, ready Vault/PF/policy/relay, selected certificate pin, published tool mapping `PfUserAccessToken=System.User.AccessToken` with fixed body, and connected existing connector credential. Do not republish/change the agent as part of this plan. Source/publication receipts must match; an unexpected tenant change blocks activation.

The public-stage proof and fresh read-only tenant/connection check must both follow approval and be less than15 minutes old before live startup. These administrative GETs are Microsoft requests, but they are not Direct Line conversations, token POSTs or tool tests. Retain only fixed connection/publication confirmation metadata. Diagnostic telemetry is limited to token-post HTTP status and fixed verified/unavailable outcomes, capped at16 entries with one-day filtering; no secure URL, token, body, user identifier or raw exception is retained there.

The known Microsoft credential-trace protection gap remains **UNVERIFIED** under the user's existing explicit PoC exception. Provider token continuity is required; the approved connector input can be present in Microsoft tool traces. Same-Windows-account process separation is not production OS isolation. This plan does not promote either limitation to production acceptance.

Keep current one-day audit settings and bounded fixed metadata. Delete recovered portal intent metadata after a day during active/startup maintenance, while retaining the non-secret spent-trial tombstone. There is no new offline deletion scheduler or autorenewal. Live nonempty-grant recovery and the public browser/provider callback flow remain **UNVERIFIED** until this separately approved trial; local/controlled-transport tests do not establish tenant acceptance.

## Apply, recovery and rollback

The non-secret packet is `.local/tool-vault/portal-activation-review/`: manifest with exact source/public-trust hashes, proposed tunnel, original tunnel backup, two callback fingerprints/diffs and a disabled tool-client baseline. Preparation reads existing settings and validates candidate ingress without applying anything. A separate explicit approval receipt must bind the exact manifest/review. The already-running stage must be stopped through its owner before live startup; live mode refuses absent approval, drift or an existing/spent trial.

After approval: create/confirm DNS; apply the reviewed ingress; run `verify-portal-public-stage.mjs --verify` and `portal-tenant-readback.mjs --verify`; apply/read back the exact callbacks; stop the owned staged portal; launch `start-portal-hidden.ps1 -Live`. The service seeds its new journal row only once and manages the dedicated PF tool-client lease. The owner then completes browser sign-in and the check. While the deployment remains up, completed/spent state disables new sign-ins and operations, and the PF tool client is restored disabled. The service stops at its fixed expiry; no further test is inferred.

Inspect protected status/recovery receipts without raw credentials. If the controller/worker dies, use the owned `--recover` path only after both PIDs are absent; it restores the dedicated PF client and recovers only journal-owned grants. PID reuse, configuration drift or unresolved remote consent keeps the lock/lease for operator review. Do not remove locks or alter counters manually.

Rollback uses the approved immutable source tunnel and callback removal only if current settings still match the corresponding reviewed after-state. The dedicated PF tool client must be disabled and owned grants revoked. Keep the DNS record pointed at the tunnel's deny-all if DNS deletion cannot be safely verified; never delete an unrelated record. Rollback permissions decrease exposure and remain usable after the test window, subject to identity/hash checks. Record all outcomes independently; an uncertain POST or DNS creation is reconciled read-only, not retried blindly.
