# Browser integration at agent.copilot.darkedges.com

Status on 1 November 2026: **managed portal running locally in staged mode, with separate web/controller processes, verified Vault readers and clean restart. Public hosting and live browser integration remain UNVERIFIED.** Sign-in is disabled; no DNS, tunnel ingress, PF client or Microsoft allowance was changed. The earlier interactive Microsoft diagnostic remains verified separately in [the live result](copilot-interactive-tool-success.md).

The first browser milestone is sign-in, consent, one fixed delegated access check, revoke and sign-out. Free-text chat is a later extension, after repeat tool authorization and one-use provider binding have been designed and verified.

## Implemented components

- `src/consent/agent-portal.ts`: server-side session controller and rendered page, with separate human and provider OAuth transactions. Rotates the human session, checks cookie-bound one-use state, requires same-origin CSRF on mutations, uses server-owned grant pointers, pins the expected registered agent and capability against policy preview, and permits interactive execution only. Tokens and grant pointers never enter HTML, forms or browser storage. Failed execution consumes the session attempt, with fixed error text and no automatic retry. Parallel checks are rejected.
- `src/identity/provider-browser.ts`: user-driven authorization-code/S256 client for the configured Generic OAuth provider. No password file or lab browser. Fixed HTTPS endpoints, callback, scope and resource; confidential client secret in the server-to-server body only. Bounded response, deadline, no redirects, JOSE provider-token verification and same-human check. Live hosting must obtain its secret through a limited Vault reader.
- `src/identity/oidc.ts`: optional deployment-pinned `browserAuthorizationEndpoint` lets the browser use PF A's public reverse proxy while PAR, redemption, issuer, audience and JWKS remain on canonical trust configuration. This alias cannot change backend origins or authorization path. The default local configuration is unchanged.

These factories alone start no listener, enroll no credentials, do not invoke the lab runner and have no mock fallback. The managed composition below supplies the real dependencies under a staged-mode guard. Factory tests demonstrate local behavior, not tenant acceptance.

The managed composition described below now hosts those factories locally. Its current mode is deliberately staged; it does not authorize a live trial or enable the sign-in/diagnostic methods.

## Managed local service checkpoint

`scripts/vault/portal-service.mjs` owns a protected single-instance lock, current-user ownership, controller/worker receipts and fixed metadata status. `portal-runtime.ts` loads the verified controller/executor/TLS records with exact certificate roles, composes real OIDC/provider/PF gateways, the signed mTLS handoff, strict Direct Line adapter, independent audit and durable control plane. Startup and periodic readiness check Vault, the authenticated policy service, both local PF JWKS endpoints, dependency instances/heartbeats, lease expiry and public trust/config drift. It imports no operator Vault token or stored human password.

The actual HTTPS listener is a separate `portal-web-worker.ts` process on **127.0.0.1:9466**. Its environment is allowlisted. Initialization passes only public UI configuration and this server's TLS key/certificate. OIDC/client/agent/gateway keys, channel secret, Vault reader certificates, trial journal and Microsoft transport stay in the controller. `portal-rpc.ts` has a closed method/argument/result contract, bounded payload/concurrency/request count, replay-ID checks, fixed errors and drain/disconnect handling. It offers no Vault-path selection, arbitrary transport or trial-approval method. Process separation under the same Windows account is still **not production OS isolation**.

`portal-web-tls` is a new server-only localhost TLS identity, independent of all agent/gateway and relay keys. Its private key is held in Vault; the protected public `portal-origin-cert.pem` pins the certificate. Exact role `copilot-portal-tls-reader` issues one-use120-second read tokens, using the controller's existing reader certificate. Its policy permits only the TLS record; actual tokens were denied access to the executor, controller and relay-caller records. Enrollment/reconciliation retained version1 and the same server certificate. Temporary private-key staging was removed. No public route or listener was created by TLS provisioning.

The controller defaults to **staged mode**. The reviewed live path below requires a separate exact approval, recent public/tenant proofs and a durable new allowance; it is not approved or active. Authentication/diagnostic RPCs remain disabled in the running stage, and the page says live testing is not enabled. There is no browser API to authorize/reset a trial. Finished diagnostic intents become immediately eligible for recovery. Startup/worker death/shutdown recover owned grant obligations independently, and incomplete cleanup retains the ownership lock for explicit recovery. No automatic restart, lease renewal or fixture import is configured. The service stops before its fixed activation/dependency/signing lease and on dependency failure, stale controller heartbeat or disconnect.

Actual local verification passed twice around a clean stop/restart: TLS and disabled landing page, unknown route, wrong Host, invalid sign-in request and forged authority headers. Both old processes exited and the lock was released; restart used a new instance with the same certificate. The trial/intent tables remained empty, policy grant states/versions and all11 historical Microsoft budget files remained unchanged. Windows listener inspection confirmed a single loopback listener. Receipts are `portal-service/{stage-verification,shutdown-verification,lifecycle-verification}.json` under protected custody. Live nonempty-grant cleanup is not claimed by this smoke test; it is covered by actual SQLite fixtures and still requires the reviewed browser trial.

Current verification: **549 production tests and372 baseline tests pass**. No Microsoft request, PF token issuance, new grant or public exposure was performed by the stage checks.

Operations:

```powershell
node scripts/vault/portal-service.mjs --status
node scripts/vault/test-portal-stage.mjs --verify
node scripts/vault/portal-service.mjs --stop
pwsh -NoProfile -File scripts/vault/start-portal-hidden.ps1
```

Use `--recover` only for a stopped/dead owned controller/worker; it refuses live PIDs, ownership drift or unresolved grant recovery. Do not remove its lock manually. The public HTTP Host is intentionally strict: this is not a browser preview at the plain localhost URL. Public DNS/tunnel activation is still pending.

## Controller and custody checkpoint

- `portal-journal.ts` persists a single hash-bound approval, pre-approval ownership intent and monotonic conversation/token-post/success counters in SQLite with FULL synchronization and transactional updates. The trial is consumed from consent reservation; a failed approval can therefore spend it without making a Microsoft request. Execution is durably claimed before calling the executor. A new cookie, second database handle or process restart cannot resume/spend it again. No runtime approval has been issued or seeded.
- `portal-control-plane.ts` independently verifies human proof, restricts policy operations to the consent endpoints and interactive one-hour approval, keeps grant/attempt associations private, and binds execution to the owned proof/grant. It requires measured conversation and token-post counters before accepting a successful diagnostic. The actual executor must still provide independent Microsoft-origin and policy-audit verification; counters alone are not that verification.
- `portal-recovery.ts` checks durable approval-token digest, creation time, expected policy workload and grant provenance before revoking. It verifies persisted revoked state before completing recovery. A missing or delayed remote commit remains pending. This is a controller-only, decreasing-authority operation; a stopped worker or elapsed lease is required. The actual authority-store adapter is now tested below; scheduled controller wiring remains unfinished.
- `agent-server.ts` adds a TLS factory with exact public Host and Origin, closed method/path/media rules, duplicate-header checks, bounded upload/header sizes and timeouts, global rate/concurrency/connection limits, dependency readiness and drain. Forwarded addresses do not select authority or evade admission limits. Only fixed event/status metadata is observed. It starts no listener; the final service must bind loopback and enforce the executor deadline within the 90-second response window.

`scripts/vault/enroll-portal.mjs` defaults to preview. The authorized local `--enroll` run created version1 of `/federated-copilot-tool-secrets/data/portal-controller` and its dedicated certificate reader. Exact policy `copilot-portal-controller-read` permits only that KV read; role `copilot-portal-controller-reader` grants a 120-second, one-use token without the default policy. The record contains the existing OIDC client key, consent-policy key, configured-provider secret and bound Direct Line secret. It excludes operator tokens and agent/gateway private keys. Runtime loading validates independently pinned public keys and credential digests and has no local-file fallback. Provisioning reads the existing protected project credentials; it does not remove them or rotate working clients.

Actual Vault read and seven unrelated-path/role denial checks passed. Repeating enrollment preserved version1 and existing role/policy unchanged. Its protected receipt is `.local/tool-vault/portal-enrollment.json`. No value or Vault token was printed, no Microsoft request was made and no service/public route was started. This remains Windows-account PoC custody, not production OS isolation.

Validation checkpoint:515 production tests and372 baseline tests passed, including crash/restart allowance handling, lost approval responses, ownership substitution, failed recovery and HTTP admission. These results do not establish a live browser service. The selected first UI scope is explicitly sign-in/access check, without chat.

## Gateway execution and actual database recovery checkpoint

`portal-policy-recovery.ts` now connects recovery to the existing version5 policy database. It checks the existing regular canonical file without creating a missing database, finds the exact persisted consent digest, and revokes only after provenance validation. Real SQLite tests recover a grant whose approval response was lost, preserve another grant's state/version, respect an active browser lease and prove repeat cleanup is harmless. Scheduled startup/worker-death/shutdown wiring still needs the managed controller; the test did not modify the running PoC policy database.

`src/copilot/portal-diagnostic.ts` composes the actual DirectLineAdapter with an independently verified human/provider/broker context, exact fresh-card token POST and private signed/mTLS handoff dependency. It sends only the two fixed verification messages, counts before channel/token POST requests, requires signed-in status and both connector stages, checks independent tool-policy evidence, and reauthorizes online before returning success. A bounded deadline stops stalled issuance; no raw messages/tokens become its result. `portal-policy-evidence.ts` reads exactly two matching tool-policy permit decisions for the owned grant and current operation window; human, actor/issuer, org, mode, scope/resource, tool issuer/audience and grant version must match. This evidence does not replace the final current policy check.

`scripts/pf/portal-gateway.ts` prepares real PF A assertion exchange and PF B broker issuance with injected Vault material, independently verified human and broker context, fixed registered agent, signed JWT client authentication and online policy. The portal's PF B client is `consent-gateway-2`, not the relay's `copilot-sso-exchange`. No password login, runtime private-key file fallback or operator token is used by this factory.

The [exact additional gateway custody review](portal-executor-custody-review.md) is awaiting explicit approval. Automatic approval review rejected creation of the new record/reader because it includes registered-agent and gateway private keys. The enrollment command did not execute; it was not retried through another method. A non-secret source/public-trust hash manifest is prepared. This is separate from the already verified four-credential portal-controller record. No new live PF/Microsoft issuance or trial was run. Latest full suites:537 production tests and372 baseline tests passed; the new execution protocol tests use controlled transports and do not promote live browser acceptance.

Subsequent enrollment checkpoint: the user explicitly approved **Vault enrollment only** against that unchanged review. All11 reviewed file/public-trust hashes matched before application. The approved command created record version1 and the dedicated exact-path reader. Its first verification did not complete; read-only diagnostics confirmed the expected key bindings, record/role/policy, one-use120-second login, permitted read and five unrelated-authority denials. Reconciliation then completed without changing the reviewed code, widening permission or overwriting credentials. The protected receipt is `.local/tool-vault/portal-executor-enrollment.json`; approval and independent verification are in `.local/tool-vault/portal-executor-review/`. All11 historical budget files and reviewed hashes remained unchanged. The three focused reader tests passed again. No runtime service, PF client change, grant, Microsoft test, public route or new allowance was authorized or started by this approval. The review document remains an immutable prepared packet; the separate approval/verification receipts record its later accepted state.

## Proposed endpoint configuration

## Live activation package ready for review

The [first browser activation review](portal-live-activation-review.md) is prepared and **awaiting approval**. It permits only the fixed new public hostname, one proxied CNAME, a path-limited tunnel route, two additive PF callbacks and a temporary exclusive PF B tool-client lease. The durable whole-deployment limits are one grant approval attempt, one Direct Line conversation, one fresh-card token POST and one successful diagnostic within a fixed one-hour maximum window (or earlier existing lease expiry). No Graph, free-text chat, autonomous execution, new billing policy or automatic retry is included.

`portal-activation.ts` / `portal-activation.mjs` validate the immutable review/manifest, all selected file hashes, exact targets/limits, explicit approval and a nonextendable activation intent. Live startup requires fresh post-approval public disabled-stage and tenant-readback receipts, actual callback after-state and no foreign PF lease. It refuses a spent/interrupted trial and never resets historical ledgers. New sign-in closes as soon as consent reserves the single attempt; existing verified sessions can finish their provider/check/revoke flow. Completion/revocation schedules immediate grant recovery and releases the PF tool-client lease. Fixed diagnostic metadata contains only HTTP status or verified/unavailable outcome, capped at16, with no token/URL/body/identity data.

`portal-activation-policy.mjs` checks the consent client's existing PAR/S256/private-key-JWT profile and configured-provider manager, adds only the exact two callbacks, supports guarded rollback, and ignores only server modification date/re-encrypted secret representation in settings fingerprints. Its persistent PF lease writes ownership before enable, checks drift/expiry, restores disabled state, can recover after expiry/lost enable response, and coalesces concurrent releases. The tool-client public key is independently matched to enrolled trust. Grant sweeps are serialized; incomplete cleanup/restore retains recovery ownership. `portal-admin.mjs` restricts operator administration to the three existing clients and emits no raw vendor errors. The gateway runtime imports no operator credentials; the separately invoked lifecycle supervisor uses the existing local PF administration path only for the reviewed enable/restore scope.

`portal-route.mjs` adds only the fixed host/path/loopback/TLS rule before deny-all. The application still independently enforces Host, Origin, method, schema and authorization. Ingress activation checks the pinned cloudflared2026.10.5 executable and owned connector, with a bounded readiness/rollback restart. DNS activation uses only the existing configured token, refuses conflicts/ambiguous retries and can require the owner to create the exact record manually if permission is unavailable. No alternate credential lookup is authorized.

Preparation actually read the existing three PF clients, verified the existing Power Platform connection as Connected and matched the publication/action receipt, then validated candidate YAML with the pinned cloudflared binary. These were administrative reads, not Direct Line conversations or token POSTs. **570 production tests and372 baseline tests passed.** Refreshed actual staged probes still passed with no trial/intent rows, unchanged grants and all11 historical budget hashes. An unapproved `--serve-live` attempt was rejected before modifying the running stage, PF clients, allowance or route.

Frozen packet: `.local/tool-vault/portal-activation-review/`;77 source/public-trust files. Review SHA256 `138aa6e0723ee786da44980e8697503a884b1fb33b59e06bf6985932af795964`; manifest SHA256 `c8112ba3a332d6128d7388f8ba3154b2812494f3bb3869cb323258fd64b07f2b`. `preflight-verification.json` confirms all files, callbacks, disabled PF tool client, source tunnel and historical ledgers unchanged. No new callback, DNS/ingress, PF client enable, grant approval or Microsoft test has been applied. Public browser/provider callback behavior and nonempty live recovery remain UNVERIFIED until the approved trial.

## Endpoint configuration

| Purpose | Exact destination | Exposure / status |
| --- | --- | --- |
| Browser origin | `https://agent.copilot.darkedges.com` | Proposed, not deployed |
| Human callback | `https://agent.copilot.darkedges.com/callback` | Additive callback on `copilot-consent-portal`; not applied |
| Provider callback | `https://agent.copilot.darkedges.com/provider-callback` | Additive callback on `copilot-studio-generic-oauth`; not applied |
| Browser authorization | `https://pf-a.copilot.darkedges.com/as/authorization.oauth2` | Existing public route; canonical human OIDC issuer stays `https://localhost:9033` |
| Human PAR / redemption / JWKS | Existing fixed PF A localhost endpoints | Server only; original OIDC client audience |
| Provider issuer / audience | `https://pf-a.copilot.darkedges.com` / `api://copilot-login` | Existing trust; not tool authority |
| Gateway handoff | `https://localhost:9465` | Existing private pinned mTLS/signed envelope; never public |
| Connector callback | `https://relay.copilot.darkedges.com/v1/copilot-tools/verify-access` | Existing approved route, unchanged |
| Portal origin listener | `https://127.0.0.1:9466` | Running locally in staged mode; pinned server-only certificate, TLS hostname `localhost`, HTTP Host `agent.copilot.darkedges.com` |

Proposed DNS is one proxied CNAME: `agent.copilot.darkedges.com` to `a979d27b-f2cd-45cf-aada-b44c850e3a0e.cfargotunnel.com`. Proposed tunnel allowlist is only `/`, `/login`, `/callback`, `/approve`, `/provider-login`, `/provider-callback`, `/check`, `/revoke`, `/logout`, followed by host-specific 404 and existing final deny-all. The application must independently enforce methods, Host, request limits and CSRF. Never expose policy, Vault, PF administration, handoff, diagnostics or metrics. Preserve currently approved PF/relay routes. These are proposed values, **not an approved activation packet**.

## Required before public activation

1. Obtain explicit approval for the prepared live package, then apply only its reviewed actions. Staged mode remains default; missing approval, hash drift or absent fresh proofs blocks live startup. Verify actual PF/browser behavior within the bounded scope. Do not pass operator authority, stored passwords or agent keys to web code. Same-account process separation does not establish production OS isolation.
2. Seed the implemented durable journal only under the approved immutable review, before any Direct Line request. Preserve every historical ledger. One attempt across browsers/processes/restarts, no retry/reset. Keep its approval loader and journal outside the web worker.
3. Verify the now-wired startup/scheduled/shutdown recovery with an actual owned browser grant and controlled worker failure under the reviewed trial scope. The page's in-memory session map is not durable authority. Never extend expired human proof or revoke unrelated grants. Preserve spent-trial state when deleting old audit data.
4. Preserve the verified loopback service, dependency readiness, separate controller/web data flow, lease bounds and fixed metadata. Apply the prepared bounded privileged PF-tool-client enable/restore lifecycle only after approval; keep operator credentials out of the runtime composition. Preserve one-day audit maintenance and the existing eight-hour signing lease.
5. Verify the frozen packet again after approval, then perform its DNS/ingress/stage/tenant/callback/live steps in order. Do not change issuers, keys, audiences, lifetime, client authentication or existing callbacks as side effects. Do not apply live changes merely because a local test passed.
6. Verify actual browser sign-in for the same human in both OAuth transactions, the current published agent, a fresh Direct Line OAuth card's exact `content.tokenPostResource.sasUrl`, exact JSON `{ "token": "<configured-provider-user-access-token>" }`, fixed diagnostic and independent identity-policy audit. Revoke the owned grant and verify cleanup independently. Retain no raw credentials in logs or test output.

Provider authorization-code/S256 under the proposed second callback is **UNVERIFIED** against actual PF. The Generic OAuth secret would be shared with the existing Microsoft test client; review this PoC custody choice. A separate client requires Microsoft provider-binding verification; do not assume interchangeability. Microsoft tool-trace protection remains UNVERIFIED under the existing explicit PoC exception.

## Lifecycle verification

Local tests cover other-browser callbacks, replay, CSRF, substituted authority fields, wrong human/provider issuer/audience/scope, expiry, injected delegation claims, malformed aliases, endpoint substitution, parallel execution, failed execution and failed revoke. These are not live Microsoft lifecycle results.

A live revocation test must prepare a fresh unused binding before revoking its owned grant. Reusing a consumed binding after success could fail from replay protection and does not isolate revocation. Distinguish gateway denial from an already-authorized request in flight reaching the connector; review that race explicitly if testing origin-side enforcement. Require zero successful tool operations and an independent denial record.

Label the layer under expiry test: human proof, browser session, broker token, binding or PF provider token. The binding/proof can expire before the 60-minute provider token. Its denial does not establish Microsoft provider-token expiry behavior. Keep live provider expiry and autonomous Copilot SSO **UNVERIFIED** until separately reviewed and tested. Graph/SharePoint remain **NOT CONNECTED**.

## Live activation outcome - 2026-11-01

The explicitly approved portal is now reachable at https://agent.copilot.darkedges.com. Reviewed DNS/ingress, public staged TLS/no-store/denied-path checks, Microsoft connection read-back and both additive PF callbacks passed. Live sign-in was enabled at 14:54 AEDT for a fixed window ending **15:54 AEDT on 1 November 2026**. One durable attempt is available; no conversation/token POST/tool check has been consumed at activation. Actual browser flow remains UNVERIFIED pending the owner's sign-in, consent, provider sign-in and single access check. Earlier proposed/not-applied descriptions above are superseded only for this approved bounded activation; production acceptance is unchanged.

## Sign-in correction deployed - 2026-11-01

The approved form-policy correction is deployed and public HTTPS confirms same-origin on the sign-in page. Sign-in is enabled again. Reload the root page before retrying, to obtain a fresh page/session after the service restart. Original expiry remains15:54 AEDT; the existing single allowance remains unused. Actual browser resolution and diagnostic completion remain UNVERIFIED until the owner continues.

## PingFederate redirect correction deployed - 2026-11-01

The approved second browser correction is deployed. Public HTTPS verifies form navigation allows self and exactly https://pf-a.copilot.darkedges.com, with no wildcard. Sign-in is enabled; reload the homepage for a fresh session and current policy before retrying. Original expiry15:54 AEDT and unused single allowance remain unchanged. Browser completion is still UNVERIFIED pending the owner's retry.

## OIDC key refresh deployed - 2026-11-01

The explicitly approved two-alias refresh for one PF A RSA signing key is loaded by the restarted portal and existing policy/relay services. Public page and connection readiness passed. Reload the homepage for a fresh session and complete PF login/consent again; callback resolution is still UNVERIFIED until that retry. The original15:54 AEDT expiry and unused single diagnostic allowance are unchanged.

## Diagnosed issuer correction deployed - 2026-11-01

Fixed diagnostics identified iss validation rejection. The explicitly approved public virtual issuer and exact user/client-to-existing-human binding are now loaded by the restarted portal/policy/relay services. Actual verified issuer is retained; original localhost flow and principal record remain intact. All585 production and372 baseline tests passed before deployment. Public readiness and connection checks pass; callback resolution awaits fresh owner login/consent. The original15:54 AEDT expiry and unused single allowance are unchanged.

## First browser trial finished - 2026-11-01

Human sign-in and portal/provider consent succeeded, but the access check ended at the private proof handoff before any Microsoft token POST. The owned grant is revoked and the dedicated PF tool client disabled. The original allowance is spent and its window expired; the portal is stopped. A reproduced relay issuer-list propagation defect is fixed locally with590 passing production tests, but deployment and another browser run are pending. See docs/portal-browser-trial-result.md for evidence and limits. Browser delegated-diagnostic acceptance remains UNVERIFIED; do not reuse/reset the spent trial.

## Corrected relay and separate retry active - 2026-11-01

The owner approved the relay fix and a distinct bounded retry. The corrected relay is deployed; source/predecessor, public HTTPS and connection checks passed. New run409f6cde-b84a-439d-931c-a1ad1083ed34 uses a separate journal and review; the original spent journal/counters/window are unchanged. Its live window is19:29-20:29 AEDT today, with one unused manual consent/conversation/token-post/diagnostic allowance. Reload the homepage and complete sign-in/consent/provider sign-in/check once. Do not reuse the earlier session or infer another retry. Corrected live delegation remains UNVERIFIED pending that outcome. See docs/portal-relay-retry-review.md.

## Interactive browser success verified - 2026-11-01

The owner completed the live flow at19:50AEDT and saw Delegated access verified. Independent confirmation proves1 conversation,1 fresh-card tokenPOST200,1 successful diagnostic, exactly2 matching tool-policy permits and1 relay-origin success. The original public human issuer, human/agent/org/grant/mode/resource/audiences are preserved. Grant revoked, recovery complete, dedicated PF tool client disabled and lease removed. Both original and retry journals remain spent; new sign-ins/checks are disabled and no further run is authorized. Passive window ends20:29AEDT. See docs/portal-browser-success.md for evidence and remaining production/autonomous/Graph limits. Earlier UNVERIFIED labels above remain historical; this outcome supersedes only interactive browser diagnostic acceptance.

## Repeatable sessions prepared - 2026-11-02

Repeatable interactive sessions are implemented and tested locally, with a separate five-session/one-hour/serial deployment proposal. Each session requires new login/consent and confirmed cleanup before the next; earlier spent allowances remain unchanged. The portal remains stopped pending approval of the expanded live budget and exact OIDC pin refresh. See docs/portal-repeatable-sessions.md and docs/portal-repeatable-session-review.md. This does not change the earlier single-check browser PoC's verified status; multi-session tenant acceptance is still UNVERIFIED.

## Repeatable deployment active - 2026-11-02

The owner approved the five-session profile and exact additional key amendment. Deployment/readiness passed with both prior runs unchanged. Run5047fea6-ce89-4d4c-b62d-06652af5a094 is live from16:58 to17:58AEDT today, with zero of five fresh sessions used at activation and one active session maximum. Complete one manual sign-in/consent/check, select Sign out and start again, then complete another. Each slot stays spent and its owned grant must be independently revoked before the next. No automated test or renewal occurs. Multi-session live acceptance remains UNVERIFIED until independent confirmation of those sessions.

## Repeatable browser acceptance verified - 2026-11-02

Two independently audited owner-operated sessions passed with distinct login proofs/grants and completed per-session cleanup. Repeatable interactive diagnostic acceptance is VERIFIED_POC. Three slots remain in the existing five-session window, ending17:58AEDT. No new allowance or automatic renewal is inferred. Earlier one-shot records remain unchanged; production/autonomous/Graph limits remain.


## Single visible login and optional automatic approvals — local preparation

The new checkbox is checked by default and discloses fixed chat/sample permissions before sign-in. Automatic mode advances setup without submitting a question; clearing it preserves manual approvals. Distinct login proofs/grants remain mandatory. A five-minute per-adapter PF session and scoped identity-only approval-page bypass are prepared, not applied. See [the exact deployment review](document-chat-single-login-review.md). Local796 production/372 simulation tests pass; actual single-visible-login behavior remains UNVERIFIED. The prior three-sign-in sample answer remains verified under its original source packet.
