# Review: five repeatable browser sessions

Status: **PREPARED, NOT APPROVED OR DEPLOYED**. The earlier verified browser allowance is spent. The user's request to implement repeatable sessions authorizes local development; this packet requests the expanded live allowance.

Run ID: `5047fea6-ce89-4d4c-b62d-06652af5a094`.

## Exact live allowance

Enable the existing portal at `https://agent.copilot.darkedges.com` for **at most five new consent/session attempts in one fixed one-hour window**, with **one active session at a time**. Each session requires fresh PF login proof, explicit agent consent, same-human provider sign-in and one fixed delegated diagnostic. Each slot permits at most one Direct Line conversation, one fresh-card token POST and one successful tool check: at most five of each for the deployment. Failed, revoked or abandoned consent attempts consume their slot; they are never reset or automatically retried.

The first activation intent anchors the hour, shortened if the existing dependency lease ends sooner. Restart cannot extend it or reset totals. This is one deployment, not an hourly renewal, unlimited service or new dollar spending cap. Existing billing settings remain unchanged. No free-text chat, autonomous execution, Graph/SharePoint, new public route, DNS/certificate, tenant grant, external Entra provisioning, publication or credential-custody change is included.

The owner manually completes browser sessions. After a result, **Sign out and start again** uses the existing protected logout route, revoking any remaining owned permission before clearing the browser session. A subsequent check needs a fresh signed proof and consent; the prior proof hash cannot reserve another slot. No automated human login or test conversation is authorized. The owner may perform two sequential sessions for initial live verification, leaving any remaining capacity within this same reviewed cap.

The controller refreshes the worker's presentation-only availability flag after completed actions so sign-out does not wait for the next periodic poll. These budget messages cannot renew dependency health, heartbeat age or service expiry. Authentication and quota decisions remain in the independent controller; worker presentation alone never enables authority.

## Authority and persistence

Read-only preflight found that PF A has published another dynamic RSA signing key since the verified run. This packet also permits adding only its two public identifiers, `j7r0rZ5VtyY3ZHWwyeRInDC1xTc` and `j7r0rZ5VtyY3ZHWwyeRInDC1xTc_RS256`, to the existing OIDC verifier pins. Both represent the same RSA2048 key with RFC7638 thumbprint `8ZjWnzICYItU-gVwdRg5_O-JFZbK2R296nEkBPNKaHo`, read from the existing TLS-trusted PF A JWKS endpoint. Reverify identical public material before application; refuse drift. Candidate OIDC config SHA256 is `14bbb4314f3a7c6785bf25b901425a16a11afd3fd36d44206e2adddf37031a8d`. Retain every existing pin, issuer, audience and signature/lifetime requirement. No PF key generation/rotation, private-key export, credential or client change is included. This is an explicit reviewed pin refresh, not automatic admission of every published key.

Use the new repeatable journal `sessions.5047fea6-ce89-4d4c-b62d-06652af5a094.sqlite`, bound to this review and exact `{maxSessions:5,maxConcurrent:1}` policy. Do not migrate, replace, reset or reinterpret either earlier one-shot ledger. Archive the preceding active packet/status/instance/diagnostic snapshots; preserve both completed one-shot journals, windows, results and every historical allowance. Manifest/approval bind the original predecessor plus the verified successful predecessor's exact journal/window/result hashes; readiness refuses drift or reuse of the predecessor run ID. Staging uses its own journal.

SQLite reserves a slot before remote consent. Further sign-in is blocked while a prior session has unresolved recovery, even if a delayed consent commit is not yet visible. Completion/failure leaves the slot spent. Only independent confirmation that its owned grant is revoked releases the next available slot. A restarted controller cannot resume old in-flight proof ownership; owned recovery must revoke it first. No browser route chooses a run or authorizes/resets a deployment.

Original human issuer/subject/audience, registered actor/issuer, organisation, grant, interactive mode, resource, scope and token audiences remain independently verified at the existing boundaries. One-hour service availability does not extend five-minute human proof/session freshness. Every tool operation retains current policy checks, signed agent authentication, private handoff, mTLS and explicit issuer/key pins. No mock fallback is added.

The dedicated PF B tool client may remain enabled under its existing exclusive ownership lease between sessions while this deployment has capacity. Restore it disabled after the final recovered session, fixed expiry, shutdown/startup failure or explicit owned recovery. No client scopes, issuers, keys, lifetimes, callbacks or authentication method change. Public PF/relay/portal routes remain exact and unchanged; protected status, Vault, policy, handoff and metrics remain private.

## Apply and containment

Freeze source/public-trust hashes and final test results in the candidate manifest. Before applying, verify the stopped portal, both predecessor journals finished with no pending recovery, their owned grants revoked, unchanged fingerprints/callbacks/virtual issuer and disabled PF tool client. Refuse any unexpected state. Archive the old OIDC config before installing the reviewed public pin addition. Restart the existing owned private tool/policy and relay services to load consistent pins, preserving credentials, policy data, retention and all ledgers. Use only the existing Windows/Docker deployment; no automatic restart/renewal is installed.

After explicit approval, record the exact policy/run/review/manifest and successful predecessor in a new approval receipt. Start disabled stage and verify real public HTTPS/no-store/denied admin/health/metrics paths plus fresh read-only Microsoft connection/publication metadata. Stop stage and launch live with the distinct repeatable ledger and window. This must not seed or modify a one-shot allowance. Revoke/recover only owned grants, preserve final audit counters after close and disable sign-in when capacity/window ends.

Audit uses the existing one-day settings and bounded credential-free telemetry. Recovered session proof/grant metadata is stripped after one day, retaining minimal spent rows/counters. Pending ownership is retained until resolved. The new stopped-owner maintenance command defaults to preview, requires the selected Windows owner and stopped portal, scans only repeatable ledgers and cannot reset budgets or renew authority. No offline deletion scheduler is installed; eligible metadata remains while the host is offline until maintenance runs. Do not run maintenance against prior one-shot evidence.

## Validation and acceptance

Failing tests precede the trust/policy changes. Local validation covers repeated fresh-consent/check/revoke cycles against the actual persistent-policy implementation, cross-controller reservations, missing/lost consent responses, restart recovery, stale proof/replayed event/grant substitutions, expiry, cap changes, malformed profiles, immutable predecessors, worker presentation without authentication authority, sign-out/fresh-login and one-day metadata maintenance. Full production and simulation suites must pass before this packet is frozen; final counts are recorded in its preparation receipt.

Live multi-session acceptance remains **UNVERIFIED**. For each successful session require runtime sign-in, fresh exact OAuth-card URL/JSON provider-token POST, both connector stages, fixed positive result, exactly two matching independent tool-policy permits, origin success, final authorization and confirmed owned-grant revocation. After two sessions verify distinct proofs/grants and aggregate counts; retain the remaining approved cap without inferring renewal. Stop on unexpected outcomes and investigate the existing attempt rather than retrying it.

The existing PoC exception for provider-token tool input remains: Microsoft credential-trace protection and same-Windows-account isolation are not production guarantees. Autonomous SSO, live Microsoft expiry/revocation and Graph integration remain outside this verified feature.

Approval is needed because the earlier live approval allowed one check, while this packet permits up to five separately consented checks and keeps the bounded PF lease active between them. It also admits only the identified newly published OIDC public key through an exact pin refresh.
