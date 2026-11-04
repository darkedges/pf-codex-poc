# Consent-backed canary through enrolled Docker credentials

The local canary extends [enrolled private networking](enrolled-tool-network.md) with real PF A browser login, human-approved consent, independently authenticated agent issuance, actual PF A/B exchanges and the enrolled mTLS tool workload. Run `npm run tool:enrolled-network-test -- --canary`. The default no-argument command only previews the non-mutating readiness scope; `--canary` explicitly includes temporary PF B enablement and consent grant creation/revocation.

## Execution and authority

The runner holds the existing shared PF/Microsoft execution lock in addition to the network/policy locks. It loads the pinned local CA at Node startup for the browser harness. It never disables TLS validation, changes public routes or sends a Direct Line/Microsoft/Graph request. Only local PoC identities, the fixed read-only diagnostic and `sharepoint:approved-research` are used; no Microsoft resource is accessed.

The temporary portal at `https://localhost:9461` connects explicitly to the persistent policy profile at `https://localhost:9452`. The existing portal is not redirected. Actual PF A login uses the existing PAR/S256/OIDC flow and approved PoC test account. Each of two newly consented grants is explicitly approved with interactive and autonomous modes. Interactive issuance additionally supplies a fresh independently validated login proof; autonomous issuance uses authenticated agent proof plus the active consent grant, with no human token supplied to that request.

The bounded client lifecycle verifies the current human-login and PF B tool-client profiles, temporarily enables only PF B, then restores it disabled and compares the human client's observable settings. It never writes the human client. PF's randomized encrypted-secret representation cannot prove absence of an out-of-band secret rotation; this limit is unchanged.

Tokens stay in memory and cross to the Docker probe on stdin. They never enter command arguments, environment variables, chat prompts, receipts or diagnostic output. The probe returns fixed status/boolean fields. The runtime still independently verifies the pinned issuer/JWKS, exact audience, RS256, key ID, bounded lifetime and online PDP before execution and result release; the canary's claim comparisons are assertions over the already verified exchange result, not a replacement verifier.

## Checks

For both modes, the canary verifies:

- Exact original human and acting-agent identities, actor issuer, organisation, grant, execution mode, PF issuer, audience, scope and maximum 120-second lifetime.
- A successful diagnostic through the enrolled mTLS workload, plus missing-certificate, unapproved body identity/resource override and upstream-audience rejection.
- Independent pre/post `policy-tool` permit records containing the same verified identity, audience and fixed resource.
- Real-clock token expiry while the grant remains active, followed by successful fresh issuance/use under that same grant.
- Fresh owner-authorized revocation, rejection of the still-valid replacement token, denial of new issuance and independent PDP evidence of the newer revoked grant version.
- Restricted local tool audit containing success/denial evidence without raw human/agent identifiers or any emitted token.

The readiness/network suite also runs its existing route, mount, privilege, outage and recovery checks. Real expiry is intentionally observed without shortening lifetimes, changing the clock or weakening validation. A progress message reports only the phase and remaining seconds.

## Durable cleanup

Before approval, a protected receipt records existing grant IDs/state/versions. Newly created owner-consented grants are recorded separately. Cleanup uses fresh human-owner proof and exact server-rendered revoke forms; it does not use an admin grant mutation or direct database write. An owner-revocation recovery pass makes at most three requests, independently reading the exact grant state before/after each request. Confirmed revocation ends the pass even if the response was lost; missing/unknown state or exhausted recovery fails closed. Failure cleanup may make its own bounded pass, but does not turn a failed verification into a pass. Recovery reconciles only new consent rows under the PoC human/agent/organisation and consent workload, excluding the entire pre-run grant set. Every newly owned grant must be terminally revoked and every pre-existing grant must retain its original state/version. Revoked grants and consent/audit evidence remain in the durable registry rather than being deleted.

The parent independently checks those terminal states, PF A enabled/PF B disabled, removal of labeled Docker resources and temporary role credential copies, and retirement/removal of the separate policy signing lease. It preserves the selected Vault records/snapshot and restricted audit receipts. Uncertain cleanup retains execution locks for review. Verification leaves services stopped; it does not establish continuous operations or production approval.

## Verification status

Verified 2026-10-31 Australia/Sydney: **47 live checks passed**, including all 23 readiness/network checks and 24 consent-backed identity, acceptance, rejection, real-expiry, renewal, revocation and audit checks. The successful run completed at **2026-10-30 19:32:39 UTC / 2026-10-31 06:32:39 AEDT**. All **259 baseline** and **283 production** tests pass. Production runtime behavior was unchanged; new tests cover canary identity continuity, preservation of pre-existing grants and bounded owner-revocation recovery, including lost responses and unknown grant state.

All new grants are terminally revoked, existing grant state/versions are preserved, PF A remains enabled and PF B is disabled. Verification containers/network, temporary credential copies and the policy signing lease were removed; selected Vault credentials/snapshot and restricted consent/audit records remain. No continuous service or public host port was left running.

Earlier attempts failed closed and cleaned up: one lacked the browser process's startup CA configuration, and another encountered a transient owner-revocation failure after its expiry/renewal checks. Loading the pinned CA at startup and adding independently state-checked bounded owner revocation resolved these harness issues. No TLS, token, consent or revocation policy was weakened to obtain the successful result. Failed receipts are retained.

Copilot secure-token-post, Copilot-originating caller authentication, Graph/SharePoint and production operations remain **UNVERIFIED** regardless of local canary success. The [local service controller](local-tool-controller.md) now implements and verifies start/stop, dependency failure and owned crash recovery. Continuous startup awaits the explicit service/audit owner and retention choice; Microsoft verification remains separate.
