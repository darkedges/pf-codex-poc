# Controlled live token-post test — approved run results

Current status (2026-10-31): all historical allowances below are consumed. They posted PF B tool proof despite a PF A Generic OAuth connection. The [provider-token correction](copilot-provider-token-fix.md) is locally implemented and verified, but has not been tested against Microsoft. The old two-mode runner is retired; autonomous provider sign-in fails closed. A new explicitly approved single interactive allowance is required for any corrected tenant test. No budget was reset by the fix.

Prepared 2026-10-30 (Australia/Sydney). Automatic approval review initially rejected adding the runnable harness because general continuation did not specifically authorize delegated-token egress and temporary PF B client enablement. The operator subsequently explicitly approved this exact plan with “yes please continue.” The harness was then added and the approved test executed without exceeding its two-conversation/two-POST cap. The earlier rejection was not bypassed.

## Observed results

| Mode | Microsoft token POST | Runtime status after POST | Local policy/cleanup |
|---|---|---|---|
| Interactive | One POST, HTTP 400 | Not verified; adapter stopped on failure | Isolated consent-backed test grant confirmed revoked; PF client states restored |
| Autonomous | One POST, HTTP 400; sanitized error category `expired` | Not verified; adapter stopped on failure | Fresh delegated token passed independent local tool verification and online policy with original human/actor/org/grant/mode; grant revocation then denied local tool use and channel access; PF client states restored |

The error classifier emits only fixed categories; `expired` means the response contained expiry-related text, not that the PF access token or SAS URL is independently proven expired. The original response body was not retained. The autonomous Microsoft response request ID is `5319621832974d895c07d7d18f2aad02`; its run window was 2026-10-29 20:50:27–20:50:34 UTC (2026-10-30 07:50:27–07:50:34 AEDT). A subsequent credential-free GET to Microsoft's root returned a Date header aligned with the host to the nearest second. This rules out an observed broad clock offset at that check, not every timing or service condition.

The private budget now records both modes reserved. An explicit exhausted-budget check refuses another run before starting a policy process, taking a client lease or changing that budget. Both isolated databases show their one consent-backed test grant revoked. The synthetic bootstrap fixture grant is separate from these test grants. PF A's dedicated human login remains enabled, PF B's dedicated tool client is disabled, and no public ingress/Microsoft/Graph setting changed.

## Timing follow-up — explicitly approved and executed

The operator approved the single additional interactive attempt with “please continue.” A separate one-attempt receipt reserved the follow-up without resetting either original mode. It made one token POST, received HTTP 400 with expiry-related text, revoked its grant and restored PF B disabled. The local interactive diagnostic and both revocation checks passed.

At card receipt, the secure challenge had about 58 seconds remaining against host time and 59 against the provider Date; at the POST it had about 58 seconds against both clocks. The independently verified PF access token had about 119 seconds remaining. The Microsoft request ID is `c28843b0bdc85a5d4004f46700b19b94`. These measurements do not identify which internal object Microsoft considered expired. See the [new support draft](copilot-token-post-support.md); no further retry or configuration change is inferred from this error.

All **164 baseline tests** pass. Original and follow-up reservations are both exhausted; no new attempt is authorized. The remaining text describes the scope of the completed follow-up for reference.

One additional **interactive** conversation, at most one token POST, with the same synthetic identity, grant, destination, client cleanup and no-new-public-route constraints. Record only relative expiry timing when the OAuth challenge arrives and immediately before token POST, comparing to the provider Date header where available. Never record the SAS URL or query values. If the secure challenge is already expired or the token/PDP checks fail, stop without sending a token. No automatic POST retry or further conversation is authorized.

The timing helper is prepared and unit-tested for UTC ISO, Unix seconds/milliseconds and .NET tick-shaped expiry values; unrecognized formats are marked unknown rather than asserted valid. It is diagnostic arithmetic, not a new authorization source. Any extension of the exhausted conversation budget requires explicit operator approval; existing budget reservations must remain historical evidence.

## Harness and verification

`npm run copilot:live-sso` previews only. `--run` starts only with an unused two-conversation budget; `--remaining` consumes only the one mode not previously reserved in a partial run. Reservations are saved before channel token generation; failed/ambiguous attempts remain spent. PF enablement and cleanup are guarded by the six lifecycle tests. Production Direct Line adapter JOSE/PDP checks and exact destination rules are used for the actual POST. The harness uses a reserved, nonresolving trusted origin for its backend-only lab channel; it deploys no browser app or public frontend.

All **159 baseline tests** pass, including budget/lifecycle/error-redaction/timing checks. The last production suite has **228 passing tests**; no production adapter change was made in this live-test step. Live Microsoft token-post acceptance, Copilot-received token continuity and Copilot-originated protected tool acceptance remain **UNVERIFIED**.

## Original approved scope (reference)

| Item | Proposed action |
|---|---|
| Microsoft target | Existing Federated Delegation Test in Sandbox `c72f8bf6-020d-e210-8662-fa461a415ec2`, bot `1d18f6de-66d3-f111-a05b-6045bd40333e`, schema `cra8f_FederatedDelegationTest` |
| Channel identity | Existing operator-bound current-agent secret; pin the sender recorded in the protected current-channel contract |
| External destination | Verified HTTPS origin `https://token.botframework.com`, **exact path `/api/sas/postToken`**, only a fresh OAuth challenge received in the bound conversation; never print/store SAS query values |
| Data transmitted | A fresh, short-lived PF B delegated access token in JSON `{ "token": "..." }`, once per test conversation; signed synthetic human/actor/organisation/grant/mode/scope claims are disclosed to Microsoft |
| Token authority | PF B issuer `https://pf-b.copilot.darkedges.com`, audience `api://copilot-tool`, scope `copilot.invoke`, maximum 120-second lifetime; validated signature and canonical identity/grant continuity plus online PDP before/after issuance and transmission |
| Human and agent | Existing synthetic lab user `partner-a:user-123` and registered lab agent; no real document content or external Entra user provisioned |
| Credentials | Existing selected non-exportable Vault signer, separate signed-JWT PF client credentials and protected current-agent channel credential; no fallback signer and no secret in source, command arguments, prompts or output |
| PF state change | Temporarily enable **only local PF B client `copilot-sso-exchange`**; restore/verify disabled in cleanup even on failure or an ambiguous enable response; PF A login stays enabled and unchanged |
| Grant custody | New isolated local policy database with synthetic lab consent and explicit background opt-in, local HTTPS authority/PDP and fresh subject assertions; revoke test grants during cleanup |
| Bounded external use | At most two new Direct Line conversations, one for interactive and one for autonomous grant-backed execution; one fixed status message and at most one token POST per conversation, no automatic POST retries |
| Networking | Existing public PF ingress unchanged; PF B public token endpoint stays denied. No new public listener, DNS, tunnel route, firewall rule or browser application |
| Out of scope | No tenant-wide grants, Entra application registration/permission change, Microsoft authentication change, Graph/SharePoint request, deployed Copilot tool API or real business data |

## Proposed checks and evidence limits

1. Verify exact current channel target/digest binding, observed sender and token-post destination. Refuse stale/unknown configuration before a credential is used.
2. Use an isolated consent-backed policy registry and the selected Vault authority. Obtain fresh verified PF A proof and separately audienced broker/tool tokens. Never use a human-login token as delegated authority.
3. Open one bound Direct Line conversation for each mode and trigger the authentication topic using the fixed status command. Validate the complete activity batch and independently verified tool token before posting it to the pinned fresh challenge. Transmit no channel Authorization header to the token-post endpoint.
4. Record only generic status/counters and whether the existing fixed diagnostic returns `User.IsLoggedIn=true`. This measures the live protocol/runtime status; it does not prove that Copilot preserved the exact token bytes or accepted a protected tool call.
5. Invoke only the existing **local diagnostic** policy-protected operation with the issued token to check original subject/actor/grant/mode, then revoke the grant and verify denial of further local operation/channel use. This local call is not a Copilot-originated tool call.
6. Revoke remaining test grants, stop owned local processes, disable/verify PF B's dedicated client and confirm PF A's login profile remains unchanged. Preserve a recovery receipt/lease if state cannot be verified; never stop unrelated services or overwrite unexpected state.

Actual Copilot-to-tool token delivery, independent verification of the token received from Copilot, negative/expiry behavior in the real tenant and tool-side grant enforcement remain **UNVERIFIED** until tested through a separately reviewed tool API. A successful token POST or Boolean status is insufficient. The existing local expiry/revocation tests remain separate evidence.

## Pre-run preparation (historical)

- Exact Microsoft token-post path support and destination substitution negatives pass in the production adapter tests.
- The local lifecycle helper preserves the active human client, enables only B, restores B on success/failure or ambiguous enable response, and rejects unexpected profile/state. Six synthetic lifecycle tests pass; no live enablement was performed.
- All 141 baseline tests pass; the last production suite has all 228 tests passing. The production adapter was not changed while preparing the lifecycle helper.

Original approval and the explicit one-attempt timing extension are now both consumed. Neither authorized new public routes, production IAM changes or Graph access. Do not reset their historical reservations.

## Explicitly approved single retry — 2026-10-30

Following explicit operator approval, one fresh interactive conversation and one token POST ran at 2026-10-30 08:41:03–08:41:14 UTC (19:41:03–19:41:14 AEDT). Microsoft again returned HTTP 400, expiry-related text (raw body not retained), request ID `320cc71fbead2f79d8b9e025737fc8ed`. At POST, challenge lifetime was approximately 57 seconds against host time / 58 seconds against provider Date; independently verified PF token lifetime was 119 seconds. Local protected-tool verification passed; grant revocation subsequently denied local tool and channel access. Read-only database inspection confirmed the one consent-backed grant revoked; independent PF administration checks confirmed human login enabled and tool client disabled. The separate one-attempt retry budget is consumed; earlier budgets remain unchanged. No successful Microsoft token-post or Copilot tool acceptance is claimed.

Preflight initially stopped before any conversation because the local Vault runtime lease had expired. The existing Vault setup command refreshed its sign-only lease; no development signer fallback was used. The approved diagnostic then ran once. This adds a second fresh-lifetime request trace to the support case; it does not identify the expired Microsoft-side object.
