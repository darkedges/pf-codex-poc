# Current-agent channel reconciliation

Timing follow-up: the explicitly approved single interactive follow-up also returned HTTP 400 despite about 58 seconds remaining on the challenge and 119 on the independently verified access token. Its local verification/revocation checks passed and cleanup is confirmed. Both approval budgets are exhausted. A [sanitized Microsoft support draft](copilot-token-post-support.md) now contains the request ID and measured relative lifetimes; the root cause remains unverified.

Latest live-test result (2026-10-30 Australia/Sydney): the operator explicitly approved two bounded grant-backed token-post attempts. Both interactive and autonomous POSTs reached Microsoft and returned HTTP 400; the autonomous response classified as expiry-related. Both test grants are revoked and PF B is disabled again. Local autonomous token verification/policy and revocation denial passed, but Microsoft acceptance and Copilot-originated tool use remain UNVERIFIED. The two-conversation budget is exhausted. See [results and the proposed single timing follow-up](copilot-token-post-test-plan.md). Earlier “no PF token posted” statements below describe the discovery stage only.

## Verified discovery — 2026-10-30 (Australia/Sydney)

The operator copied the Native app URL for the current **Federated Delegation Test** agent, schema `cra8f_FederatedDelegationTest`, in the approved Sandbox. Its path is `/copilotstudio/dataverse-backed/authenticated/bots/cra8f_FederatedDelegationTest/conversations`, with API version `2022-03-01-preview`.

This is an authenticated conversation route, not a Direct Line token endpoint. The diagnostic accepts this exact path shape in addition to the earlier `agenticruntime/3p` shape, validates the configured environment host/schema/API version first, and makes only a credential-free regional-settings request. It never sends PF or Direct Line credentials to the authenticated conversation route. Microsoft's [SDK documentation distinguishes Entra-authenticated D2E from Direct Line](https://github.com/microsoft/Agents/blob/main/docs/copilot-studio-client-s2s-doc.md). Discovery is not evidence that either integration is usable for this agent.

Live discovery returned `https://directline.botframework.com/v3/directline`, without reading a secret or creating a conversation. The previous agent settings were preserved under ignored `.local/copilot/channel-settings.before-current-agent.json`; active local channel settings now identify the current exact agent. Old publication/channel receipts remain historical and have not been rebound.

## Bind the current agent's channel credential

Completed follow-up: the operator saved the current-agent credential with the binding helper. The gated live probe passed missing/invalid credential rejection, generated a conversation token and started a conversation. The initial greeting-only short poll returned no activity; a corrected bounded probe with one fixed `/federation-status` message received two bot messages including one OAuth card. It observed one sender ID, distinct from both the Dataverse record ID and old agent sender. Exact current binding/contract metadata are stored privately in `.local/copilot/current-channel-contract.json`. This is evidence from an operator-bound channel and verified HTTPS responses, not a protected-tool authorization result.

The observed secure token-post contract is origin `https://token.botframework.com`, exact path `/api/sas/postToken`, query parameter names `expiry`, `hmac`, `id`, `state`. No query values, sign-in URLs, bot text, conversation IDs, token or credential were printed or persisted. No PF token was posted and the SAS URL was not followed.

The production adapter previously required a directory prefix ending in `/`. It now supports exactly one of `pathExact` or the existing `pathPrefix`, retaining the old behavior. The [observed Microsoft rule fragment](../infra/copilot/microsoft-token-post.example.json) pins the single path without widening to `/api/sas/`. It is not a full deployment configuration: trusted application origin and production hosting/custody still require a concrete deployment plan.

The existing secret has no verified provenance for the current agent. The diagnostic refuses to use it without an explicit operator binding. In the current agent's **Settings → Security → Web channel security**, copy an existing Secret 1 or Secret 2 and run locally:

```powershell
pwsh -NoProfile -File "E:\development\projects\copilot\federated-copilot-codex\scripts\copilot\store-direct-line-secret.ps1" -BindCurrentAgent
```

Paste into the hidden prompt, not chat. There is no need to regenerate a secret or change authentication/security settings. If that page/secret is unavailable, report the available field labels instead of substituting a PF client secret, SDK credential or token.

The helper uses the protected current-user/SYSTEM directory, stores the channel secret in the existing credential file and records an exact tenant/environment/bot/schema tuple plus SHA-256 credential digest in a separate private receipt. A missing/malformed receipt, changed target or changed credential fails closed. The receipt is an **operator assertion of provenance**, not cryptographic proof of remote bot ownership and not a grant of delegated authority. Live channel sender/challenge inspection is still required. Changing an agent record or credential cannot silently carry forward an old receipt.

After saving, the authorized probe can generate one conversation-scoped token, start one conversation and observe sanitized OAuth-card metadata. It must not automatically post a PF token to the observed SAS URL. A distinct tool-audience token, mandatory online policy, original human/actor/grant/mode checks and protected tool-side acceptance remain separate requirements.

## Repeat discovery or run the gated probe

```powershell
npm run copilot:probe -- --discover-only
npm run copilot:probe
```

Discovery does not read a secret. The full diagnostic checks the target receipt before network operations, then checks the saved credential digest before credential use. It has no mock fallback. It remains a transport diagnostic and cannot establish PF delegation or authorization.

Validation: 135 baseline tests pass, including thirty route/probe tests and eleven credential-binding tests; all 228 production tests pass. New production tests exercise exact-path success and rejection of sibling/child/case/encoded path substitution, wrong host, missing/duplicate query parameters and ambiguous/malformed rule configuration before token issuance. Probe tests cover delayed challenges beyond an initial greeting, deduplication, altered replay, a card without a token-post resource and bounded empty polling. The Windows helper previously passed five non-elevated fixture checks. Tool client enablement, Microsoft configuration, public ingress and Graph access were not changed.

Polling now carries forward the opaque watermark, validates/deduplicates activity IDs and waits for an OAuth card rather than stopping on a greeting. It performs at most thirty reads, waits one second between reads and stops starting new reads after a 45-second polling deadline; a final in-flight request retains its ten-second deadline. It submits only one greeting event and one fixed status message, never retries POSTs and never follows card buttons or posts an access token. The user identity used for Direct Line is random and is not delegated authority.
