# Instrumented Microsoft diagnostic result

User-facing date: 1 November 2026 Australia/Sydney. Platform timestamps below are UTC.

Run: `f1393311-cc38-43bf-92a5-d1160ecfef4b`.

| Check | Result |
|---|---|
| New conversation / token POST | Exactly one each; allowance consumed |
| Provider token POST | HTTP 200; Microsoft request ID `193b367c7617d4059be73523b80099e5`, server time 2026-10-31 14:52:00 UTC |
| Runtime signed-in diagnostic | Passed |
| Fixed connector-started marker | Observed |
| Fixed connector-returned marker | Not observed |
| Published platform error response | Observed |
| Exact platform error code | Not retained: outside the runner's fixed recognized categories |
| Tool policy decisions for this grant | Zero |
| Delegated tool acceptance | **UNVERIFIED** |
| Cleanup | Passed: owned grant revoked, PF B client disabled, prior grants/budgets preserved |
| Managed services | Remained ready |
| Graph requests / local raw credential retention | Zero / none |

The deterministic topic entered the connector invocation and failed before returning. This rules out absence of topic entry in this run. It does not identify whether the platform rejected the dialog invocation, input mapping, connection, connector request, or an early relay authentication check. Do not claim the relay received the operation or that the connector credential was invalid solely because no tool-policy decision exists.

The two final activity polls returned HTTP 200. Their Microsoft request IDs were `6695f862cffa8f6714c60c3ceffc11d4` at 14:52:02 UTC and `60d83ab39b0c3cb72a4a34c1d018bf9d` at 14:52:03 UTC. These IDs identify Direct Line activity retrieval responses; they are not asserted to be the internal connector execution request IDs.

## Existing-evidence investigation

A read-only exact timestamp query for this agent between 14:51:40 and 14:52:20 UTC currently returns no transcript. Recheck with `node scripts/copilot/inspect-tool-transcript.mjs --followup-1` when the existing record becomes available. This only reads existing data and cannot open a conversation or post a token. The inspector keeps raw content in memory and emits fixed categories/markers.

Later read-only inspection on 1 November 2026 Australia/Sydney retrieved the exact-window transcript with the diagnostic user turn. Fixed-category projection found **ConnectorAuthorizationError** and **Unauthorized**. This retrospectively identifies the published failure category, matching the operator's separate Test-pane category; no additional live conversation was run. The original runner receipt remains unchanged with its historical `unclassified` value. See [credential-free relay header diagnostics](relay-header-diagnostics.md) for the pending delivery investigation.

For Microsoft support, ask for the underlying platform/connector error corresponding to this agent and time window, using the polling request IDs above as correlation candidates. Explain that sign-in succeeded and a deterministic before-call marker was emitted, followed by the published generic error without the after-call marker. Share no provider token, Direct Line credential, connection key or secure OAuth-card URL. No support message has been sent automatically.

Local evidence: `.local/tool-vault/microsoft-tool-f1393311-cc38-43bf-92a5-d1160ecfef4b/verification.json`. Approval and publication receipts: `.local/copilot/relay-microsoft-review/followup-1-approval.json` and `publication-followup-1-confirmation.json`. Consumed allowance: `.local/copilot/live-sso-tool-diagnostic-followup-1-budget.json`. Do not delete/reset either consumed tool ledger or automatically retry.
