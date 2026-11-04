# Copilot diagnostic credential protection checkpoint

Status on 1 November 2026: **credential logging protection remains UNVERIFIED; user-approved PoC exception continues**. After two failed automated tool attempts and the provider-header repair, the separately approved third attempt [verified interactive delegated execution](copilot-interactive-tool-success.md). All three allowances are consumed. Successful execution does not establish redaction or production approval.

The user explicitly instructed continuing the existing design because this is a PoC. That exception permits the existing token-bearing tool argument despite unverified Microsoft trace protection; it does not establish redaction, approve production, permit credentials in local logs/chat, change trust validation or increase the one-conversation/one-token-POST allowance. The diagnostic draft was restored under this exception. The historical containment below describes the preceding blocked checkpoint. Local approval receipt: `.local/copilot/relay-microsoft-review/poc-risk-exception.json`.

The imported connector and secure maker connection exist. The operator confirmed that the provider-token tool input has no Sensitive data, Secure input or masking control. The proposed mapping is a manual expression from `System.User.AccessToken`; the request body is fixed `{}`. The installed Microsoft object model marks that system variable read-only, not externally initializable and hidden from AI context. These properties establish neither transcript nor connector trace redaction.

Microsoft's [sensitive-data documentation](https://learn.microsoft.com/en-us/microsoft-copilot-studio/voice-sensitive-data) lists tool actions and generative orchestration as unsupported for redaction. It also says marking a variable through variable-management actions alone does not provide redaction. Absence of an input control does not itself prove a token was logged. No real credential was sent through this diagnostic to investigate it.

## Current containment

The draft TaskDialog has `triggerCondition: =false`. Its exact-trigger topic is replaced by the fixed blocked response in `infra/copilot/verify-delegation.blocked.topic.mcs.yml`, with no connector invocation or credential access. The intended mapping/topic candidates remain separate review artifacts. The previous published agent is unchanged. Do not publish or run a real-token test until the protection gate is resolved; do not reuse or reset historical test allowances.

## Question for Microsoft

For a published standard-harness Copilot Studio agent using Generic OAuth 2 with PingFederate, does a custom connector TaskDialog `ManualTaskInput` whose value is exactly `System.User.AccessToken` receive built-in credential redaction in conversation transcripts, DialogTracing, Application Insights and tool/connector execution traces? The input has no Sensitive data or secure-input setting. The system variable is hidden from AI context, but the public sensitive-data documentation lists tool actions as unsupported. Please identify the supported credential-protection mechanism and its exact scope, including whether diagnostic/test-pane traces differ from published-channel traces. No token values or signed URLs are needed to answer this configuration question.

Do not interpret Hidden AI visibility, an OpenAPI advanced/internal flag, or a password UI hint as a logging guarantee. Do not send a real token merely to see whether it leaks.

## Alternative to evaluate if this mapping is unsupported

A connector can use its own OAuth authentication and a user connection instead of exposing an access token as a tool argument. Microsoft documents [tool user connections and channel support](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-enduser-authentication). This is a different flow: it can issue a different PF token and require separate sign-in/consent. It does not automatically prove continuity with the exact token posted to the original OAuth card. Our current relay deliberately requires that exact binding.

Before adopting that alternative, review the PF client/callback, user-connection channel support, secure credential injection, independent human/agent/grant binding and autonomous behavior. Keep the current relay fail-closed. Do not substitute a maker's PF user token, trust a conversation ID as authority, remove provider verification, or claim the original token-continuity test passed. A Power Automate wrapper with secure inputs cannot by itself protect the preceding Copilot tool argument.
