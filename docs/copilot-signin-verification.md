# Verify the live Copilot sign-in state

## Result — 2026-10-30 (Australia/Sydney)

The operator returned the diagnostic's exact positive message: **Authentication status: signed in. Copilot reports User.IsLoggedIn=true. Delegated tool access has not been verified.** Record this as operator-observed execution of the live sign-in diagnostic after opening the exact current agent. Together with the reported PF login, Microsoft validation-code step and resumed conversation, this completes the manual sign-in/runtime-Boolean checkpoint. The assistant did not directly inspect the activity map or user token. It does not prove JWT claim extraction inside Copilot, token-post SSO, expiry behavior, actor/grant binding or protected tool acceptance.

On 2026-10-30 (Australia/Sydney), the operator reached Microsoft's validation-code step and reported that entering the code resumed the agent greeting. This is operator-reported manual sign-in progress. The greeting alone is not evidence of the runtime authentication flag, token validity, delegated tool authority or autonomous SSO.

## Published diagnostic

The dedicated topic [FederationStatus](../infra/copilot/topics/FederationStatus.mcs.yml) was added to the current **Federated Delegation Test** agent using the pinned project-local PAC 2.14.1 clone/push/publish workflow. The exact target is the existing approved Sandbox `c72f8bf6-020d-e210-8662-fa461a415ec2`, current bot `1d18f6de-66d3-f111-a05b-6045bd40333e`, schema `cra8f_FederatedDelegationTest`.

PAC reported exactly one pushed change and successful publication. A subsequent pull confirmed the topic matches the committed source and all existing topics are byte-identical to the private pre-change snapshot. The settings file changed after publication and reports `GenericOAuth2`, `Always` and a publication timestamp; it is not claimed byte-identical. No authentication setting was submitted by this change. Protected private receipts and the CLI workspace live under `.local/copilot`.

The diagnostic branches only on the runtime Boolean `System.User.IsLoggedIn = true`. It emits fixed text and uses the failure branch when that expression is not true. It does not read, decode, log, display or transmit `User.AccessToken`, make an HTTP/tool call, infer identity from a prompt, or grant access to a resource. Existing authentication and sign-in system topics remain in place.

Routing correction: the first version used `OnRecognizedIntent`, and the operator received a free-form answer about an identifier rather than either fixed diagnostic message. That answer is not evidence of authentication failure or of an actual session-record lookup. The replacement uses `OnActivity` / `Message` with priority -1 and a condition allowing only the normalized exact command `/federation-status`, `verify federated sign in`, or `check federation sign in status`. It cancels other topic dialogs for that command. It does not change agent-wide orchestration. Microsoft's [trigger documentation](https://learn.microsoft.com/en-us/microsoft-copilot-studio/authoring-triggers) describes message triggers running before intent selection. Runtime routing still requires observation in the actual tenant.

The operator still received free-form text after the routing correction. A read-only Dataverse check confirms the diagnostic component is Active, published component state 0, and attached to current bot `1d18f6de-66d3-f111-a05b-6045bd40333e`, alongside the active Sign in system topic. Do not assume that the operator's test pane is bound to that same bot/runtime merely because the display names match. Before any further source edits, open the [exact current agent](https://copilotstudio.microsoft.com/environments/c72f8bf6-020d-e210-8662-fa461a415ec2/bots/1d18f6de-66d3-f111-a05b-6045bd40333e/overview) and verify **Topics → Federation sign-in status** is visible and its activity-map nodes execute. Absence of that topic/UI is a context/harness diagnostic, not proof of failed user authentication. No further routing, authentication or orchestration changes were applied after that metadata check.

## Run in the existing signed-in test chat

Refresh the Studio editor if necessary to load the published topic, then send:

```text
/federation-status
```

The positive branch's exact message is:

```text
Authentication status: signed in. Copilot reports User.IsLoggedIn=true. Delegated tool access has not been verified.
```

The negative branch's exact message is:

```text
Authentication status: not signed in or unavailable. Copilot has not reported User.IsLoggedIn=true. Delegated tool access has not been verified.
```

Refresh Studio to load the updated topic before testing; sign in again if prompted. Use Studio's activity map to confirm **Federation sign-in status** and the condition node actually ran; a generative answer copying the words is not sufficient. Microsoft documents [the sign-in Boolean and both branches](https://learn.microsoft.com/en-us/microsoft-copilot-studio/advanced-end-user-authentication). No token or validation code should be copied into chat, diagnostic messages or screenshots.

## Pending evidence and next gates

- **Operator observed:** the positive diagnostic response in the live signed-in session. Direct assistant inspection of the activity map/user session remains unavailable; the negative branch has not been exercised live.
- **UNVERIFIED:** negative/cancelled sign-in behavior, login-token expiry and fresh reauthentication. Keep sign-in required; do not disable it merely to reach a negative diagnostic branch.
- **UNVERIFIED:** reconciliation of the current agent's channel credential/bot sender identity with earlier old-schema Direct Line receipts. Do not reuse old transport evidence as current-agent verification.
- **UNVERIFIED:** actual separately audienced PF delegated-token delivery, actor/grant continuity, tool-side verification/online policy and autonomous execution. A true login flag is not delegated authorization. The PF B tool client remains disabled.

After the runtime flag is observed through the condition node, reconcile the current channel binding and observe the actual OAuth challenge contract before any secure token-post test. Protected tool requests must still use independently validated audience-specific evidence and online grants. Graph and SharePoint remain disconnected.
