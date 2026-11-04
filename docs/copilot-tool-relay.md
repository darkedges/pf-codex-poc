# Copilot provider-to-delegated-tool relay — local preparation

Transport follow-up: the [HTTPS/lifecycle composition](copilot-tool-relay-hosting.md) now implements strict inbound parsing/admission, a pinned private mTLS client and optional Direct Line binding/close hooks. The composed loopback tests pass. These factories are not deployed into the running controller; actual tenant/container tool invocation remains UNVERIFIED. Statements below about missing transport describe the initial core milestone and its remaining deployment requirements.

The interactive PF A sign-in/token POST now succeeds; see [the successful run](copilot-sixty-minute-success.md). The token available to Copilot is a human-login credential, **not a PF B delegated tool token**. This relay prepares the missing correlation boundary without granting authority from a prompt, user ID header or body parameter. **Actual Copilot-originated tool invocation is UNVERIFIED.** No listener, tenant tool, connector credential, new public route or Microsoft conversation is created by this milestone.

## Fixed flow

1. The trusted broker selects an active registered agent/grant through its existing authenticated workflow. It calls `ProviderToolRelay.bind` internally with the broker token and exact PF A user token destined for that session. There is no HTTP registration route.
2. The relay independently verifies both tokens, requires an issuer-qualified provider-to-broker identity mapping, checks current broker policy and writes a credential-free audit event. It stores a SHA-256 fingerprint of the exact provider token and the verified broker context in memory. It never indexes by a client-supplied human, grant or conversation ID.
3. A dedicated connector connection supplies its independently enrolled connection key. Copilot supplies its authenticated PF A token through a fixed system-variable expression. The only request body is `{}`.
4. The relay authenticates the connection to its configured caller, atomically consumes the exact-token binding, re-verifies user proof and mapping, checks current broker policy, and requests a fresh tool token from a server-composed issuance dependency.
5. A separate tool verifier checks the PF B signature/issuer/audience/lifetime. The relay compares human, actor issuer/subject, organisation, delegation ID, interactive mode and scope with its stored broker context. It invokes only the configured private `verify-access` diagnostic, then rechecks current broker authority and all expiries before returning `{"authorized":true}`.

The provider audience is `api://copilot-login`, broker audience comes from the trusted exchange profile, and tool audience is `api://copilot-tool`. Scope/resource selection belongs to the composition root and existing policy. No Graph call is made. A one-hour login token cannot extend the binding: it lasts at most 120 seconds and ends earlier with the broker/provider credential. Close/invalidation cancels in-flight result release. The separate tool proof is limited to 120 seconds, and broker JWTs to 300 seconds.

Bindings are single-use even after issuance, policy, audit or downstream failure. No POST retry occurs. In-flight callbacks receive cancellation and must honor it; timeout withholds results but cannot undo an external action that already completed. This milestone therefore exposes only a read-only diagnostic. Short expiry timers clear broker credentials; remaining replay tombstones contain only a hash/deadline until provider expiry. Capacity is bounded at 1000 entries. State is process-local: restart loses authority and requires a fresh provider token/session. Replicated/persistent replay state is a deployment gate.

## Connector draft and transport mapping

[OpenAPI draft](../infra/copilot/tool-relay.openapi.draft.json) uses a deliberately non-resolving `.invalid` host. It is not an import/deployment instruction for the live agent. Its one route is:

```http
POST /v1/copilot-tools/verify-access
Content-Type: application/json
X-Copilot-Connection-Key: <separately enrolled connection credential>
X-PF-User-Access-Token: <System.User.AccessToken>

{}
```

The future HTTPS transport must reject duplicate credential headers, queries, forwarding-identity overrides and oversized bodies; disable caching and credential/body logging; enforce admission limits; and map the provider header to `ProviderToolRelayApi.authorization` as `Bearer <value>`. The relay API is an in-process factory only and does not yet perform HTTP/TLS parsing. The existing private tool continues requiring its approved mTLS workload, tool JWT and independent PDP; the relay must use separate enrolled outbound credentials.

`connectionKeyAuthenticator` compares a SHA-256 digest in constant time and returns only its configured caller ID. The composition root must load that digest from protected Vault custody, while Power Platform holds the original key in the dedicated connection. No real credential is generated or enrolled yet. The key authenticates possession of that connection credential; it is not cryptographic attestation of a Microsoft tenant or of arbitrary callers that know it. Pinning the exact provider token to a separately verified broker context supplies the independent delegation restriction.

Microsoft documents [HTTP request headers](https://learn.microsoft.com/en-us/microsoft-copilot-studio/authoring-http-node) and [generic-provider tokens in System.User.AccessToken](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-sso-3p). Those documents support the proposed carrier pattern, not this connector's live behavior. Before import/publication, confirm that the selected connector/action can bind the header to that system variable deterministically and prevent raw credentials from entering model-selected inputs, transcripts, run history or telemetry. An OpenAPI visibility annotation alone does not provide credential secrecy. If secure handling cannot be established, keep this path disconnected.

## Composition and remaining review

`src/copilot/provider-tool-relay.ts` requires explicit broker/provider/tool verifiers, identity mapping, connector authentication, online broker policy, tool issuer, fixed downstream invocation and audit sink. The registration and invalidation methods are internal broker lifecycle hooks. This milestone does **not** wire them into the running Direct Line adapter/controller or enable the PF B client; a production composition must register only the exact token held by the session, invalidate on session close, issue under the approved registry authority and preserve signal/deadline handling. Missing dependencies fail at construction; there is no mock fallback.

Before requesting public-route approval, prepare a concrete loopback/mTLS hosting composition, exact hostname/path, Vault connection-key/outbound identity enrollment and egress restriction, secure ingress transport, independent operations/audit custody and rollback. No hostname is selected from a request. The connector secret must not be hardcoded into a topic. A live test needs separate explicit authorization because all nine conversation reservations are consumed.

## Tests and live acceptance plan

Current verification: **297 baseline and 361 production tests pass**, including the initial 27 relay tests and later transport/lifecycle checks. No real PingFederate/tenant relay integration, public listener or Microsoft request was performed for these milestones.

The signed-JOSE local contract tests prove the full binding-to-fixed-result path and negatives for unbound/equivalent-but-different tokens, caller substitution, wrong human/actor/org/grant/mode/audience/scope, duplicate/concurrent replay, session close, revocation before/during work, expiry, malformed routes/body, audit failure and issuance timeout. These tests inject local policy/issuance/operation dependencies and are **not** a real-container relay test or evidence of Copilot execution.

After secure composition and approvals, use one fresh token/conversation, register only its exact broker binding, and have a deterministic Copilot action call the relay with its system token and separate connection credential. Require both authoritative relay/tool audit and the fixed runtime result; bot prose alone is insufficient. Verify the exact token's fingerprint internally without printing it. Under separately bounded attempts, reject missing/wrong connection keys, unbound/substituted user tokens, body authority, consumed binding, expired proof, revoked grant and PDP failure. Prove owner revocation denies both existing proof and new issuance. Test autonomous provider SSO only after an independently verified unattended provider capability exists; it remains unsupported here.
