# Direct Line adapter — local implementation, live tenant UNVERIFIED

Current correction (2026-10-31): the actual Microsoft Generic OAuth token-post endpoint requires a [configured-provider user-token flow](copilot-provider-token-fix.md). PF A user sign-in proof is separate from PF B broker/tool delegation. All 288 baseline and 315 production tests pass. One subsequently authorized [corrected-provider cURL capture](copilot-provider-capture.md) returned HTTP 400 with actual body `"Token is expired"`; Microsoft acceptance remains UNVERIFIED. Earlier validation counts below are historical.

Live update: the [separate channel diagnostic](copilot-channel-probe.md) now passes real missing/invalid-credential tests and one conversation/greeting. This does not exercise the production adapter's PF/PDP composition or establish Generic OAuth federation. The current agent uses Integrated authentication, and its supplied URL is an authenticated runtime endpoint rather than a Direct Line token route.

Implemented a typed REST adapter, environment/credential-file composition, and an HTTPS API factory. The default simulation remains separate. No Microsoft tenant settings were changed and no real Copilot conversation was created. The API factory does not open a listener; deploying it requires the verified identity/policy/SSO dependencies described below.

Validation (2026-10-29): **85 Copilot adapter/API/configuration tests**, **197 total production tests**, and **85 baseline tests** pass. Transport tests use simulated Microsoft responses with real ephemeral JOSE-signed identity tokens. They establish local contracts, not Copilot tenant support.

## Identity and credential boundaries

```mermaid
sequenceDiagram
  participant G as Gateway 2
  participant C as Copilot integration service
  participant P as Verified PF trust + online policy
  participant D as Configured Direct Line endpoint
  participant I as Approved fresh SSO token issuer
  participant S as Approved secure token-post endpoint
  G->>C: PF B token (aud api://copilot-broker)
  C->>P: Verify signature/audience/time and current grant
  C->>D: Generate per-conversation token using server-only channel secret
  C->>D: Start conversation using its channel token
  C-->>G: Opaque local handle, awaiting_oauth
  G->>C: Send/poll with fresh verified broker evidence
  C->>P: Recheck owner, actor, organisation, grant, mode and policy
  D-->>C: Bot OAuthCard within the bound conversation
  C->>I: User token from configured OAuth provider and login audience/scope
  I-->>C: Subject-only provider user access token
  C->>C: Verify provider token and trusted binding to delegated broker identity
  C->>S: POST token only to approved SAS destination
  C-->>G: token_posted; no challenge-batch messages
  Note over C,S: HTTP success is not proof of tenant/tool authentication
```

Direct Line channel credentials and end-user identity are different boundaries. The master channel secret is used only for token generation. Subsequent requests use the conversation token; refresh occurs before expiry. The adapter generates an unpredictable `dl_` user ID and configured trusted origins rather than placing human/agent/grant claims into channel metadata. This follows [Direct Line authentication](https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-direct-line-3-0-authentication). [Copilot web-channel security](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-web-security) must also be enabled in the actual agent; a channel secret is not end-user authentication.

The adapter stores the immutable binding server-side: verified token issuer/audience, original human, actor issuer/subject, organisation, delegation, mode and scope. Fresh broker tokens can change issuance times/jti, but cannot change that binding. Every operation verifies the presented broker token and current online policy. Outbound requests recheck before transmission and after response processing. Revocation prevents result release even after a successful remote request. As with the PF adapter, an already transmitted side effect cannot be rolled back; actual protected tool calls need their own current-grant check.

Generic OAuth SSO needs the configured provider's **user access token**, not the incoming broker JWT or separate tool JWT. Explicit `providerSso` configuration pins issuer/audience/scope/lifetime; the provider verifier and trusted issuer-qualified identity binding are mandatory. Full human/actor/org/grant/mode authority remains bound server-side to the broker session and separately verified tool JWT. Autonomous provider sign-in is currently unavailable and fails before channel egress. Missing verifier/binding/policy fails closed; no delegated token fallback exists. See the [mismatch correction](copilot-provider-token-fix.md).

## OAuth challenges and egress

Current live challenge observation (2026-10-30 Australia/Sydney): a current-agent, operator-bound Direct Line probe received the documented OAuth card with exact token-post path `/api/sas/postToken` on `https://token.botframework.com`, and query names `expiry`, `hmac`, `id`, `state`. The adapter supports `pathExact` for this single endpoint alongside existing directory `pathPrefix` rules; exactly one is required. The [Microsoft rule fragment](../infra/copilot/microsoft-token-post.example.json) pins that observation. Contract tests cover both rule styles and reject path substitution before issuing any SSO token. No live token POST or tool acceptance has yet been verified; see [current channel evidence](copilot-current-channel.md).

The generic OAuth flow uses an `application/vnd.microsoft.card.oauth` attachment's `content.tokenPostResource.sasUrl` and an HTTP JSON body `{ "token": "..." }`. Microsoft documents the posted token becoming available in `System.User.AccessToken`; that must be proven for this PF-backed flow in the tenant. See [generic OAuth SSO](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-sso-3p). This adapter implements that POST pattern, not an Entra token-exchange invoke flow.

Only a configured bot sender in the bound Direct Line conversation/channel can supply a challenge. The complete activity batch is validated before any credential is posted. Destination rules require an exact configured HTTPS origin, approved path prefix and required query parameters. IP/localhost origins, userinfo, fragments, duplicate query parameters, encoded path traversal and redirects are rejected. The SAS URL supplies neither token audience nor scope. Token POSTs contain no Direct Line Authorization header. The response `streamUrl`, sign-in buttons and other URLs are never followed.

`awaiting_oauth` returns no bot messages until a valid challenge is processed. The challenge batch is withheld even after POST success. `token_posted` means only that this protocol step completed; it does not assert that Copilot authenticated the user or that a tool accepted the token. A missing/failed challenge never yields protected replies or triggers an unauthenticated fallback. SSO expiry requires a new conversation. The tool API must verify the actual received token and current grant; it cannot trust this channel state, bot text or conversation ID.

Duplicate identical activities are ignored. A reused activity ID with changed content fails closed. Canonical SAS URL hashes prevent repeated token posting, including query reordering, across conversations in the same adapter process. The vendor must also enforce SAS expiry and conversation/connection association; exact tenant URL shape and cross-session behavior remain live checks.

## Composition and configuration

| File | Responsibility |
|---|---|
| `src/adapters/copilot.ts` | Typed adapter, dependency and sanitized error contracts |
| `src/adapters/direct-line.ts` | Conversation/token lifecycle, owner binding, OAuth handling and polling |
| `src/adapters/copilot-env.ts` | Explicit Direct Line selection and secret-manager mounted file reader |
| `src/copilot/api.ts` | Closed API routes; no caller identity/resource/token-destination fields |
| `src/copilot/server.ts` | TLS server factory with request/header/body limits and no automatic listener |
| `infra/copilot/direct-line.example.json` | Public configuration template; tenant URL/audience/query fields are placeholders |

Set `COPILOT_MODE=directline`, exactly one of `COPILOT_DIRECT_LINE_CONFIG` (public JSON) or `COPILOT_DIRECT_LINE_CONFIG_FILE` (absolute path), and `COPILOT_DIRECT_LINE_SECRET_FILE` (absolute secret-manager mounted file path). Keep credentials out of config JSON, source files, prompts and logs. The file is read for token generation so operator-managed channel-secret rotation can take effect; callers never receive the secret or conversation tokens. Startup rejects missing/invalid configuration and empty/missing credential files. `NODE_TLS_REJECT_UNAUTHORIZED=0` is refused.

The example's `.invalid` origins, bot ID, tool audience, path and `sig` parameter must be replaced from approved tenant evidence. They are not asserted Microsoft endpoint formats. Pin the actual regional Direct Line endpoint and token-post destination; never use a wildcard origin or derive configuration from a request/OAuth-card resource field.

The host must compose `directLineFromEnvironment` with a production broker verifier, separate SSO verifier, independently authenticated online policy client bound to an approved resource, and an approved fresh-token issuer. `CopilotApi` then wraps that adapter; `createCopilotServer` wraps the API with secret-manager supplied TLS credentials. Any local host should listen explicitly on `127.0.0.1`; no new host was started in this milestone. Gateway mTLS/workload ingress authentication and production hosting are separate deployment gates. The existing demo broker intentionally still refuses real Copilot mode.

## API and lifecycle

Every route requires a verified PF B bearer through the adapter. Handles are local opaque UUIDs, not caller-selected Microsoft conversation IDs.

| Method/path | Body | Result |
|---|---|---|
| `POST /v1/conversations` | `{}` | Handle, protocol state and expiry |
| `POST /v1/conversations/{handle}/messages` | `{ "text": "..." }` | Submission acknowledgement |
| `GET /v1/conversations/{handle}/activities` | None | Protocol state and filtered text messages |
| `POST /v1/conversations/{handle}/refresh` | `{}` | Same handle with updated channel expiry |
| `DELETE /v1/conversations/{handle}` | None | Local session invalidation |

Extra body fields, arbitrary paths/query parameters and duplicate authorization headers are rejected. Messages are plain bounded text, with no client-supplied actor, channel metadata, attachments, scopes or resource. Bot text is untrusted data: render it as text and never execute it or use it as authorization. Known credentials and compact JWTs are redacted from returned text; no credential fields, raw OAuth cards or SAS URLs are returned.

Polling tracks the opaque watermark and deduplicates activities; null cursors retain the previous value, consistent with [Direct Line activity retrieval](https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-direct-line-3-0-receive-activities). Only read-only failures retry, once, with fresh policy checks. POSTs never retry automatically; ambiguous failures invalidate the local session. No remote logout/revocation guarantee is claimed by local DELETE.

All remote calls, secret reads and SSO issuance callbacks have deadlines. Sessions have fixed maximum lifetime, channel/SSO expiry, bounded activity/credential sets, concurrency locks and reserved opening capacity. Replay/conversation tombstones are bounded to 10,000 entries with 24-hour retention. State is single-process memory; restart invalidates local handles. Expired sessions are removed on use/open. HA/shared replay state, encrypted distributed credential custody, background retention operations, ingress quotas and tenant polling cadence need deployment work. Telemetry contains only operation, generic outcome and duration; the injected PDP supplies identity/grant audit. Neither request bodies nor endpoint URLs are logged.

## Live tenant verification plan — UNVERIFIED

Publication update (2026-10-29): read-only `pac copilot list` against the approved Sandbox now confirms **Federated Delegation Test** is Published/Active/Provisioned. Its exact tenant/environment/agent IDs are stored privately in `.local/copilot/published-agent.json`. Publication does not prove secured Direct Line, channel sender ID, Generic OAuth or interactive/autonomous federation. No channel secret has been requested in chat or retrieved into tool output.

For the Windows lab, open the published agent's Settings > Security > Web channel security and enable Require secured access. Microsoft says this change can take up to two hours and does not require republishing. Enter one channel secret into the hidden local prompt with `pwsh -NoProfile -File scripts/copilot/store-direct-line-secret.ps1`; the helper restricts `.local/copilot` to the current Windows user and SYSTEM, atomically stores `direct-line-secret.txt`, and makes no network call. Point `COPILOT_DIRECT_LINE_SECRET_FILE` at that absolute path when composing the adapter. Production still needs secret-manager mounts. Do not put secrets in CLI arguments, public JSON, source, logs or chat. Keep user authentication enabled separately; a secured channel does not establish human identity.

The published agent/environment is now identified, but no Microsoft credential reference or approved live channel/authentication configuration is available yet. Before a live run, verify exact endpoint/channel bot ID/approved origins, observed token-post route/query contract, separate PF tool-token audience/scope, and secure credential references. Do not paste secrets or captured SAS URLs into chat.

1. Confirm licensing/channel support, published agent, secured Direct Line, manual Generic OAuth settings and an approved PF B trust relationship. Do not create Entra identities for the external humans.
2. Configure a distinct short-lived PF tool/SSO issuance profile and verifier. Prove actor/human/grant/mode continuity and denial of broker-audience token substitution.
3. Start one conversation under real interactive consent and another under an active autonomous grant with no stale human token. Check actual OAuth card schema, sender and conversation IDs, SAS origin/path/signature/expiry and rejection of cross-conversation challenge substitution.
4. Verify `System.User.AccessToken` reaches a controlled authenticated tool without logging it. Verify signature/audience/identity and current grant independently at that tool. HTTP token-post success alone is insufficient evidence.
5. Test missing sign-in challenge, interactive-user-required responses in autonomous mode, denied SSO and tenant policy failures. If unattended authentication is unsupported, stop and record it; do not bypass sign-in.
6. Test channel refresh, SSO expiry, expired broker credentials, grant revocation/suspension before/during operations, channel-secret rotation/revocation, timeout/429/outage and local process restart.
7. Inspect tenant DLP, maker/run-only connection credentials, logs and traces for authorization bypass or credential exposure. Keep Graph/SharePoint disconnected until their separate app-only broker approval gate.

Run local contract checks with `npm run test:copilot`; the original baseline and full production suites remain `npm test` and `npm run test:production`.
