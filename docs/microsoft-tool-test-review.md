# Microsoft delegated-tool test — activation review

The managed local relay is ready. A separate gateway test process delivered a signed, mutual-TLS-authenticated broker/agent/human/provider bundle to the running relay; the relay used Vault-backed credentials and real PF A/B to invoke the private Docker diagnostic. The successful local run finished on 31 October 2026 at 09:03:21 UTC and passed 11 checks, including identity continuity, one-use binding, owner revocation, unchanged Microsoft allowances and continued service readiness. Evidence: `.local/tool-vault/managed-relay-test-aff93d98-668e-4b24-8ec5-ce99adb05a3d/verification.json`.

## Approval requested

Approve these bounded changes as one Microsoft PoC step:

1. Add exactly one proxied CNAME, `relay.copilot.darkedges.com`, targeting the existing `federated-copilot` tunnel `a979d27b-f2cd-45cf-aada-b44c850e3a0e.cfargotunnel.com`. Refuse to overwrite a conflicting existing record.
2. Add only the exact `/v1/copilot-tools/verify-access` ingress to `https://127.0.0.1:9464`, with origin hostname `localhost` and CA verification enabled. The application accepts POST only. A host-specific deny rule blocks all other paths, including the private `/v1/internal/relay/proofs` route. Existing PF A/B ingress remains unchanged. No TLS bypass or wildcard DNS/route is proposed.
3. Import the prepared diagnostic connector and attach it to the existing **Federated Delegation Test** agent, then publish after deterministic sensitive input handling is verified.
4. Reserve and run at most **one new Direct Line conversation, one secure token POST and one successful delegated diagnostic operation**. Do not overwrite historical allowance ledgers or automatically retry the runner. Create at most one owned synthetic grant, revoke it afterward, and restore the dedicated PF B exchange client to disabled.

No Graph/SharePoint access, external Entra user provisioning, tenant-wide permission, new billing policy, subscription, support-plan purchase or additional Azure service is included. Existing billing arrangements remain unchanged. The test uses the previously selected PoC budget; the one-attempt limit is an execution limit, not a claim about a billing hard cap.

Applying the local tunnel configuration may require a connector restart and briefly interrupt the existing PF routes. Preserve the current file and verify its hash first; rollback restores that exact file and removes only the new relay DNS record.

## Prepared files

- Import candidate: `infra/copilot/microsoft-tool-test.openapi.json` (also copied into `.local/copilot/relay-microsoft-review/connector.openapi.json`).
- Exact proposal: `infra/copilot/microsoft-tool-test.review.json`.
- New ingress fragment: `infra/cloudflare/relay-ingress.review.yaml`.
- Full tunnel candidate: `.local/copilot/relay-microsoft-review/tunnel.review.yaml`.
- Source/candidate hashes and current managed instance: `.local/copilot/relay-microsoft-review/manifest.json`.

Preparation has not applied the route, changed DNS, imported a connector, published the agent or reserved a new Microsoft attempt. Before applying, compare the active tunnel hash with the manifest and refuse unexpected drift. Before the live test, recheck current service/lease readiness and the actual published connector mapping. If TLS, mapping, credential secrecy, license/connection ownership or publishing checks fail, stop before opening a Microsoft conversation.

## Connector configuration

Target tenant: `4161be3f-bf2b-41d4-a02b-e6f82b529d53`.

Target environment: `c72f8bf6-020d-e210-8662-fa461a415ec2`.

Target agent: `cra8f_FederatedDelegationTest`, Dataverse ID `1d18f6de-66d3-f111-a05b-6045bd40333e`.

The operation is **VerifyDelegatedAccess**. Its only business result is `{authorized:true}`. Use a maker-provided API-key connection for `X-Copilot-Connection-Key`; obtain the value directly from Vault record `federated-copilot-tool-secrets/relay-connection` without putting it in chat, configuration exports or command arguments. The relay itself holds only the enrolled SHA-256 digest.

Override `X-PF-User-Access-Token` using **Custom value**, derived deterministically from `System.User.AccessToken`. Use sensitive-variable handling: if the tool cannot mark that system input as sensitive directly, assign it to a sensitive topic variable and bind that variable with a fixed Power Fx expression. Never let generative input filling, a question or chat supply it. The required request body is the internal fixed empty object `{}`; it has no grant, identity, scope or resource inputs. Confirm the imported connector preserves that default. Return only a fixed success/failure message and the Boolean result. Do not emit the token or serialize the entire tool result/debug context into chat.

Microsoft documents [custom input overrides](https://learn.microsoft.com/en-gb/microsoft-copilot-studio/add-tools-custom-agent), [custom connector/maker credentials](https://learn.microsoft.com/en-us/microsoft-copilot-studio/copilot-ai-plugins), [internal OpenAPI defaults](https://learn.microsoft.com/en-us/connectors/custom-connectors/openapi-extensions), and [sensitive variable handling](https://learn.microsoft.com/en-us/microsoft-copilot-studio/voice-sensitive-data). These describe the supported setup, not verification that this agent's imported tool is configured correctly. Connector/flow destinations need their own redaction; if an agent-flow wrapper is needed, secure its inputs/outputs. Keep local and edge request/header/body tracing disabled or redacted. Do not send a real token until those settings are confirmed.

After publishing, the bounded test must use a fresh conversation/OAuth card, post the correct PF A configured-provider token to its exact secure URL, register that same token with independently verified broker/agent/human evidence through the private gateway, then trigger the fixed diagnostic topic. A signed-in message alone is not success. Evidence must show the Copilot-originated callback, fixed tool success and independent policy audit retaining the original human, agent, organisation, grant, mode, audience and resource. Copilot tool acceptance remains **UNVERIFIED** until that happens.

## Managed PoC service and rollback

The relay runs under the selected Windows account. The controller owns a separate application process and a credential-free TCP forwarder; the application executes no Docker command. Listeners are only `127.0.0.1:9464` (callback), `127.0.0.1:9465` (private mTLS control plane) and `127.0.0.1:9481` (end-to-end TLS to the private tool). The forwarder joins the existing private network and Docker bridge so Docker Desktop can publish its loopback port; it has no credentials or Docker socket and forwards only to tool-api:8443. This is a bounded PoC transport, not an egress firewall or production OS isolation.

The relay reads existing OAuth/workload client keys from the dedicated limited Vault record `relay-authority-runtime`; the gateway's new TLS/JWT private credentials stay in operator-only `relay-gateway-client`. No agent signing key is enrolled in the relay. Its provider binding requires the exact user token in the signed private bundle; that token alone carries no tool authority. Bind failure, completion-audit failure, timeout, disconnect and shutdown erase or invalidate provisional authority. Audit retention is one day with the existing size cap. Shutdown prunes expired whole journal files; no offline deletion or automatic service restart is scheduled.

Commands: `node scripts/vault/managed-relay-service.mjs --status`, `--stop`; restart explicitly with `pwsh -NoProfile -File scripts/vault/start-relay-hidden.ps1`. The relay also stops when the parent/controller disconnects, its dependencies/config drift, its lease ends or the underlying tool instance changes. Interrupted/foreign ownership leaves locks for review. Crash recovery and production promotion remain gates; the existing production deployment review stays disabled.

The current managed PF rejection was diagnosed as a signed PF A token with iat/nbf one second in the future. Verified credentials now wait at most five seconds, within the operation deadline, until they are actually valid, then undergo the same strict time and expiry checks. No clock, expiry, signature or issuer checks were relaxed. This local correction does not establish the cause of historical Microsoft token-post HTTP 400 responses.

Rollback removes only the new relay ingress/DNS and the diagnostic connector/tool, restores the prior published agent if necessary, stops the managed relay, revokes only the test-owned grant and restores PF B disabled. Existing PF A/B routes and all historical Microsoft evidence/allowances remain untouched.
