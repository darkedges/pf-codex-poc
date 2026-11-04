# Copilot Studio Generic OAuth callback failure — support evidence

**Historical failure:** the operator subsequently reached Microsoft's validation-code step and resumed the agent conversation after correcting the Token URL field. Do not submit this as a currently reproduced incident without a fresh failure. The exact root cause was not independently established. See [current sign-in verification](copilot-signin-verification.md).

Prepared 2026-10-30 (Australia/Sydney). This is a draft for the operator; it has not been sent to Microsoft.

## Trace to investigate

- Service: Microsoft Bot Framework Token Service, `GET https://token.botframework.com/.auth/web/redirect` (query deliberately omitted).
- Browser response status: **400 Bad Request**.
- Response JSON: `{"message":"Login failed","statusCode":500,"responseBody":""}`. The nested status is distinct from the browser response status.
- Response `x-ms-request-id`: `556469a5a1f2e2bd4477d845484b4f95`.
- Response Date: **2026-10-29 19:49:55 UTC**, equivalent to **2026-10-30 06:49:55 AEDT**.
- Environment: Federated Copilot PoC, `c72f8bf6-020d-e210-8662-fa461a415ec2`, Australia.
- Agent: Federated Delegation Test, Dataverse ID `1d18f6de-66d3-f111-a05b-6045bd40333e`, schema `cra8f_FederatedDelegationTest`.

## Reproduction and evidence

The operator saved and published Authenticate manually / Generic OAuth 2, with sign-in required, then used a fresh sign-in card. PF's login page opens and PF's audit records successful human authentication and OAuth authorization. The browser is redirected to Microsoft's registered callback and receives the error above. Re-entering the existing dedicated client secret and republishing did not change the outcome.

The operator-supplied authorization query and token URL/body templates match the reviewed configuration in [the settings guide](copilot-generic-oauth-settings.md). The operator corrected the scope and subsequently reached the PF login page. Full effective Microsoft connection settings have not been independently retrieved; Dataverse exposes only a connection reference.

Four independent actual-public-HTTPS tests pass: complete PF authorization-code issuance/redemption with pinned JWT verification, code reuse rejection, invalid client-secret rejection and unregistered callback rejection. These tests capture the Microsoft callback without contacting it and therefore do not prove Microsoft's integration works.

Additional synthetic invalid-credential POSTs to the exact public token endpoint, including a trailing question mark and different user-agent labels, return expected HTTP 401 JSON `invalid_client` without a Cloudflare challenge header. These are local-origin probes and do not prove Microsoft egress reachability. No corresponding token-exchange event was observed after the user login successes in the sampled PF audit. This bounded absence is not conclusive proof that no request arrived.

The operator reports no matching Cloudflare Security Event. That view does not establish absence of all HTTP traffic or rule out connectivity problems.

## Request to Microsoft

Please trace the request ID and UTC timestamp above and identify the underlying exception masked by the empty response body. Specifically, determine whether the configured token URL/body templates expanded successfully, whether a token POST was attempted, and whether it failed in DNS, TLS, connection establishment, HTTP handling or response parsing. If a token response was received, provide its status and a sanitized error category without returning credentials or tokens. Confirm the effective OAuth provider/connection binding for the specified current published agent.

Do not request an unredacted HAR or raw session URL. No authorization code, state value, cookie, client secret, access token or raw audit field is included in this draft. PF tool exchange remains disabled; no Graph operation is involved.
