# Microsoft Copilot Studio Integration

The [interactive real-tenant PoC](copilot-interactive-tool-success.md) now verifies Generic OAuth sign-in and a Copilot-originated delegated diagnostic through the Vault-backed relay, real PF A/B and private Docker tool. The original human, acting agent, organisation, grant, mode, resource and audience were independently audited, and cleanup passed. Autonomous Copilot SSO and live Microsoft expiry/revocation behavior remain UNVERIFIED; Graph is not connected. The default local demo remains isolated.

The [Direct Line adapter and HTTPS API factory](direct-line-adapter.md) also have local contract/negative tests for conversation binding, separate credentials, controlled token posting, expiry/revocation and secret injection. Local contract tests alone do not establish further tenant behavior. The current provider connector header is PfUserAccessToken; caller connection authentication uses X-Copilot-Connection-Key.

Sources:
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-sso-3p
- https://learn.microsoft.com/en-us/microsoft-copilot-studio/configuration-end-user-authentication

## Target configuration

- Publish an internal Copilot Studio agent in an approved Power Platform environment.
- Configure **Authenticate manually → Generic OAuth 2.0** with an approved PingFederate B provider and suitable protected broker API scopes.
- Enable secured Direct Line. Keep Direct Line secrets in the server-side secret manager; never send them to the external agent.
- Use a dedicated Copilot Integration Service that binds the Direct Line conversation to the verified subject, actor, grant ID, permissions, expiry and correlation ID.
- Configure authenticated HTTP tool calls to the broker's specific read-only APIs, not arbitrary Graph URLs.
- Prevent Copilot prompt text, topics and unauthenticated channel headers from choosing user identity or delegation grants.

## Generic OAuth SSO hypothesis to test

The documented custom Direct Line client flow receives OAuthCard attachments (`application/vnd.microsoft.card.oauth`), reads `content.tokenPostResource.sasUrl`, POSTs `{ "token": "<approved user token>" }` to the secure URL, then Copilot exposes the token in `System.User.AccessToken`.

**Validate in a real environment** that a separately audienced PingFederate B SSO/tool token is accepted, reaches a protected HTTP tool, and allows the custom *autonomous* flow without illicit interactive impersonation. Also validate Power Platform data policies, licensing, tool connection credentials and refresh behavior. The adapter implements the documented POST protocol, but product acceptance remains UNVERIFIED. Do not forward the incoming broker-audience token as an SSO token or interpret HTTP POST success as authenticated tool access.

Do not treat an accepted OAuth token as proof that Copilot natively understands the `act` claim. The broker, not the model, must verify and enforce the original agent delegation.

## Failure strategy

When SSO challenge is missing, denied, timed out or requires an actual user that is absent, fail closed. If autonomous SSO is unsupported by the channel, design a distinct supported channel or broker-driven orchestration path; do not override user-authentication constraints.

## Native Microsoft knowledge limitation

Generic OAuth external users do not automatically receive Microsoft Graph user-delegated access. Native SharePoint knowledge features have separate authentication limitations; implement approved SharePoint reads as broker-backed tools using Entra application-only access.
