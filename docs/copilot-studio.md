# Microsoft Copilot Studio Integration (UNVERIFIED live tenant)

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

**Validate in a real environment** that a correctly issued PingFederate B token from your token-exchange architecture is accepted, that the token is available to a protected HTTP tool, and that the custom *autonomous* flow can establish a session without illicit interactive impersonation. Also validate Power Platform data policies, licensing, tool connection credentials and refresh behavior. This product-specific behaviour is not implemented or verified by the demo.

Do not treat an accepted OAuth token as proof that Copilot natively understands the `act` claim. The broker, not the model, must verify and enforce the original agent delegation.

## Failure strategy

When SSO challenge is missing, denied, timed out or requires an actual user that is absent, fail closed. If autonomous SSO is unsupported by the channel, design a distinct supported channel or broker-driven orchestration path; do not override user-authentication constraints.

## Native Microsoft knowledge limitation

Generic OAuth external users do not automatically receive Microsoft Graph user-delegated access. Native SharePoint knowledge features have separate authentication limitations; implement approved SharePoint reads as broker-backed tools using Entra application-only access.
