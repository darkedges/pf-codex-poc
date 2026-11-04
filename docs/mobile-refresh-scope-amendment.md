# Mobile refresh scope amendment

The approved activation stopped on its first PF write: HTTP 422, `oauth_client_mgmt_scope_invalid`, `Undefined scope 'offline_access'`. Read-only verification confirms `mobile-copilot-login` does not exist. No mobile client was enabled, TLS record changed, public route switched or Microsoft request sent.

Approve one additional PF A authorization-server catalog entry: `offline_access`, static, described as explicit mobile OIDC session renewal with no resource access. Preserve every other server setting and scope exactly. This does not add the scope to any existing restricted client, widen a Graph permission or change the shared Copilot OAuth client. The dedicated mobile client's already approved restricted scopes include this value, required by its planned refresh-token flow.

The helper pins the current complete settings hash, checks that the rejected client is still absent, records intent before the write and verifies exact read-back. It preserves the rejected attempt's journal before reconciling its pending entry. An uncertain result stops for inspection. Then complete the existing approved deployment and phone installation; the same 100-question/20-conversation allowance and $50 budget remain unchanged.

AGENTS.md requires explicit approval for production IAM policy changes. The original frozen activation plan did not include a global scope-catalog edit, so this is a narrow amendment rather than a new test allowance. Existing approved manifests and spent staging evidence stay unchanged.
