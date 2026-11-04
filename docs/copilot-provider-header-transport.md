# Missing provider header: isolated cause and transport workaround

Current checkpoint: 1 November 2026 Australia/Sydney. **Interactive connector-origin exact provider-token continuity and delegated diagnostic execution VERIFIED in the PoC.** The [approved real signed-in run](copilot-interactive-tool-success.md) passed with independent policy identity audit and cleanup. Autonomous and production verification remain separate gates.

Earlier connector-only checkpoint: the operator's refreshed simple-header synthetic probe returned403 and fresh origin records showed provider/caller `present`. This established nonempty provider-header delivery and caller-key acceptance before the separately approved signed-in run. The chronology below preserves the preparation and verification limits at each stage.

Fresh origin diagnostics for the operator's synthetic connector probe showed HTTP401 with provider header `missing` and caller header `present`. The caller key's value was not checked on that path: the HTTP handler rejects missing headers first. Do not conclude that Microsoft's stored key is valid merely because its header is present.

A direct HTTPS request through the same public Cloudflare route, using the Vault-held caller key and synthetic unbound provider value, returned403 with both headers present. This verifies that the route and relay can accept the headers; it isolates the omission to the connector-specific forwarding path, without identifying Microsoft's internal mechanism.

## Ineffective policy attempt

Added the documented [Set HTTP Header policy](https://learn.microsoft.com/en-us/connectors/custom-connectors/policy-templates/setheader/setheader), scoped to VerifyDelegatedAccess, copying `@headers('X-PF-User-Access-Token')` into the same header. Saved/read-back policy matched; API operation and connection schema were unchanged. The operator's next fresh synthetic probe still produced401 with a missing provider header. The policy did not solve the omission and was removed. Its candidate and receipt remain historical evidence, not the active configuration.

## Active workaround

The connector and managed relay now use **PfUserAccessToken** as the provider header name. It has no prefix, hyphen or Power Fx property-path punctuation. The agent's ManualTaskInput remains exactly `System.User.AccessToken`; no user/model input, query parameter, token-bearing body or extra authority field is introduced. The caller connection still supplies X-Copilot-Connection-Key. Body remains `{}` and result remains Boolean authorization.

The HTTP factory accepts an explicit trusted configuration selecting either the original X-PF-User-Access-Token or PfUserAccessToken format. Its default stays original for existing local adapters/tests. The managed PoC explicitly selects PfUserAccessToken. It refuses the other header or mixed formats rather than falling back or merging credentials. Token signature, issuer/audience, human/agent/grant binding, caller-key validation, current policy and one-use/replay rules are unchanged.

Active connector candidate: `infra/copilot/microsoft-tool-test.simple-header.openapi.json`. Action candidate: `infra/copilot/verify-delegation.action.mcs.yml`. The original reviewed Swagger/approval manifest remains historical and unchanged. The dedicated managed harness uses the current simple header; other explicit local simulation factories keep the original default.

## Verification and remaining gate

Failing-first regression proves the explicit mode was absent before implementation. Tests now verify correct credential/binding success, rejection of old/mixed/duplicate headers and wrong keys, and consumed-binding replay denial. Full suites pass:450 production with bounded test concurrency,371 baseline. A 100ms signer fixture timed out during a simultaneous full-suite run, then passed in isolation and in the full four-worker production run; production deadlines were not changed.

Updated the existing connector, removed the ineffective policy, pushed/published the fixed action and restarted only the owned relay. Read-back checks confirm the API route/operation/caller authentication and connection schema remain unchanged apart from the provider parameter name. Actual direct public probes returned403 for the simple header and400 for the rejected legacy header, with no PF issuance, grant, Microsoft agent conversation or successful tool operation.

The operator must refresh the connector's Test tab and enter a new synthetic unbound value in the **PfUserAccessToken** parameter. Expected403 proves caller-key acceptance and delivery of a nonempty header for that denied probe. It does not prove delivery of the exact PF token, agent execution or full delegation; a later separately approved bounded agent test remains necessary. Existing automated conversation/token-POST ledgers remain consumed. The PoC exception for Microsoft credential traces continues; production approval is unchanged.
