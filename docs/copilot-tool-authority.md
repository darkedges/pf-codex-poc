# Policy-protected tool tokens — local integration verified

The dedicated PF tool branch now uses the same hardened exchange adapter and independently authenticated HTTPS policy service for both token release and tool execution. The verification uses actual PF A/B containers and an isolated persisted grant registry. It does not call Copilot Studio, Graph or SharePoint, enable public routes or deploy a production listener.

`src/copilot/tool-authority.ts` provides the typed `PolicyProtectedTool<T>` boundary. Its configured verifier must validate an audience-specific token; its mandatory policy callback receives the signed token as evidence. Before invoking a fixed server-side operation, the boundary checks signature/identity, current grant authorization and exact expiry. Before returning the operation result, it checks live policy and expiry again. It never derives identity, scope or resource from prompts, operation output or unverified headers.

The boundary has one bounded deadline, an AbortSignal for the operation, sanitized error codes (`configuration`, `invalid_token`, `policy_denied`, `tool_failed`) and optional credential-free telemetry. There is no operation retry or policy fallback. If revocation, suspension, expiry or policy failure occurs before release, no result is returned. An already performed external side effect cannot be undone by a post-operation check; write tools require their own commit/authorization semantics. The current verification uses read-only diagnostic callbacks, not Microsoft data access.

## Explicit lab policy profile

`POLICY_COPILOT_TOOL_PROFILE=local-verified` plus an explicit `POLICY_DATABASE` opts a local policy process into the dedicated tool issuer. Missing selection keeps the original profile; unknown/ambiguous values fail startup. The controlled harness creates a new isolated database. Existing consent-principal issuer lists are not silently expanded: enabling the option against an old registry without that issuer fails and requires a reviewed migration.

| Boundary | Approved token/configuration |
|---|---|
| Fresh consent proof into PF B | PF A `https://localhost:9033`, audience `api://gateway-2`, `consent-a-signing`, RS256 |
| Issued tool token | `https://pf-b.copilot.darkedges.com`, audience `api://copilot-tool`, `copilot-tool-signing`, RS256, maximum 120 seconds |
| Local JWKS transport | Fixed verified HTTPS `https://localhost:9034/pf/JWKS`; issuer and transport names deliberately differ in this lab |
| OAuth client | `copilot-sso-exchange`, separate private_key_jwt key, resource `urn:copilot:delegated:tool` |
| Policy workload | Separate `policy-tool` key; decision role only, organisation `partner-a`; no registry/grant administration |
| Approved capability | Only `copilot.invoke` on `sharepoint:approved-research`; no arbitrary URL/site/scope |

Only the consent-backed human principal receives the additional allowed token issuer when the isolated registry is created. The fixture human and existing default policy profile remain separate. The grant still binds the original human, actor issuer/subject, organisation, mode, scope and approved resource. A registry issuer allowance alone is insufficient: the policy process independently verifies the actual token against its closed issuer/audience/key registry on every decision.

The local composition in `scripts/pf/consent-tool-exchange.ts` obtains fresh consent-backed PF A proof and uses `PingFederateExchange` with mandatory online authorization before and after PF B issuance. It also constructs the tool boundary with its own strict verifier and online policy client. Tokens remain server-side. This composition is explicit lab code with local credential files; production needs approved key custody, deployment configuration and HTTP ingress/sender authentication.

## Verification

Run `npm run copilot:pf-policy-test` sequentially with other live consent suites, which share port 9461. The harness temporarily enables only the dedicated tool exchange client, uses an isolated policy database and restores/verifies both dedicated clients disabled. It leaves receipts and preserves uncertain-run leases for recovery. No existing persistent registry, public networking or Microsoft agent configuration is changed.

All eleven actual-PF/HTTPS policy checks pass:

- Both interactive and autonomous token release and tool execution preserve the human/actor/grant/mode binding.
- Revocation before exchange prevents issuance; revocation during actual PF issuance suppresses token release in both modes.
- Revocation after issuance prevents invocation; revocation during the operation suppresses its result.
- Tool credentials cannot administer the registry or request another resource.
- A default policy process rejects the tool issuer even if its underlying registry contains that issuer.
- Stopping an actual policy service blocks exchange and tool invocation.
- Agent suspension blocks both a valid signed proof and an already issued token; the authenticated owner can still revoke the grant.

Additional local tests cover signed subject/actor/org/grant/mode/audience/scope substitution, human/organisation suspension, exact expiry during an operation, deadline cancellation, missing policy dependencies and owner-proof checks after suspension. Final regression evidence: 97 baseline tests, 216 production contract/security tests, eleven live tool-policy checks, 35 original PF checks and four disabled-client checks pass. The existing six public-profile protocol checks and real signed-proof aging evidence remain documented separately in `copilot-pf-staging.md`.

The original simulation smoke also passes: interactive/autonomous 200, revoked/unapproved-resource 403. Both dedicated PF clients are confirmed disabled after the completed policy run; public routes remain closed.

## Revocation correction

The previous consent API called the active-agent approval check for revocation as well. That prevented an authenticated owner from revoking after agent suspension. Revocation now checks the verified human, owned grant and caller organisation directly, preserving transactional ownership checks and rejecting unknown/other-owner grants or forged login evidence. Preview/new approval still require an active agent. The portal's review page may refuse to render a suspended-agent approval; the verified revoke operation itself no longer depends on agent activity.

## Remaining work — UNVERIFIED

Update 2026-10-30: the [fixed protected tool API and mandatory-mTLS HTTPS factory](protected-tool-api.md) are implemented and tested locally, including real loopback certificate rejection. They are not deployed. Actual Copilot tool delivery, supported calling-workload authentication and public/private hosting remain separate verification gates. The historical verification milestones above do not describe current PF human-login client state.

Wire this boundary into the deployed tool HTTP API and Copilot's actual `User.AccessToken` path, with sender authentication and production secret custody. Verify resource authorization and expiry through real tenant SSO challenges before claiming Copilot federation. Public edge TLS, complete browser assets/cookie behavior and exact DNS/ingress activation still need review and approval. Graph/SharePoint remain disconnected; no Microsoft app grants or external-human Entra identities were added.
