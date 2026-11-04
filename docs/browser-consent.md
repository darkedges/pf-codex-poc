# PF browser login and human consent

Implemented and verified against the isolated PingFederate 13.1.0 pair. A real PF Authorization Code login with S256 PKCE now creates an authenticated browser session. Explicit approval creates a human-owned, persisted grant; both interactive and autonomous execution traverse real PF A/Gateway 2/PF B exchanges and stop after revocation.

The identities are local PF test accounts, not a production directory integration. The registered agent uses development credentials; authority signing uses the selected backend, including the [verified actual local Vault profile](vault-containers.md). Production workload isolation, deployment and security approval remain **UNVERIFIED**. Copilot, Entra and Graph remain disconnected.

## Run and try

For an existing prepared local pair:

```powershell
npm run pf:configure
npm run consent:serve
```

For first-time setup, follow the [container guide](pingfederate-containers.md), including `pf:prepare` and `pf:up`. Configuration creates the separate consent login and exchange objects and updates the policy registry. Only this project's two PF containers are changed.

Open [Delegated access](https://localhost:9460). The launcher starts the HTTPS portal on **127.0.0.1:9460** and its own authenticated HTTPS policy process on an ephemeral loopback port. It loads the prepared CA for outbound TLS verification and keeps data in ignored `.local/pingfederate/policy.sqlite`. Ctrl+C stops these launcher-owned processes; PF containers and persisted grants remain.

1. Select **Sign in to review access**.
2. On the PF A login page, sign in as `partner-a:user-123`. Its generated password is in the local file `.local/pingfederate/login-password`; view it locally without pasting it into chat or shared logs. A second account, `partner-a:user-other`, exists solely for rejection tests and has no delegated-access registration.
3. Approve PF's `openid` request. This establishes identity; it does not grant the agent permission.
4. In the portal, review the registered agent, exact scope/resource, execution modes and expiry. Choose **1 hour** or **24 hours**. Interactive access is included; background access is **off by default** and needs explicit opt-in.
5. Select **Approve access**. The policy service creates a new grant ID with evidence bound to this PF identity and the reviewed terms.
6. Use **Check interactive access** or, if approved, **Check background access** to exercise the actual identity chain. These check authorisation only; they do not query Microsoft data.
7. Select **Revoke access**. Further requests under that grant are denied. A new sign-in can list and revoke the same human's previous grants; revoked IDs cannot reactivate.

One fresh login can approve one new grant. To approve another, sign in again. Browser authentication lasts at most five minutes; the separately approved background grant can last until its selected expiry without retaining or replaying the human's login token.

## Endpoints and trust

| Component | Local endpoint | Purpose |
|---|---|---|
| Consent portal | `https://localhost:9460` | Sign-in, review, approval, owned-grant revocation and access checks |
| Browser integration test portal | `https://localhost:9461` | Same code, separate test listener and cookie name |
| PF A authorization | `https://localhost:9033/as/authorization.oauth2` | Browser login through `consentHTMLForm` |
| PF A PAR | `https://localhost:9033/as/par.oauth2` | Signed-client-authenticated authorization request |
| PF A token | `https://localhost:9033/as/token.oauth2` | Code redemption and consent-backed exchange |
| PF B token | `https://localhost:9034/as/token.oauth2` | Broker-audienced exchange |
| Policy API | Launcher-assigned HTTPS loopback port | Independent OIDC verification, grant lifecycle and PF-token decisions |

The OAuth client `copilot-consent-portal` has only `AUTHORIZATION_CODE`, only `openid`, exact registered callback URIs on ports 9460/9461, required PAR and PKCE, private-key JWT authentication and replay prevention. It has no refresh grant. Redirect endpoints, issuer and JWKS come from approved configuration; token or request headers cannot choose a host.

The OIDC verifier checks RS256 signature, approved key ID/JWKS, exact issuer/audience, authorised party, nonce, expiry, issued-at and fresh `auth_time`. The portal also validates `at_hash` when present against the token response. It discards the login access token. The ID token remains in server-side session memory solely as evidence for the independent policy verifier and current interactive authentication; it is never rendered or persisted as a credential fixture.

The portal binds state, nonce and PKCE verifier to an opaque browser session. State is consumed before code redemption. Successful callback rotates the session ID and CSRF token. Cookies are Secure, HttpOnly, host-only and SameSite=Lax. All state-changing forms require the exact configured Origin, session-bound CSRF and an allowlist of fields; duplicated or extra human/scope/resource fields are rejected. Responses disable caching, referrers and framing. No callback URL, code, token or password is logged by the portal.

The policy service grants a separate organisation-scoped `consent` role to the portal workload; it is not a grant/registry administrator. It independently verifies the signed ID token and looks up the exact external issuer/subject in the preapproved human registry. Unknown humans are denied, not provisioned or linked by email. The agent, capability and maximum lifetimes are server policy. The human ID, scope, resource and grant ID cannot be supplied by a browser form.

| Policy route | Signed caller role | Behaviour |
|---|---|---|
| `POST /v1/consents/preview` | `consent` | Verify the login and return its registered identity, approved agent/capability, allowed options, owned grants and review hash |
| `POST /v1/consents/approve` | `consent` | Verify the same login and exact review hash, then atomically create grant and evidence |
| `POST /v1/consents/revoke` | `consent` | Verify current login and ownership, then persist terminal revocation |

Approval records store the login token's digest, nonce digest, issuer, subject, audience, authentication/approval times, reviewed-terms digest and grant reference. The grant captures the actual selected modes, scope, resource and expiry. The token digest is unique, so reusing a login cannot mint another grant, even through a different policy process. No raw ID/access tokens are stored. Grant creation, approval evidence and their audit records commit atomically.

The review hash binds the login proof, human, agent, capability and available options. Approval cannot silently expand to a changed policy after the page was shown. The portal also pins the displayed capability to its configured capability.

## Consent-backed exchanges

```mermaid
sequenceDiagram
  participant U as Human browser
  participant C as Consent portal :9460
  participant A as PF A :9033
  participant P as Policy service / SQLite
  participant D as Consent-backed authority
  participant G as Gateway 2 adapter
  participant B as PF B :9034
  U->>C: Start sign-in (same-origin CSRF)
  C->>A: PAR + S256 challenge + nonce + signed client assertion
  U->>A: Real login and openid approval
  A-->>C: Authorization code / state
  C->>A: Code + original PKCE verifier + client authentication
  A-->>C: Signed ID token
  C->>P: Independently verify login and preview permissions
  U->>C: Explicit permission / expiry / background opt-in
  C->>P: Signed approval + ID token + nonce + reviewed-terms hash
  P-->>C: New human-owned grant / persisted evidence
  D->>P: Check current consented grant and independently verified agent
  Note over C,D: Interactive also requires current verified human login; autonomous uses the approved grant without a human token
  D->>A: Fresh 60-second assertion + independent actor proof
  A-->>G: PF A token (aud api://gateway-2)
  G->>P: Verify PF A evidence / current authority
  G->>B: Exchange with separate confidential client
  B-->>G: PF B token (aud api://copilot-broker)
  G->>P: Verify PF B evidence / recheck authority before release
```

The [authenticated authority API](authority-service.md) runs `GrantAuthority` inside the policy service. The caller sends a signed request bound to grant, mode and operation; its credential resolves to the registered actor. The authority independently verifies the actor proof and consent, requires current matching human login for interactive execution, signs a 60-second assertion and rechecks grant state after signing. Autonomous issuance rejects human login evidence. The exchange caller no longer loads the authority key or opens the policy database. Separate issuance permission and persistent replay protection guard the endpoint.

The consent authority has its **own key and issuer**, `https://partner-a.test/consent-authority`, distinct from retained fixture authorities. PF A's `consentGrantProof` processor trusts only this public key/issuer and `api://pf-a/consent-proof`. Its processor mappings bind interactive/autonomous mode and independently validate the actor. The issuer URI is a configured local-test namespace, not a deployed public endpoint.

Separate consent gateway clients and token managers prevent the retained fixture profiles from becoming a fallback. PF A and PF B use unique ATM selectors `urn:copilot:consent:gateway-2` and `urn:copilot:consent:broker`, while their **issued JWT audiences remain** `api://gateway-2` and `api://copilot-broker`. The adapter's administrator-configured `requestedResource` selects the ATM independently of the strict receiving audience; requests cannot choose it. PF B pins the consent PF A signing key at configuration time. Both gateways preserve the original human, actor issuer/subject, organisation, grant, mode and narrowed scope.

The original mock demo and retained real-PF fixture tests remain separate. Their synthetic human/authority credentials cannot enter the consent exchange profile, and manual fixture grants lack the consent evidence required by the new authority.

## Verification and remaining gates

`npm run pf:test` now includes 35 live tests. They perform real PF login/approval forms and code redemption over verified HTTPS, human approval, both exchange modes, owned revocation, background execution without a human token, mandatory foreground login, wrong PKCE rejection, another subject/session rejection, CSRF/field forgery rejection, explicit background opt-in and fixture-authority isolation. They also retain the prior token/client/replay/outage/mid-issuance-revocation tests. Test passwords, codes and tokens are not printed.

The offline suites contain 38 baseline/store tests and 109 production/API/portal/identity/signer tests. The original simulation smoke flow remains supported. Local validation metadata is saved under `.local/pingfederate`; it contains versions/status/database paths, not credentials.

Still **UNVERIFIED / not implemented**: production PF account/directory and MFA policy, production OAuth-client approval, distributed browser session custody, secret-manager/HSM/workload-isolated authority signing, sender-constrained external agent requests, per-operation resource broker enforcement, dynamic PF-to-PF key rollover, disaster recovery and deployment/security approval. The local account/agent/private-key fixtures are for development only. Copilot Studio authentication and Microsoft resource access remain separate integration gates.

References: [PF authorization endpoint](https://docs.pingidentity.com/pingfederate/13.1/developers_reference_guide/pf_authorization_endpoint.html), [PF PAR endpoint](https://docs.pingidentity.com/pingfederate/13.0/developers_reference_guide/pf_pushed_authoriz_request_endpoint.html), [PKCE server settings](https://docs.pingidentity.com/pingfederate/12.2/administrators_reference_guide/help_authorizationserversettingstasklet_oauthauthorizationserversettingsstate.html).

