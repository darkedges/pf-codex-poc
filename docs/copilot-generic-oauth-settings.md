# Copilot Generic OAuth 2 — manual sign-in configuration

Current lifetime/result (2026-10-31 Australia/Sydney): the user's later request increased the dedicated PF A login token to **60 minutes (3600 seconds)**. The [single approved one-hour-token run](copilot-sixty-minute-success.md) returned **HTTP 200** and the published `User.IsLoggedIn=true` diagnostic. This supersedes the five-minute lifetime below. Copilot-originated delegated tool use, autonomous provider SSO and Copilot expiry behavior remain UNVERIFIED.

Lifetime update (2026-10-31 Australia/Sydney): the user approved a longer PF A login token. The dedicated `copilotLoginJWT` manager now issues **five-minute (300-second)** tokens, and the provider verifier/example accept at most 300 seconds. Actual local PF A issuance/signature/binding and rejection at the separate tool boundary passed; no Microsoft callback or token POST was sent. Other PF token managers and client grants remain unchanged. All 295 baseline and 316 production tests pass. This lifetime change is not evidence of a fix for Microsoft's expiry response; a further live attempt requires separate approval. Existing tokens retain their original expiry.

Latest operator checkpoint (2026-10-30): after correcting the Token URL field and completing Microsoft's validation-code step, the operator received the [published Boolean diagnostic](copilot-signin-verification.md)'s exact positive response, `User.IsLoggedIn=true`. Manual sign-in and the runtime Boolean checkpoint are operator-observed. Token claims inside Copilot, delegated SSO/tool acceptance and autonomous execution remain UNVERIFIED.

The dedicated PF A login client is enabled. Four real public-HTTPS tests pass: authorization-code login, pinned JWT verification, code replay rejection, invalid-client-secret rejection and unregistered-redirect rejection (the first test includes login plus token verification). The Microsoft callback was captured locally, not contacted. The PF B tool-exchange client remains disabled. **Copilot tenant acceptance and delegated SSO remain UNVERIFIED.**

Select the published agent **Federated Delegation Test** in **Federated Copilot PoC** (`c72f8bf6-020d-e210-8662-fa461a415ec2`). In Settings → Security → Authentication, select **Authenticate manually**, provider **Generic OAuth 2**, and keep **Require users to sign in** on.

| Field | Value |
|---|---|
| Client ID | `copilot-studio-generic-oauth` |
| Client secret | From protected local `.local/copilot/pf-generic-oauth-client-secret.txt`; do not use a gateway or Direct Line credential |
| Authorization URL template | `https://pf-a.copilot.darkedges.com/as/authorization.oauth2` |
| Token URL template | `https://pf-a.copilot.darkedges.com/as/token.oauth2` |
| Scopes | `copilot.login` |
| Scope list delimiter | `,` (only one scope is requested) |
| Grant type, if displayed | `authorization_code` |
| Redirect URL | Leave the displayed `https://token.botframework.com/.auth/web/redirect` unchanged |
| Token exchange URL | Leave blank for this initial manual-sign-in verification; do not put the PF token endpoint here |
| Refresh URL template | If required, `https://pf-a.copilot.darkedges.com/as/token.oauth2`; otherwise leave blank |
| Refresh URL query string template | If required, `?`; otherwise leave blank |
| Refresh body template | If required, `refresh_token={RefreshToken}&grant_type=refresh_token&client_id={ClientId}&client_secret={ClientSecret}`; otherwise leave blank |
| OAuth Metadata endpoint | Leave blank; this profile uses the explicit endpoint templates above |
| PKCE Challenge Method | `None` for the currently tested confidential-client flow; Copilot S256 integration remains UNVERIFIED |

Authorization URL query string template:

```text
?client_id={ClientId}&response_type=code&redirect_uri={RedirectUrl}&scope={Scopes}&state={State}&pfidpadapterid=consentHTMLForm&resource=urn%3Acopilot%3Alogin
```

Token body template:

```text
code={Code}&grant_type=authorization_code&redirect_uri={RedirectUrl}&client_id={ClientId}&client_secret={ClientSecret}
```

Keep the brace placeholders exactly as shown. These are Microsoft's [documented manual-authentication template fields](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configuration-end-user-authentication); PF A's exact endpoint, adapter, scope, resource, callback and body combination were exercised through the public edge. Do not add `openid`, Graph scopes or refresh grants to make an unfamiliar UI field save. If mandatory fields differ, capture their labels before changing the PF contract.

The refresh templates only satisfy UI fields if required: PF still permits only `AUTHORIZATION_CODE` and issues no refresh token. They do not enable refresh; a refresh request must be rejected. Sign-in must be repeated after the short-lived login token expires. The verified initial login used client-secret authentication without PKCE; do not claim that Copilot adds or redeems S256 correctly until that separate flow is tested.

The generated secret is already saved under the protected current-user/SYSTEM directory. To copy it for pasting directly into the Copilot **Client secret** field without printing it in the terminal, run locally:

```powershell
Set-Clipboard -Value ([IO.File]::ReadAllText('E:\development\projects\copilot\federated-copilot-codex\.local\copilot\pf-generic-oauth-client-secret.txt').Trim())
```

After pasting, clear the clipboard when convenient. The assistant does not read the clipboard or send the secret through chat.

Save the authentication settings and publish the agent. Microsoft states that authentication changes take effect only after publication. In an independently authorized new test conversation, follow Sign in and use the synthetic PF lab user `partner-a:user-123`; its generated password remains in `.local/pingfederate/login-password`, not this document. This is the PF account, not an Entra user. If sign-in succeeds, confirm that outcome without sharing access tokens, codes or client secrets. The current one-hour human login token has no actor/grant authority and protected delegated tools must continue rejecting it.

## Boundaries and remaining verification

Manual human sign-in is one prerequisite. It is not a test of autonomous execution, Generic OAuth token-post passthrough or the deployed tool API. Keep the independently verified tool-audience token, actor/grant checks and online PDP for those flows; the PF B client remains disabled and no Graph connection exists. No Microsoft agent authentication configuration was changed by the local enablement script.

`npm run copilot:login-test` repeats the four bounded public checks while preserving the current enabled state. `scripts/pf/enable-public-login.mjs` defaults to preview; `--enable-and-verify` requires the exact staged profile, records intent before enabling only the dedicated login client, and restores it disabled if initial verification fails. Unknown/existing activation receipts require reconciliation. `node scripts/pf/check-copilot-clients.mjs --login-enabled` checks the current explicit lifecycle state. The older staging harnesses intentionally require both clients disabled and must not be run over an active sign-in configuration.

Client secrets and workload keys remain local lab custody. Production secret-manager deployment, real rendered-browser verification, Microsoft callback/code redemption and actual Copilot authentication acceptance remain separate gates.
