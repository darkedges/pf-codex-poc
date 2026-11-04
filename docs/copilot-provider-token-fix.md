# Generic OAuth provider-token mismatch correction

Implemented 2026-10-31 Australia/Sydney. **The mismatch is corrected; Microsoft acceptance remains UNVERIFIED.** The user subsequently authorized [one corrected-provider cURL test](copilot-provider-capture.md): it returned HTTP 400 with exact body `"Token is expired"`, request ID `7da611c1417a7063c88ae1f2bbbcf00d`, despite verified PF A proof and a measured 161.787 ms card-to-invocation interval. That new allowance and all four historical allowances are consumed. The running private tool service and Microsoft agent settings were unchanged.

## What was wrong

The saved agent Generic OAuth connection uses PF A (`https://pf-a.copilot.darkedges.com`), client `copilot-studio-generic-oauth`, user-token audience `api://copilot-login` and scope `copilot.login`. The previous live runner instead posted the PF B delegated tool JWT (`api://copilot-tool`, `copilot.invoke`). Its successful local signature/grant checks proved it was usable for the tool; they did not prove it matched the configured OAuth connection. This is a confirmed client-side mismatch, not proof of which Microsoft-side object caused HTTP 400.

Microsoft's [Generic OAuth documentation](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-sso-3p) describes posting the configured provider's user access token. Preserve the four historical failure traces and the `expired` response category as observations. Do not reinterpret them as successful provider-token tests or as proof of an expired PF token/SAS URL.

## Distinct credential boundaries

| Credential | Verification and use |
|---|---|
| Direct Line secret/conversation token | Channel transport only; never posted as user sign-in proof |
| PF B broker JWT | Full human/actor/org/grant/mode/scope binding and online policy for every channel operation |
| PF A provider user access token | Generic OAuth sign-in only; pinned PF A issuer/JWKS, `api://copilot-login`, `copilot.login`, RS256/kid, bounded dates and trusted identity binding |
| PF B tool JWT | Separate audience `api://copilot-tool`, full delegation claims and independent tool policy before execution/result release |

`System.User.AccessToken` will contain the provider user token if Microsoft accepts it. It is **not delegated tool authority** and must still be rejected by the existing tool verifier. The original human, acting agent, organisation, grant and mode remain in the verified server-side broker context and tool JWT. A Copilot-originating tool needs a separately authenticated broker-mediated delegation/delivery path; a prompt, channel user ID or provider token alone cannot supply one. That handoff remains unverified.

## Implementation

`ProviderAccessVerifier` is a separate JOSE-based verifier for this subject-only PF user access token. It uses fixed HTTPS issuer/JWKS and explicit key IDs, RS256, exact audience/scope, bounded JWKS response/timeout/cache, required timestamps/jti and a maximum lifetime. It rejects delegated `act`, grant, mode and org claims, ID/wrong-purpose tokens, untrusted key headers and expired/overlong tokens. It produces only the verified provider identity; no missing delegation claims are invented.

`DirectLineAdapter` now accepts explicit `providerSso` configuration and requires both an independent provider verifier and a trusted `bindProviderIdentity` dependency. The actual Microsoft `/api/sas/postToken` destination cannot be constructed with the old delegated-SSO configuration, including rules whose path prefix could match it. Other existing custom-transport contract tests keep their explicit delegated behavior; there is no fallback from a configured provider failure to a tool/broker token.

Provider identity is bound before transmission to the already verified broker context. The lab binding explicitly maps the pinned PF A issuer and synthetic human to the approved broker human/org/agent issuer/agent. It does not infer partner/org/actor from a login username or chat data. Production must supply its authoritative issuer-qualified identity registry rather than generalizing that lab mapping.

Broker policy continues before and after each outbound request. Provider expiry is installed in session checks before the POST, so expiry during binding or the final policy check prevents transmission. Failure closes the session, never releases the accompanying bot messages and never retries the token POST. Provider/channel/broker credentials remain server-side and covered by existing transcript redaction.

The corrected local live runner acquires the dedicated PF A authorization-code user token before opening a conversation, verifies it and binds it to the broker. The registered Microsoft callback is intercepted locally and the code redeemed directly with PF A; it is not followed to Microsoft. A distinct PF B tool JWT is used only for the independent local tool/revocation diagnostic. The runner requests the provider's audience/scope for SSO, not the tool's.

## Autonomous mode and allowances

The configured PF A client permits authorization code only and has no verified unattended user-token/refresh capability. The provider-SSO adapter therefore rejects autonomous sessions before any Direct Line request. The old two-mode `--run`/`--remaining` diagnostic is retired before client/budget work. Local autonomous grant-backed PF/tool execution remains supported and separately verified; it is not silently downgraded to interactive login or replaced with an old user token for Copilot.

No historical budget was reset by the correction. The user subsequently explicitly approved [one corrected-provider capture](copilot-provider-capture.md), limited to one interactive conversation/one POST; it returned HTTP 400 and that separate allowance is now also consumed. Any further attempt needs a fresh explicit allowance. Live acceptance, exact Copilot token continuity and secure tool delivery remain unverified.

## Verification

- All **281 baseline** and **315 production** tests pass. New negatives cover provider issuer/audience/scope/key confusion, delegated-token substitution, subject/partner/actor binding, missing binding authority, expiry during binding/final policy, grant revocation before POST, and unsupported autonomous sign-in.
- `tests/live-copilot/provider-login.integration.ts` passes against the actual local PF A container with pinned TLS and the public issuer/Host profile. It obtains and verifies a real provider user token, validates the explicit lab binding and proves that token cannot pass the PF B tool verifier. The registered Microsoft callback is captured locally; no Microsoft request, PF client mutation or test allowance is used.
- Existing Direct Line signed-query, no-channel-header, no-retry, message-suppression, session ownership, expiry/revocation and redaction regressions remain passing. The original dependency-free mock service code is unchanged.

The previously approved support packet is historical and remains unchanged/hash-verifiable. Before any submission or further diagnostic, include this correction as a separately reviewed addendum so the older PF B-token failures are not presented as tests of the configured PF A provider token. No support message or packet submission occurred during this fix.
