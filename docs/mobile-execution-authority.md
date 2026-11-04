# Mobile resumed-interactive execution authority

Status: **local authority integration verified; live PF exchange and mobile Copilot acceptance UNVERIFIED**. No running service, real grant, issuer/key trust, Vault custody, PF configuration, public route, billing policy or installed phone app changed.

## Device presence is not a fresh PF login

The existing `GrantAuthority` and `PolicyStore.authoriseConsentedGrant` interactive path retain their recent-PF-login checks. They are not weakened for mobile use. `src/mobile/execution-authority.ts` introduces a separate server-private issuance path with `authentication_basis: registered-device-key`. Assertions preserve original login issuer, audience and authentication time, original human `sub`, registered `act.iss`/`act.sub`, organisation, interactive mode, resource, scope and independent resource delegation ID. No current timestamp is substituted for original PF authentication.

`MobileDeviceAuthority.authorize` now returns deeply immutable evidence registered in an instance-private WeakMap. `revalidateEvidence` requires the original object from that exact instance, checks current session/enrollment/consent, re-runs current policy and enforces its original expiry. JSON copies, chat/header identity fields and evidence from another instance cannot be reconstructed into authority. Revalidation does not extend the request lease. It must remain inside the trusted process; a future cross-process handoff needs independently authenticated, replay-protected transport rather than serialized evidence accepted on trust.

## Current registry and independent resource consent

`createMobileRegistryCheck` binds exact verified login issuer/subject/audience tuples to existing human principal IDs. It reads current organisation, human and agent state from `PolicyStore`, verifies the registered agent issuer/subject and exact configured capabilities, and fails closed on unknown/suspended/mismatched records. An explicit virtual-issuer binding is distinct from downstream PF token-issuer trust. No external human is provisioned in Entra.

`MobileExecutionAuthority` additionally requires a protected enrollment/device-consent → resource-grant binding. The resource consent reference must be separate from the device enrollment consent. It verifies the actual current grant's version, creator workload, human/agent/organisation, active state, expiry and consent reference. Grants must have exactly one configured scope, one configured resource and interactive mode only; multi-scope or autonomous grants are rejected. Grant expiry cannot exceed device enrollment.

The class does **not** create resource grants, infer permission from a device enrollment, reuse old disposable approvals or accept a grant ID from the phone. The [persistent consent service](mobile-resource-consent.md) now implements the separate approval/creation path and live binding resolver in source. Fixed lists and live resolvers are mutually exclusive, with no fallback. Deployment review and protected custody remain required. The mobile API's strict chat body remains only `question`; identity, scopes and resources cannot be supplied there.

## Acting agent, signing and audit

Issuance requires both the gateway's authenticated actor context and an independently signed registered-agent assertion. RS256 key ID, issuer, subject, audience and scope are pinned. Actor tokens last at most 60 seconds and their JTI is consumed durably through `PolicyStore` for their entire validity. Failed or timed-out signing does not permit automatic assertion reuse. Workload, operation and organisation must match the configured endpoint and handset evidence.

The resulting assertion is bounded by all of: 60 seconds, remaining device-request evidence, acting assertion and current resource grant. Signing is injected through `AssertionSigner`, compatible with the existing protected Vault signer; there is no generated-key or mock fallback. Before release, JOSE independently verifies the configured public key, exact header/issuer/audience and full requested payload. Signer substitution of a human, actor, grant, scope or any other claim fails closed. Device, registry and grant state are checked again after signing and audit. A bounded issuance deadline covers asynchronous dependencies; late completion cannot release a token.

An audit callback is mandatory and failure/timeout prevents release. Its fixed event contains the grant/version, scope/resource, organisation, issuer/audience and hashed human/actor references, without raw subjects, tokens, proof headers, URLs or messages. `mobile.assertion.authorized` records an issuance decision, not delivery or Microsoft acceptance. Actual deployment must provide durable protected storage under the owner's Windows account, the selected one-day retention and bounded journal policy; no new audit service or key was enrolled here.

## Hardware assurance remains explicit

The device implementation enforces strong hardware-backed biometrics locally, but the server has not verified remote hardware attestation. Evidence and assertions therefore retain `hardware_attestation: UNVERIFIED`. The strict `require-hardware-attestation` profile denies this evidence. An `allow-unattested-poc` profile must be explicitly configured; nothing silently selects it. Using it live would be a trust-policy change requiring inclusion in the concrete deployment approval. It grants nothing without the independent resource grant, agent proof and current policy checks.

## Verification and next integration

829 production and 372 simulation tests pass; the existing 32 mobile and 12 Android checkpoints remain valid. Local tests use actual JOSE signatures and SQLite policy/device stores. They cover reconstructed/mutable evidence, wrong issuer/agent/audience/workload, replay, excessive actor-token validity, broad grants, device-only consent substitution, strict hardware-assurance denial, signer claim substitution, timeout, failed audit, suspended agent and revocation during signing. Failing-first cases captured excessive actor validity, broad grants and missing audit enforcement before correction. No actual Vault/PF/Microsoft request occurred in this milestone.

Next runtime work: connect reviewed resource consent and binding persistence; configure protected actor/authority custody and durable audit; compose the real PF A/B exchange and verify its complete identity/audience/resource continuity; then connect the multi-turn/document executor. The authority assertion is neither a PF access token nor a Graph delegated-user token and must never be sent directly to Graph or Direct Line. Existing sample-only/one-question Copilot code is not silently converted into site-wide persistent chat. Public/persistent activation, the PoC assurance exception and PF trust changes must wait for a concrete reviewed deployment.
