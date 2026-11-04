# Persistent mobile resource consent

Status: **local persistence/API/issuance integration verified; live service activation UNVERIFIED**. No real policy database, PF/Entra permission, Vault role, public route, phone install, Microsoft request or billing setting changed. All new grants in this milestone are temporary test records.

## Approval is separate from enrollment

`src/mobile/resource-consent.ts` implements fixed-profile resource terms, approval, status and revocation. Device enrollment alone creates no resource grant. Approval needs an independently verified, same-instance mobile request with purpose `/v1/mobile/access/approve`, the exact signed body hash, fixed terms hash and `auto` or `manual` mode. Scopes, resources, human, organisation, agent and duration come exclusively from protected server configuration and verified evidence. Neither a chat message nor a permission-status request can be repurposed into approval or execution.

Approval creates one interactive grant per configured capability, with separate grant IDs for Copilot invocation and document reading. Resource consent has its own reference, distinct from device enrollment consent. Every grant expires at the original absolute device-enrollment deadline, never 30 days from a later unlock/approval. Original PF issuer, audience and authentication time remain recorded; no fresh PF authentication is invented.

## Atomic policy-store extension

`PolicyStore.prepareMobileResources` explicitly creates a sealed version-1 mobile extension comprising metadata, resource consents and grant bindings. The default store still uses its existing schema/version 5 and never enables this extension automatically. All related grant, binding, consent and policy-audit writes use the same SQLite connection/transaction. A failure halfway through two-capability creation rolls everything back.

The profile seal covers exact login-to-principal bindings, registered agent/organisation, fixed resource terms and creator workload. Drift, missing seal or orphaned extension tables fail closed; they do not import fixtures or reset state. Admission is capped at 256 enrollment/consent pairs, with no deletion of revocation histories to make space. Persistent deployment still needs protected storage, maintenance and the selected one-day audit-retention policy.

Repeated approval for an already active pair is idempotent and returns the existing grants. Revocation atomically revokes both policy grants and writes a permanent tombstone for that enrollment/consent pair. Revoking before first approval also writes an audited tombstone. Neither auto nor manual requests can restore the same revoked pair: a fresh verified PF enrollment/consent flow is required. This preserves revocation across process restart without changing historical PoC allowances.

After creating grants, the service revalidates device/current policy and cancellation before acknowledging success. Failed post-checks revoke the committed bundle. Cleanup can revoke owned records even if the agent was suspended during the request. Cancellation before creation prevents a grant; cancellation discovered after creation triggers revocation. A verified explicit revocation is allowed to finish even if the client loses its response. A network abort cannot be treated as proof that no server action occurred.

## Signed API paths and execution gate

| Method/path | Input | Result |
|---|---|---|
| GET `/v1/mobile/access/terms` | No identity or scope input | Fixed description and terms hash |
| POST `/v1/mobile/access/approve` | Signed flat JSON: `termsHash`, `mode` | Approval status and absolute expiry |
| POST `/v1/mobile/access/status` | Signed empty object | Approval/revocation status |
| POST `/v1/mobile/access/revoke` | Signed empty object | Durable revocation status |

These routes are only handler source; no listener was opened. Existing strict parsing is shared through `flat-json.ts`, including duplicate escaped-key rejection. Request proofs bind the exact path and raw body. The foreground signer admits only chat and the three fixed access-operation paths; arbitrary paths remain forbidden. Grant IDs are not returned to the phone.

The chat API now requires the resource-consent gate even when an executor is configured. Missing consent configuration returns unavailable; absent/revoked consent denies execution. The actual short-lived authority can use the consent service as a live grant resolver rather than a frozen grant list. Fixed and dynamic sources are mutually exclusive, with no fallback on resolution failure. Every issuance rechecks current grant state/version before release.

These grants are not access tokens. The acting-agent signature, gateway identity, hardware-assurance policy, protected assertion signer, actual PF A/B exchange and downstream audience-specific verification remain separate requirements. Strict hardware-attestation mode still rejects the current unverified device-assurance evidence. Nothing here grants Entra identities or changes Sites.Selected permissions.

## Verification and remaining work

834 backend production, 372 simulation and 33 mobile tests pass; web typecheck/build passes. Native sources were unchanged, retaining the previous 12-test checkpoint. Tests close/reopen a real temporary SQLite policy database, reuse persisted bindings during actual JOSE issuance, and verify revocation without restart. They cover wrong terms/body/purpose, serialized evidence, profile drift/seal removal, rollback, post-check suspension/cancellation, audited pre-approval revocation and absence of a consent-gate bypass. HTTP round trips use the actual client/handler/device authority with explicit browser/hardware/final-answer fixtures, never live PF or Microsoft.

The transport methods and signed request paths are implemented, and the [live-preview consent controls](mobile-consent-controls.md) now connect the native preference, manual page and revoke action to these endpoints. No APK was rebuilt or installed for the original backend milestone; the later UI candidate was built but remains uninstalled. Next: compose protected issuer/exchange/executor services and prepare the concrete persistent activation review. Site-wide document retrieval and live mobile Copilot acceptance remain unverified; existing sample-only/one-question deployments are not reopened.
