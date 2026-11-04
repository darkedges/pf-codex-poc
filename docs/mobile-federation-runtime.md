# Mobile federation runtime

The server-only runtime now composes device evidence, persisted resource consent, current registry policy, Vault Transit signer interfaces and two separately authenticated PingFederate exchanges. It opens no listener, loads no credentials and changes no PF configuration. Build separate runtime instances for `copilot.invoke` and `m365.document.read`.

The authority requires original same-instance device evidence and an independently signed registered-agent assertion. Each PF hop uses its own `private_key_jwt` client and pinned HTTPS issuer/JWKS/audience profile. Outputs preserve the original human, actor, organisation, delegation, mode, resource, original login issuer/audience/authentication time and device-presence time. A child token cannot outlive its parent. Credential-bearing POSTs are not retried; missing audit, cancellation, substitution, revocation and dependency failures deny release.

After issuance, the broker authorization hook accepts only a token issued by that runtime instance, independently verifies its PF B signature and audience, and rechecks the original device session and resource grant. An otherwise valid out-of-band PF token is denied. Leases are bounded, in memory, and cleared on shutdown; restart requires fresh issuance. No messages or raw access tokens are persisted by this module.

The protected composition requires distinct Vault Transit signer instances and rejects development signers or mock mode. Tests exercise the actual signer protocol against synthetic transport and generated fixture keys, real temporary device/policy stores, and cryptographically signed PF fixtures. This establishes local protocol behavior, **not live Vault custody or PF acceptance**. Hardware attestation remains **UNVERIFIED**; the explicit unattested PoC option is not activated by this source change.

## Remaining integration

Live mobile federation remains **UNVERIFIED**. Deployment needs reviewed authority/client keys, exact PF mappings and trust pins, hop lifetimes that remain within parent expiry despite clock skew, and renewable workload custody. Existing spent browser-test packets and their bounded runtime are unchanged.

The next executor work must connect broker verification to bounded SharePoint retrieval and multi-turn Copilot execution. All-site document cataloguing and supported format extraction, provider-token renewal for the 30-day enrollment, asynchronous question handling, supervised startup and the public Android return association remain pending. The existing verified single-sample browser answer does not verify those capabilities. No new public route, Microsoft request, permission, billing policy or phone installation is included here.
