# Editorial source map

This file is an editorial aid, not an additional Dev.to post. All references below are repository-relative. Article claims are based on their most recent relevant evidence, not an older milestone's stale future-work label.

| Article | Project evidence and implementation |
|---|---|
| 1 | `README.md`, `AGENTS.md`, `docs/architecture.md`, `docs/threat-model.md`, `src/services/`, `src/lib/policy.ts` |
| 2 | `docs/gateway-2-production.md`, `docs/pingfederate-containers.md`, `src/adapters/`, `scripts/pf/common.mjs` |
| 3 | `docs/delegation-policy.md`, `docs/browser-consent.md`, `docs/authority-service.md`, `docs/vault-containers.md`, `docs/mobile-staging-review.md`, `src/policy/`, `src/mobile/workload-lease.ts` |
| 4 | `docs/power-platform-environment.md`, `docs/copilot-generic-oauth-settings.md`, `docs/copilot-provider-token-fix.md`, `docs/copilot-sixty-minute-success.md`, `docs/copilot-provider-header-transport.md`, `docs/copilot-interactive-tool-success.md`, `src/adapters/direct-line.ts` |
| 5 | `docs/sharepoint-broker-setup-review.md`, `docs/sharepoint-admin-grant-review.md`, `docs/sharepoint-document-adapter.md`, `docs/sharepoint-collection-guid-fix-review.md`, `docs/document-chat-live-success.md`, `docs/document-chat-single-login-review.md`, `src/m365/` |
| 6 | `docs/ionic-android-migration-plan.md`, `docs/mobile-device-authority.md`, `docs/mobile-browser-lifecycle.md`, `docs/mobile-execution-authority.md`, `docs/mobile-live-composition.md`, `docs/mobile-activation-review.md`, `docs/mobile-refresh-scope-amendment.md`, latest `docs/implementation-plan.md` and `docs/decisions.md`, `apps/mobile/`, `src/mobile/` |

## Status decisions that override historical descriptions

1. Real PF A/B and Vault verification does not prove a Microsoft channel flow.
2. The provider-token mismatch was a proven defect. It does not identify the cause of every historical expiry response.
3. The later one-hour provider test succeeded. It does not establish a universal minimum lifetime.
4. The renamed connector parameter restored the observed managed transport. It does not establish a platform-wide rule about header punctuation.
5. Graph transport and sample integrity were verified before the separately authorized federated document chain.
6. The browser document result is verified for one synthetic sample. Broader discovery and multiple documents have local coverage, not equivalent live acceptance.
7. The mobile backend is activated and v5 installed. The owner reports no browser redirect; phone sign-in is unresolved. A suspected CSP issue was withdrawn after inspecting the built live artifact.
8. APK distribution is verified independently of sign-in. The temporary live URL and artifact hash are omitted from the articles because they are deployment-specific and expire.
9. No article turns root access, broad administrator setup consent or the Microsoft trace exception into production approval.

## Primary external references used

- [OAuth token exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [PF token endpoint](https://docs.pingidentity.com/pingfederate/13.1/developers_reference_guide/pf_token_endpoint.html)
- [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Vault certificate authentication](https://developer.hashicorp.com/vault/docs/auth/cert)
- [Copilot Generic OAuth SSO](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-sso-3p)
- [Copilot authentication configuration](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configuration-end-user-authentication)
- [Copilot sensitive-data limitations](https://learn.microsoft.com/en-us/microsoft-copilot-studio/voice-sensitive-data)
- [Selected Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-selected-overview)
- [Entra certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)
- [Android biometric cryptography](https://developer.android.com/identity/sign-in/biometric-auth)
- [Android Keystore](https://developer.android.com/privacy-and-security/keystore)
- [Android App Link verification](https://developer.android.com/training/app-links/verify-applinks)
- [Dev.to editor guide](https://dev.to/p/editor_guide)
- [Forem fenced Mermaid support](https://github.com/forem/forem/pull/23764)

Product documentation was checked during preparation. Tenant UI, entitlements and service behavior remain version-dependent. No private configuration files or raw conversation captures were consulted to populate article examples.
