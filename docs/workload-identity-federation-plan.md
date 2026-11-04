# Partner B Graph workload identity federation work item

Status: **BACKLOG, NOT IMPLEMENTED**. Requested by the owner on 4 November 2026. The current Graph token source remains `EntraCertificateTokenSource`, using a dedicated Vault-held certificate and the existing Entra broker application. No trust, permission, credential or runtime configuration changes accompany this plan.

## Intended result

Partner B's broker authenticates to Entra with a short-lived assertion from an explicitly trusted external workload issuer, replacing the broker's stored application certificate as the Entra authentication credential. Graph still receives an app-only token for the same broker application. The existing Sites.Selected permission and read-only selected-site grant remain the data boundary.

The workload identity identifies the broker service. It must not reuse a human provider token or relabel a human/agent delegation token as the broker workload. Preserve independent original-human, acting-agent, organisation, resource, mode and active-grant checks around every document operation. Entra workload federation does not supply Graph delegated-user access for external PF users.

## Implementation tasks

1. Define the dedicated Partner B workload issuer and subject, fixed Entra assertion audience, approved algorithm/key IDs, short lifetime and authenticated issuance path. Verify the selected PF profile's compatibility with Entra discovery/JWKS requirements; public reachability alone is insufficient. Document how the workload proves its own identity and where the issuer signing key resides.
2. Prepare one narrowly matched federated identity credential on the existing broker app. Pin exact issuer, subject and allowed audience; avoid wildcard identities. Review persistent issuer/public-route changes separately if needed. Request no broader Graph permissions or new selected sites.
3. Introduce a typed federated Graph token source behind the existing token-source interface. Use the fixed tenant token endpoint and Graph `.default` scope, bounded deadlines, redirect refusal, sanitized errors and explicit certificate/federated configuration. Federation failure must not silently switch to the stored certificate.
4. Add failing-first positive and negative coverage for wrong issuer/subject/audience/key/algorithm, expired/not-yet-valid or overlong assertions, unavailable issuer/JWKS/Entra, untrusted URLs and no-fallback behavior. Specify replay handling and verify actual platform behavior rather than assuming Entra consumes every assertion once.
5. Prepare a bounded live test against the existing approved synthetic file. Verify token acquisition, selected-site read, denied out-of-scope access, human/actor continuity and revocation independently. A successful app-token request alone does not verify the whole delegated document flow.
6. After accepted live verification, switch the chosen runtime explicitly. Retire the old certificate credential through a reviewed migration and recovery procedure; do not remove working credentials before replacement acceptance. Preserve historical evidence, request budgets and audit retention.

## Acceptance

The runtime uses no broker certificate credential when federation mode is selected; its assertion is minted only for the authorized broker workload, and the existing site permission boundary is unchanged. Local negative tests and bounded live evidence establish issuance, failure behavior and the document authorization chain. Until then, workload identity federation remains UNVERIFIED.

Reference: [Microsoft Entra workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation).
