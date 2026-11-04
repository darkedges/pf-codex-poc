# Microsoft 365 / Entra Application Access (Target)

Sources:
- https://learn.microsoft.com/en-us/graph/permissions-selected-overview
- https://learn.microsoft.com/en-us/graph/permissions-reference

## Identity and permissions

The external human does **not** exist in the Entra tenant. Entra authenticates the **broker workload**, never the user. The broker checks the external subject + agent + grant + resource before exercising app permissions. Graph does not evaluate the external user's ACL. Do not represent this as Microsoft user delegation.

## Configuration

1. Create dedicated confidential application registration `copilot-m365-resource-broker` in the resource tenant.
2. Use managed identity if hosted in a supported Azure compute environment or certificate-based client authentication with proper key custody elsewhere.
3. Grant Microsoft Graph **application** permission `Sites.Selected`, not tenant-wide `Sites.Read.All`.
4. Have an approved administrator grant the application `read` access to individual approved SharePoint site IDs.
5. Store site IDs and resource identifiers in a trusted allowlist, not in Copilot model output.
6. Implement only constrained operations (e.g. read a specified document or search a preapproved index); enforce per-user and per-agent entitlements before Graph calls.
7. Deny unknown sites, nonapproved document IDs, general-purpose Graph URL forwarding, write/delete operations and arbitrary search across a tenant.
8. Use separate application identities and permission reviews if Exchange or Teams functionality is added later.

## Real adapter design

```ts
interface GraphResourceClient {
  readApprovedDocument(input: {
    siteId: string; driveId: string; itemId: string;
    verifiedSubject: string; verifiedActor: string;
    activeDelegationId: string;
  }): Promise<{id: string; name: string; content: string}>;
}
```

Do not implement a real Graph client without a validated policy decision first. Never expose the raw Microsoft app token in a response, Copilot conversation or log.

## Evidence for deployment review

- Entra app manifest + admin consent with application permission only.
- SharePoint selected-site grants with read-only permissions.
- Broker's default-deny cross-organisation entitlement tests.
- Data handling controls (prompt injection, sensitive content limits, outbound filtering).
- Logs proving original external user, agent, delegation and app identity are independently attributable.

## Prepared operator setup

The exact site has been resolved. See [SharePoint broker setup review](sharepoint-broker-setup-review.md) for the proposed credentialless app, Sites.Selected consent and one selected-site read grant. scripts/sharepoint/setup.ts is offline-plan-only by default; --apply requires the exact reviewed plan hash. No setup mutation or Graph document access has been applied. Any partial/uncertain receipt blocks automatic reapplication.

## Verified tenant setup - 2 November 2026

Dedicated single-tenant broker app cddeda93-51e4-42ad-bba7-b85b38b51b72 now has only Graph application Sites.Selected and one verified read-only grant on FederatedCopilotPoC. Administrative reconciliation used one POST and independent permission readback. The setup client's newly added delegated Sites.FullControl.All scope was removed, restoring all prior consent records/scopes exactly. The process-only authentication ended. Immediate invalidation of an already issued admin token was not tested.

No broker password/certificate credential exists. No Graph document was read and the portal/data runtime is not connected. Preserve the original partial setup receipt alongside the separate reconciliation/completion receipts. Next gate is dedicated Vault certificate/signer custody and bounded policy-authorized Graph implementation, followed by an explicitly approved synthetic data test.

## Local data adapter - 2 November 2026

[The prepared document adapter](sharepoint-document-adapter.md) and certificate/Vault credential factories pass646 production and372 simulation tests. A separate [credential custody review](sharepoint-credential-custody-review.md) covers generation, exact-path enrollment and public certificate registration only. None of those credential changes or any document/token request has been applied. The current portal still exposes only the completed diagnostic and has no active test allowance.

## Credential enrollment outcome - 2 November 2026

The approved certificate/Vault packet is now VERIFIED_POC_CUSTODY: version1 record, dedicated one-use reader, seven denial checks, unchanged policy/role/pin on rerun, and temporary signing-key staging removed. Exactly one public certificate registration PATCH was followed by independent readback and a second no-PATCH verification of the same public key. Certificate expires2 December2026 at18:41AEDT. No client secret, broker token request, document read or Copilot test. No renewal/retirement scheduler was introduced. Administrative metadata/registration authentication is separate from zero broker client-credentials issuance.

Next gate: exact synthetic file registry, document-audience policy/proof composition and a separately approved bounded authentication/read test. The portal is not connected to SharePoint documents yet; do not activate data access under this fulfilled custody-only approval.

## Authentication/file metadata outcome - 2 November 2026

Approved run166793dc-50f5-4498-9f44-4a8edbca4b02 completed with one actual broker app-token acquisition and two exact metadata GETs. The existing Vault certificate and selected-site grant are accepted by Entra/Graph. Sample filename,text/plain MIME,201-byte size and site binding matched; projected immutable IDs saved as a candidate registry. Zero content downloads, no sample content hash validation, no synthetic PF identities and no claim of federated document authorization. The allowance is spent; see local authentication-probe-confirmed.json. Next gate is a separately scoped content read and real document-policy/proof composition.

## Exact content probe prepared - 2 November 2026

The new [sample-content review](sharepoint-content-probe-review.md) covers one operator-approved201-byte read and SHA256 verification using the actual immutable IDs from metadata. It permits at most one new token,two Graph GETs and one constrained credential-free SharePoint download. No probe has run. Source shares the existing transport with the real document adapter; the latter's13 identity/policy/revocation tests pass. Operator integrity acceptance and external PF document authorization remain separate.663 production/372 simulation tests pass; prior allowances stay spent.

## Parent-site mismatch diagnosed - 3 November 2026

One separately approved metadata-only diagnostic confirmed that this tenant returns the pinned site-collection GUID in parentReference.siteId rather than the full composite Graph site ID expected by our optional guard. Independent drive, site collection, web and file-unique bindings match. No raw returned identifier/token or file content was retained. No validation change occurred in the diagnostic. The needed correction is now concrete: accept only that pinned collection GUID or the pinned composite, keeping the remaining bindings mandatory. Content integrity and external federated document acceptance remain unverified; all diagnostic/content allowances are spent.

## Local measured-ID correction - 3 November 2026

The validator now accepts the measured pinned collection GUID or pinned composite in the optional parent site reference. It still rejects web-only/foreign IDs and keeps full independent site/web/file/drive/item checks.672 production/372 simulation tests pass. A [fresh exact sample test review](sharepoint-collection-guid-fix-review.md) is prepared; it has not run. No old allowance was reset, no IAM/PF/portal scope changed, and actual content integrity/federated document acceptance remain unverified.

## Actual sample content verified - 3 November 2026

Corrected run248c3515-6612-486f-aa12-7b7c70746063 passed actual Vault/Entra/Graph/SharePoint app-level content transport:one broker token,two Graph GETs,one constrained SharePoint download,201 bytes and exact expected synthetic SHA256. Independent frozen-hash/receipt verification passed; previous failed and diagnostic evidence remains unchanged. No file text/token/signed URL was retained in results. The allowance is spent.

This is VERIFIED_APP_SAMPLE_CONTENT only. The operator probe supplied no PF human/actor/grant and did not test external federated document authorization. Portal/Copilot document access remains unconnected until the separately reviewed document-audience proof/current-policy composition is implemented and live-verified.
