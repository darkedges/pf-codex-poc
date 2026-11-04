# Review: one broker authentication and sample metadata probe

Status: PREPARED, NOT APPROVED OR RUN. Upload the provided synthetic file first; do not spend the attempt on a missing file. Existing SharePoint credential enrollment approval excluded broker token and data requests.

Run166793dc-50f5-4498-9f44-4a8edbca4b02; plan SHA256 dfe2908c24bc2a436f5ad997f19d261f864f6d97e13a3e82b851cae58814f465.

## Exact limits

Authorize one operator-run transport probe using the existing dedicated Vault certificate and broker app cddeda93-51e4-42ad-bba7-b85b38b51b72 in tenant4161be3f-bf2b-41d4-a02b-e6f82b529d53. Retrieve the credential only through its existing exact-record one-use reader. Request at most one broker client-credentials token from https://login.microsoftonline.com/4161be3f-bf2b-41d4-a02b-e6f82b529d53/oauth2/v2.0/token using the registered PS256/x5t#S256 certificate assertion and fixed https://graph.microsoft.com/.default scope.

Use that token for at most two HTTPS Graph GETs:

1. Exact site's id and webUrl: /v1.0/sites/nirvingukhotmail.sharepoint.com,b353bf73-309c-474b-85a2-f3635a7cceff,f8d6bb5e-6c9d-41c8-bd53-0cd08796061e?$select=id,webUrl
2. Exact root file metadata: the same site ID plus /drive/root:/federated-copilot-poc.txt?$select=id,name,size,file,parentReference,sharepointIds

Zero content downloads, broad listing/search, uploads/writes, permission/credential changes, PF issuance, real external-human/agent grant changes, portal/connector/publication/public route changes, Copilot conversations/token POSTs, autonomous runs or billing changes. Do not use an administrator token as a fallback. No signed URL or token is logged/persisted. Returned document content is never requested.

## Sample preparation

The owner uploads examples/sharepoint/federated-copilot-poc.txt to the root of Documents in https://nirvingukhotmail.sharepoint.com/sites/FederatedCopilotPoC. Keep the exact filename and bytes, with no edits/conversion. The supplied file is201 UTF8 bytes, SHA256 d37938e1dd000ca43886ac0a36806e7218e70b7f92a1cbca68ea5926adeb9a09. It contains synthetic test data only. The broker stays read-only; the owner's browser handles the upload using their existing site account. Do not overwrite an unrelated existing file.

The probe verifies the metadata filename, size, MIME, site collection/web IDs and valid immutable item/drive/unique IDs. It saves only a candidate document registry for later review. Metadata alone does not prove the sample content hash. A future content test must verify the actual bytes/hash, separately.

## Authority and failure behavior

This tests the broker application's credential and selected-site metadata permission. It supplies no fake PF human/actor claims and does not claim external federated document authorization. Current production document policy and portal tool integration remain UNVERIFIED/unconnected. An app token is never represented as a delegated PF user token.

Before execution verify the exact source/config/sample/public-certificate/trust/enrollment-receipt hashes in .local/sharepoint/authentication-probe-manifest.json and obtain explicit approval. Record approval with its plan/manifest hash, approvedAt and approved=true. Start within one hour of that approval. Use scripts/sharepoint/metadata-probe.ts --run --approved-plan dfe2908c24bc2a436f5ad997f19d261f864f6d97e13a3e82b851cae58814f465. The default command only prepares an offline manifest, without reading Vault or acquiring tokens.

An exclusive local lock and durable run-specific receipt reserve the token attempt before credential acquisition and each metadata request before sending it. Failed, uncertain or successful attempts are spent, never automatically retried or renewed; restarting cannot reuse an existing receipt. A separately approved future run must have a distinct UUID/plan and preserve this receipt. Budget counters are conservative reservations/source-acquisition counts, not proof that every network request reached Microsoft.

Entra issuance has a15-second timeout, Vault calls existing5-second deadlines, Graph GET/body reads10-second deadlines and16KiB response limits. Wrong site/file, redirect, missing/changed metadata,403/404/429/5xx, invalid credential and unsafe TLS/debug runtime settings stop without retry. Persist no raw Microsoft error body, signed download URL, certificate private key, assertion or access token. No automatic grant repair or permission widening.

Validation:8 new focused tests pass,654 full production and372 baseline simulation tests pass. Coverage includes exact limits/path selection, missing approval, spent/uncertain issuance, wrong site/file/MIME/size/IDs, HTTP failures/redirects and filtering of unexpected signed/content fields. Live app token/Graph acceptance remains UNVERIFIED until this separately approved attempt completes.

Official endpoint references:
- https://learn.microsoft.com/en-us/graph/api/driveitem-get?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
