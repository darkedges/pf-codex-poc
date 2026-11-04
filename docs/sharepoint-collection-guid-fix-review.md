# Review: measured site-collection GUID fix and one sample-content test

Status: PREPARED, NOT APPROVED OR RUN. Both prior content attempts and the metadata diagnostic are spent, preserved and not reset.

## Confirmed cause and exact correction

The approved metadata-only diagnostic returned HTTP200 and confirmed parentReference.siteId is a GUID equal to the configured SPSite/site-collection GUID. Independent drive, site-collection, web and unique-file identifiers match. Our optional parent-site guard expected a composite Graph site ID, so it rejected valid metadata before any /content request.

Accept only these parent-site representations when the optional field is present:
- The exact configured composite site identifier, with DNS/GUID case equivalence.
- A GUID exactly equal to the configured site-collection GUID, with GUID case equivalence.

Do not accept the web GUID, another GUID/site, a URL, whitespace-padded identifier, null or empty value. Existing behavior when the optional field is absent is unchanged. Independently mandatory drive/item/name/size/version/MIME/sharepointIds.siteId/webId/listItemUniqueId checks remain. Opaque drive/item IDs stay case-sensitive. Do not derive any network destination, scope or authority from the returned parent reference. The real document adapter still requires a separately verified PF document-audience proof and current external policy; this test path does not replace that.

Added safe fixed MIME categories and redirect-check names for any later transport failure. They contain no raw MIME value, returned URL/query, file text, token or header. Downloader acceptance is unchanged: text/plain UTF8 only, exact pinned file/host/path, no bearer/cookie forwarding and no second redirect. No automatic broadening follows a diagnostic.

## Exact fresh allowance

Run248c3515-6612-486f-aa12-7b7c70746063; plan SHA25671bbe4a91df29637c161a9979eb462008caec346e442d053e58458305545511f.

One fresh owner-approved operator sample-content/integrity test using the existing Vault certificate for broker cddeda93-51e4-42ad-bba7-b85b38b51b72 in tenant4161be3f-bf2b-41d4-a02b-e6f82b529d53. Target only the already uploaded federated-copilot-poc.txt in https://nirvingukhotmail.sharepoint.com/sites/FederatedCopilotPoC, with the exact immutable site/drive/item/unique IDs in infra/sharepoint/content-probe.json and the actual verified metadata receipt. Expected201 bytes/SHA256d37938e1dd000ca43886ac0a36806e7218e70b7f92a1cbca68ea5926adeb9a09.

At most one new broker certificate token acquisition,two exact Graph GETs (selected item metadata and version-bound /content),one optional same-host/download-path/UniqueId-pinned SharePoint GET and one201-byte content result. No extra file/site, listing/search, writes/uploads, permission/credential/scope/PF/policy/portal/publication/public-route/billing change, administrator fallback, Copilot test or autonomous grant. Zero file text, signed URLs, raw headers/bodies, assertions, tokens or private keys in persisted/chat output. Compare actual bytes/hash, then return only integrity/hash/counters and fixed diagnostics.

This tests app-level transport and sample integrity only. It creates no PF human/actor/grant, uses no copilot.invoke permission and cannot establish external federated document authorization or activate a public document tool. That acceptance remains UNVERIFIED even if the sample read succeeds.

## Failure, history and verification

Use a new UUID-specific manifest/approval/receipt/result. Pin the confirmed diagnostic, both failed predecessor receipts/archive summaries, source/config/sample, existing custody proof and public TLS/reader/signing trust. Earlier packets remain unchanged historical evidence; do not update their hashes to absorb the correction. Original review docs are retained for history, while this packet defines the corrected parent-site rule.

Verify exact explicit approval within one hour at startup, before credential acquisition, every outbound operation and result release. Preflight public local Vault health under the exclusive lock before reserving this fresh attempt; an unavailable/sealed Vault stops without token reservation. Persist each request reservation before it can be sent. Existing receipt blocks reuse. Failure, uncertainty or success spends this run; no automatic retry, repair, renewal or reset. Reservation counts are conservative bounds rather than delivery proof.

Existing60-second total,15-second Entra,10-second read,16KiB metadata and201-byte sample-body limits remain. Record only fixed phase/status/check-category metadata in the minimal spent receipt. Keep existing audit controls. No real call has run while preparing this correction.

Validation:672 production and372 baseline simulation tests pass. New failing-first tests reproduce the observed GUID representation, accept only the pinned collection/composite, and prove matching parent collection cannot replace mandatory drive/site/web/file bindings. Negative MIME/redirect tests verify fixed diagnostics without changing acceptance or leaking secret queries. All existing actual PolicyStore identity substitution/mid-read revocation, uncertainty/budget, timeout and no-secret tests pass.

After approval, record exact plan/manifest hash and approvedAt in content-probe-approval.248c3515-6612-486f-aa12-7b7c70746063.json. Run node --experimental-strip-types scripts/sharepoint/content-probe.ts --run --approved-plan 71bbe4a91df29637c161a9979eb462008caec346e442d053e58458305545511f. Without --run the command only prepares offline. No old allowance covers this new token/read: explicit approval is required.
