# Review: one fresh sample-content attempt after metadata correction

Status: PREPARED, NOT APPROVED OR RUN. The first content probe stopped after one Graph metadata200 response and made zero content/download requests. Its failed receipt is spent and unchanged. The exact mismatched metadata field was not captured; do not claim a confirmed root cause.

## Local correction and diagnostic limits

The old validator compared optional parentReference.siteId byte-for-byte with the configured composite site ID. Local reproduction rejects an otherwise identical DNS/GUID site ID with uppercase letters. Correct only that comparison to accept equivalent DNS/GUID case. Continue requiring the same site collection/web/unique-file GUIDs, drive, item, filename, text MIME, bounded size and version. Opaque drive/item IDs remain case-sensitive. A negative different-site test still denies before any content request.

Added fixed failed-check names (item,name,size,version,mime,drive,parent_site,site_collection,web,unique_file) to metadata-failure evidence. No mismatched values, token, URL/query, raw body or file text is recorded. This fixes a demonstrated compatibility defect and makes the next failure diagnosable; it does not prove the first response's parent ID actually differed only by case. No further mismatch triggers an automatic validation change or retry.

Microsoft describes parentReference.siteId as the composite site identifier, and sharepointIds.siteId/webId/listItemUniqueId as GUIDs:
- https://learn.microsoft.com/en-us/graph/api/resources/itemreference?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/resources/sharepointids?view=graph-rest-1.0

## Exact fresh allowance

Run cdfd1f86-be8c-4d2c-b124-4441ef90bf15; plan SHA25676d9e42c31d53b95d79aee301050190c95c6f15eee13bd9fe3234870e44a16ad.

Authorize one fresh owner-operated content/integrity probe on the exact existing201-byte federated-copilot-poc.txt in FederatedCopilotPoC. All site/drive/item/unique IDs, expected SHA256, credential identity and content limits in docs/sharepoint-content-probe-review.md are unchanged and hash-bound in this new packet. Expected SHA256 remains d37938e1dd000ca43886ac0a36806e7218e70b7f92a1cbca68ea5926adeb9a09.

At most one new broker certificate token acquisition,two exact Graph GETs (metadata then version-bound /content),one optional same-host/same-unique-file SharePoint download GET and one sample body of201 bytes. No second redirect, bearer/cookie forwarding, other file/site, listing/search, writes/uploads, scope/credential/IAM/PF/portal/publication/public route/billing changes, administrator fallback, Copilot test or autonomous grant. No text, raw response, signed URL, assertion or token in persisted/chat results. Return only integrity/hash/counters and fixed failure metadata. Stop on any unexpected result without retry.

This remains an explicitly approved local operator transport test, not external PF human/agent document authority. It creates no synthetic PF proof/grant and cannot activate a public document tool. Federated document read acceptance remains UNVERIFIED even if the operator integrity test succeeds.

## Preserve history and apply

Original run9401e5d2-5974-4eb7-ab76-95e02190de76 and its failed budget receipt are retained. Its exact manifest/approval/review/source/config/public trust snapshots were archived under .local/sharepoint/content-probe-initial-spent after verifying all old hashes. Original root receipt/manifest/approval files remain. No spent allowance was reset. The new UUID has its own manifest, approval, receipt and result path. The new manifest additionally pins the failed predecessor receipt, original review and current Vault transport/public TLS/reader-certificate dependencies.

Before execution, verify content-probe-manifest.cdfd1f86-be8c-4d2c-b124-4441ef90bf15.json and record explicit approval in content-probe-approval.cdfd1f86-be8c-4d2c-b124-4441ef90bf15.json. Start within one hour; check exact unexpired approval before credential acquisition, each operation and release. Reserve each attempt/request durably before external action under an exclusive lock. Failure, uncertainty or success spends this run. Preserve all records, never delete/reset to retry. Existing60-second total,15-second token,10-second read and16KiB metadata limits remain. No secret/source trust is widened.

Apply only after approval with node --experimental-strip-types scripts/sharepoint/content-probe.ts --run --approved-plan 76d9e42c31d53b95d79aee301050190c95c6f15eee13bd9fe3234870e44a16ad. The command without --run is offline preparation only.

Validation:665 production tests and372 baseline simulation tests pass. New failing-first equivalent DNS/GUID-case compatibility and different-site rejection test, plus check-name-only diagnostic test, pass. All existing policy, revocation, uncertainty, budget, redirect and no-secret tests remain green. This new attempt needs explicit approval because the original failed run is spent. No new live request has been made while preparing the correction.
