# Review: one exact synthetic sample content read

Status: PREPARED, NOT APPROVED OR RUN. Prior metadata allowance is spent and is preserved. No file content has been downloaded yet.

Run9401e5d2-5974-4eb7-ab76-95e02190de76; plan SHA2561be997842852b3afac7d4ace01319e87c2dbfe052bd221adc0d5e5850c1172b5.

## Exact target and limits

Use the existing Vault-backed broker app cddeda93-51e4-42ad-bba7-b85b38b51b72 in tenant4161be3f-bf2b-41d4-a02b-e6f82b529d53. Authorize at most one new broker client-credentials token acquisition and one read of the owner-uploaded synthetic sample, using only these previously verified immutable IDs:

- Site:https://nirvingukhotmail.sharepoint.com/sites/FederatedCopilotPoC
- Site ID:nirvingukhotmail.sharepoint.com,b353bf73-309c-474b-85a2-f3635a7cceff,f8d6bb5e-6c9d-41c8-bd53-0cd08796061e
- Drive:b!c79Ts5wwS0eFovNjWnzO_1671vidbMhBvVMM0IeWBh4wXgL5yTfPQIa7JvmlTFAI
- Item:01NWNSTC4MOUGXJAZPXREYRNB6KXV5FOEB
- Unique ID:740d758c-2f83-49bc-88b4-3e55ebd2b881
- Name:federated-copilot-poc.txt; size201 UTF8 bytes
- Expected content SHA256:d37938e1dd000ca43886ac0a36806e7218e70b7f92a1cbca68ea5926adeb9a09

Allow at most two Graph GETs: exact item's selected metadata, then that item's /content with If-Match for the observed version. If Graph returns302, allow at most one credential-free GET to the exact approved SharePoint hostname's root/site-relative /_layouts/15/download.aspx, only with a single UniqueId matching the pinned file. No second redirect; never forward Graph Authorization or cookies. Total maximum:one Entra token POST,two Graph GETs,one optional SharePoint download GET,one201-byte content result. No arbitrary URLs, listing/search, other files/sites, writes/uploads, permission/credential/PF changes, portal/connector/publication/public route changes, Copilot requests, autonomous sessions or billing changes. Existing tokens are not retrieved from historical logs and administrator-token fallback is forbidden.

Read the existing signing credential only through its approved exact-path Vault reader. Keep the resulting token/assertion in memory only. Compare the actual downloaded byte count and SHA256 with the frozen local synthetic sample. Report only integrity success, safe counts, hash and fixed phase/status failure metadata. Do not persist or print file text, token, signed download URL, raw HTTP bodies/headers or private key. Any size/MIME/ID/version/hash/redirect/service mismatch consumes the attempt and stops.

## Authority and acceptance

This is an owner-approved local operator transport/integrity test. It is not the public delegated tool, creates no PF user/actor or grant, supplies no synthetic PF identity and does not reuse a copilot.invoke grant. It proves only the actual broker application's selected-site content transport and exact sample bytes. External PF human/agent document authorization, document-audience issuance/current-policy integration and portal/Copilot document access remain UNVERIFIED even if this test passes. The candidate file registry itself grants no access.

The production GraphDocumentAdapter still requires configured trusted proof verification and independent current human/actor/org/grant/mode/scope/resource policy before requests and release. Shared approved-content.ts transports the constrained request only; it is not an HTTP API and cannot authorize a caller. The operator probe's authorise callback instead checks its separate explicitly reviewed, unexpired durable allowance before credential loading, every request and final result. Do not use the operator test path to serve a user/tool.

## Budget and failure controls

Freeze source, sample, configuration, public credential and original metadata/enrollment evidence in .local/sharepoint/content-probe-manifest.json. Verify those exact files and owner approval before starting and before each operation/release. Start within one hour of approval; rechecking that freshness cannot renew it. An exclusive lock and run-specific spent receipt reserve issuance before credential acquisition and each outbound request before sending. Success, failure or uncertainty permanently consumes this run; no automatic retry, restart renewal, repair or permission broadening. Preserve all prior spent receipts/manifests. A future separately approved run needs a new UUID/plan, not deletion/reset of this receipt.

Enforce a60-second overall probe deadline, existing Vault5-second calls,15-second Entra issuance timeout and10-second outbound read deadlines. Metadata is bounded16KiB, sample body201 bytes. Fixed failure phases/HTTP status may be kept in the minimal spent receipt, without signed URLs or document text. Existing one-day application audit policy stays unchanged. Reservation counters are conservative upper bounds; they do not prove every attempt reached Microsoft.

## Validation and execution

Validation:663 production tests and372 baseline simulation tests pass. Nine new operator-probe tests cover exact budgets, missing/revoked approval before credential acquisition and before release, uncertain issuance without retry, integrity mismatch, same-file redirect without bearer/cookie, no content/token in results and unsafe config. All13 existing policy-document tests still pass, including actual PolicyStore identity substitution and mid-read revocation. The common transport was refactored to avoid implementing a weaker test-only downloader. Earlier fulfilled credential and metadata review packets remain immutable historical evidence; their hashes were not refreshed to absorb new source changes.

After explicit approval only, record plan/manifest hash and approvedAt in content-probe-approval.json. Run node --experimental-strip-types scripts/sharepoint/content-probe.ts --run --approved-plan 1be997842852b3afac7d4ace01319e87c2dbfe052bd221adc0d5e5850c1172b5. The command without --run only prepares offline and performs no Vault/Microsoft request. Preserve the run-specific receipt and content-probe-result.9401e5d2-5974-4eb7-ab76-95e02190de76.json. Independently confirm the final counts/integrity and unchanged predecessor metadata/custody evidence. Do not repeat the attempt to diagnose a failure.

This needs new approval because the fulfilled metadata packet explicitly allowed zero content downloads and its one-token allowance is spent.
