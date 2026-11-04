# Copilot support evidence bundle

Prepared 2026-10-31 Australia/Sydney. The user confirmed that no Microsoft support case exists and then explicitly approved submission of this exact packet. **Approved; not submitted: browser and Windows computer-use kernels failed to initialize, including after reset.** No support form was reached and no case was created. The separate protected `submission-status.json` preserves approval and verified packet hashes for resumption. No new Microsoft conversation, token POST, tenant change or billable diagnostic was performed.

The remaining observed product failure is Generic OAuth secure token-post HTTP 400. The latest recorded request ID is `320cc71fbead2f79d8b9e025737fc8ed`, at 2026-10-30 08:41:03–08:41:14 UTC / 19:41:03–19:41:14 AEDT. Its signed challenge still had about 57 seconds against host time / 58 against provider Date, and the independently validated PF tool JWT had 119 seconds left. Those measurements do not identify which Microsoft-side object was considered expired.

Microsoft's [current Generic OAuth SSO documentation](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-sso-3p), reviewed on 2026-10-31, still describes the OAuth card secure URL and a JSON token POST, and includes clients using Direct Line. No concrete protocol correction was established by that review. The sample cannot establish this tenant's service-side connection/session validation. Do not spend another allowance on an unchanged blind retry.

## Export command and files

`npm run copilot:support-bundle` reads only the known current-agent settings, three historical allowance records, known live-run JSON metadata and five specific local verification receipts. It creates a new protected directory under `.local/tool-vault/support-<uuid>` with:

- `support-case.md`: reviewable case text, four failure windows, three available Microsoft request IDs and bounded lifetime measurements. The oldest request ID was not captured and is explicitly marked missing.
- `evidence.json`: schema-projected non-secret target IDs, the four attempts, local proof counts and consumed allowance totals.
- `manifest.json`: hashes of the two shareable files, zero raw attachments and an explicit not-submitted marker.

The exporter performs no network request, submits nothing, does not alter historical budget reservations and does not stop/restart the running private service. Existing four allowances remain fully consumed; export is not a new allowance. It does not read a Direct Line secret, PF/Vault bootstrap, private key, clipboard, transcript or arbitrary input path. It never attaches the entire `.local` tree.

Source receipts are not copied. Unknown fields are excluded, expected strings use fixed enums/identifier/date validation, measurements are bounded integers and malformed expected fields stop the export. Raw vendor bodies, cookies, signed URLs/query values, access/authorization/validation tokens, raw human/agent/grant IDs and source file paths are excluded. The packet includes environment/agent identifiers intended for support; review those identifiers before sharing. This is a schema-based export of known receipts, not a general-purpose redactor for arbitrary HARs/logs.

Run end times use recorded completion where available, otherwise the result file modification time, explicitly labeled an approximate trace window. Unmeasured older lifetimes remain unavailable. New local proof does not retroactively change the evidence or timing of older Microsoft requests.

## Evidence and next external step

The generated packet includes the 47-check enrolled consent canary, 11 lifecycle checks, seven command/crash checks, 14 persistent-policy checks and eight enrolled-Vault checks, each with its own recorded timestamp. None claims Microsoft/Copilot acceptance. The current local resource service separately remains ready; no service command was invoked by export.

Seven failing-first projection/privacy/allowance tests and all **281 baseline tests** pass. The production adapter is unchanged; its prior **283 passing production tests** remain separate evidence. The exporter prepared all four historical token-post traces without a new external request. The older support draft's initial three-attempt count is superseded by this four-attempt bundle and its latest retry section.

Submission is explicitly authorized; no repeat approval is needed for this same packet and scope. Resume when browser/computer-use tooling works, or submit manually through the existing Power Platform admin center: **Support > Support requests > Get support**, following Microsoft's [current support instructions](https://learn.microsoft.com/en-us/power-platform/admin/get-help-support). Use the existing entitlement if available; purchasing a support plan or making another Microsoft diagnostic attempt remains unauthorized. Portal entitlement was not inspected and must not be assumed unavailable. Ask Microsoft to trace the latest request ID and identify the expired signed-URL/state/session/connection/token object before deciding on a new bounded diagnostic.
