# Review: read-only SharePoint broker registration

Status: PREPARED, NOT APPLIED. Owner created the site and requested automated integration. This packet requests the additional application/permission changes only.

Tenant:4161be3f-bf2b-41d4-a02b-e6f82b529d53. Existing administrative identity:admin@nirvingukhotmail.onmicrosoft.com.

Approved target proposed for this setup:
- Site:https://nirvingukhotmail.sharepoint.com/sites/FederatedCopilotPoC
- Immutable site ID:nirvingukhotmail.sharepoint.com,b353bf73-309c-474b-85a2-f3635a7cceff,f8d6bb5e-6c9d-41c8-bd53-0cd08796061e
- Resource alias for later broker policy:sharepoint:approved-research. No policy entitlement is changed in this setup.

Read-only preflight resolved this exact site, confirmed the existing administrative tenant and found no same-name broker application. Microsoft Graph service principal f8407232-7631-4fb5-a3e4-96761270021c advertises enabled application role Sites.Selected,883ea226-0bf2-4a8f-9f9d-92c9162a727d. Metadata queries did not read documents or change permissions.

## Exact requested changes

1. Create one single-tenant application named copilot-m365-resource-broker with only Microsoft Graph application Sites.Selected requested. No password, certificate, redirect URL, user provisioning or delegated permission.
2. Create its one service principal.
3. Assign only the identified Sites.Selected application role to that new service principal (administrative consent).
4. Grant that app only roles:[read] on the exact site above.
5. Independently read back the assignment, selected-site grant, application audience/requested permissions, empty credential collections and empty redirect URLs.

Sites.Selected consent alone does not grant access to every site. The explicit selected-site grant supplies read access to this one site. No Sites.Read.All, Files.Read.All, Sites.FullControl.All or write/manage/fullcontrol role is assigned to the broker. Existing administrator authority performs setup and is never copied to the runtime. No new admin authority is requested for the operator or another app.

This phase creates no usable broker credential, starts no runtime and makes no document read or Copilot conversation/token POST. Certificate/Vault custody, the actual Graph data adapter, external human/agent/grant policy binding and a bounded live data test remain separate tasks/reviews. Existing public routes, billing/trial settings, published connector and spent allowances stay unchanged. Existing PoC trace exception does not authorize routing Graph credentials through model/tool inputs.

## Application procedure and failure handling

The offline plan is produced by node --experimental-strip-types scripts/sharepoint/setup.ts. Frozen plan hash:e1e824b98ddf87eb1588cafbb2ff6ba9117a6fa0a0eedb0644c6c11b8113a2f3.

After explicit approval only, apply with node --experimental-strip-types scripts/sharepoint/setup.ts --apply --approved-plan e1e824b98ddf87eb1588cafbb2ff6ba9117a6fa0a0eedb0644c6c11b8113a2f3.

An exclusive local lock protects the setup; current tenant/admin identity is rechecked before every mutation. Re-resolve the exact site and Graph role and refuse an existing same-name app before creation. Persist intent and each returned owned identifier in .local/sharepoint before progressing. A lost response, partial write or unexpected response stops without retry/deletion/rollback. Any existing receipt blocks another application, requiring independent reconciliation of the existing attempt. No refresh of missing permissions or blind regrant. Each external request has a60-second deadline and bounded output; errors omit raw Graph responses. No access token is saved or printed.

The frozen source/config/test hashes and this review hash are recorded in .local/sharepoint/setup-review-manifest.json. Reverify those exact bytes and the plan hash before applying. Stop on drift.

Validation:10 focused tests,628 full production tests and372 baseline simulation tests passed. Covered invalid URL/site/tenant/extra configuration, missing approval, wrong or changing administrator identity, duplicate app refusal, ambiguous pagination, uncertain creation without retry, exact four writes, final read-only grant and no credential/redirect/broad-permission drift. PowerShell syntax and the live metadata-only transport passed. Live setup/read access remains UNVERIFIED.

Approval is required because this creates a persistent application/service principal and grants a tenant application role plus selected-site data access. It does not buy a subscription, grant tenant-wide document access or authorize additional live Copilot attempts.
