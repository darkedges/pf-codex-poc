# Power Platform environment provisioning

## Actual Azure foundation status (2026-10-29)

After explicit human approval, the dedicated Australia East resource group, security group (only the current admin as member) and AUD 50 monthly cost budget were created and read back. Alerts at 50/80/100% use the supplied recipient; the notification period ends 2027-10-01 and is not a spending cap. Power Platform provider registration completed. IDs and resource receipts are private under `.local/power-platform`. No external user accounts, directory roles, purchased licenses or PAYG billing links were created.

**Sandbox not created:** the capacity API returned 403; tenant SKU listing was empty. Browser and native computer-use helpers both failed initialization with a kernel-assets path error. Verify Licensing > Capacity add-ons (or Licensing > Dataverse) in the [Power Platform admin center](https://admin.powerplatform.microsoft.com/) before completing capacity review. The environment draft has the created group ID and retains `licenseAndCapacityReviewed=false`. Actual Sandbox/Dataverse readiness and Copilot publishing remain UNVERIFIED.

The repository can plan and request a Dataverse-backed **Sandbox** or explicitly owned **Developer** environment using Microsoft Power Platform CLI. The default command is offline and makes no cloud changes. Initial script implementation created no cloud resources; the subsequently approved Azure foundation is recorded above.

Validation (2026-10-29): 29 provisioning tests pass, including wrong-tenant denial, exact-plan approval, drift, interrupted creation, duplicate prevention and sanitized errors. The full baseline suite has 67 tests; the production suite has 197. Read-only discovery against the existing authenticated tenant confirms no environments. PAC 2.14.1 emits no JSON for an empty list; the wrapper requires an independent exact English text confirmation before accepting an empty result. Unexpected/partial/localized text fails closed. **UNVERIFIED:** nonempty live listing, creation, readiness schema and Copilot provisioning. No creation was attempted.

Microsoft documents [`pac admin create`](https://learn.microsoft.com/en-us/power-platform/developer/cli/reference/admin) for Dataverse environments. Creation depends on eligible licensing, available capacity and tenant policy; see [environment prerequisites](https://learn.microsoft.com/en-us/power-platform/admin/create-environment). A script cannot supply those entitlements. The `licenseAndCapacityReviewed` flag is an operator attestation, not an entitlement check or a purchase.

## Prepare and preview

Run from the repository root in PowerShell:

```powershell
npm run powerplatform:tools
npm run powerplatform:plan
```

The installer verifies pinned SHA-512 hashes for official PAC 2.14.1 and .NET/Core ASP.NET 10.0.14 Windows x64 packages. It extracts them under ignored `.local/tools`, checks ZIP destination containment and installs nothing globally. Downloads require network access. No .NET SDK is required.

If no suitable PAC profile exists, sign in interactively with an internal maker/admin account:

```powershell
pwsh -NoProfile -File scripts/power-platform/sign-in.ps1 -TenantId '<tenant-guid>'
npm run powerplatform:draft
```

The draft command reads non-secret tenant metadata from the existing active profile into `.local/power-platform/environment.json`; it refuses to overwrite a draft. It does not copy tokens or choose a license. The current private draft uses the approved Sandbox, Australia, AUD and English choices and the created security-group ID. Licensing/capacity review remains incomplete. For future drafts, tenant country alone does not approve a deployment region.

Edit the private draft using `infra/power-platform/environment.example.json` as its schema. Sandbox requires an **existing approved security-group GUID**. Developer requires an explicit internal maker UPN matching the active profile and disallows a group. Neither path provisions external humans in Entra. Only English/1033 is currently supported. Production, Default, arbitrary CLI flags, application credentials and billing/IAM fields are rejected.

```powershell
npm run powerplatform:plan -- --config .local/power-platform/environment.json
npm run powerplatform:inspect -- --config .local/power-platform/environment.json
```

Preview writes a public plan and its configuration hash under `.local/power-platform`. Inspect only reads cloud metadata and local state; it cannot create an environment. Both commands sanitize external errors rather than printing raw CLI output. Current inspection returns `not_found`, with group and license/capacity blockers still present in the plan.

## Apply after discovery and prerequisites are verified

Review the exact tenant, name/domain, region, type, currency, access group/owner and capacity/license consequences in the generated plan. Once all blockers are resolved, apply requires its exact hash:

```powershell
npm run powerplatform:apply -- --config .local/power-platform/environment.json --approved-plan '<reviewed-plan-hash>'
```

The hash binds the configuration; it is not a credential or evidence of human approval by itself. Run apply only after approving the concrete plan. Use a dedicated PAC profile and avoid concurrent profile changes: PAC's authentication cache is shared, and before/after principal checks cannot make external profile switching atomic.

An exclusive local lock and durable pre-create receipt precede the one creation request. Creation is never automatically retried. An interrupted request is recorded as uncertain; later runs only reconcile. Existing matching names are not silently adopted: reuse needs the script's matching receipt or an explicitly configured environment ID. Readiness checks require the expected tenant, region, type, name, domain, access group and ready Dataverse state. An automatically adjusted domain fails review. No reset/delete/group modification/role elevation is implemented. Review stale locks or uncertain receipts manually; do not delete state to force a second creation.

## Live verification still required

1. Verify a nonempty read-only listing and add captured **non-secret, sanitized** schema fixtures before changing parsing. Uncorroborated empty/malformed output must continue to prevent creation. The empty-result confirmation path has already been checked live.
2. Verify licensing, capacity, regional availability, approved access group and tenant DLP with the tenant owner. Confirm Developer eligibility if choosing that type instead.
3. Approve the offline plan, create once, and independently compare admin-center tenant/region/group/domain/readiness with the receipt. Capture the actual detail response schema without credentials; test mismatches and pending/failed states.
4. Test interrupted creation and reconciliation in the approved disposable environment without blind retries or automatic deletion. Confirm PAC authentication stays on the intended tenant throughout.
5. Create/import and publish a Copilot Studio agent, configure supported manual Generic OAuth and secured Direct Line, and store its channel secret in Vault or a protected mounted file. Environment creation alone does not provide a published agent or publishing entitlement.
6. Add the separately audienced PF SSO/tool issuance profile and approved endpoint configuration, then execute the interactive, autonomous, expiry, revocation and tool-token tests in [the Direct Line plan](direct-line-adapter.md). Those capabilities remain **UNVERIFIED** until the actual tenant passes.
