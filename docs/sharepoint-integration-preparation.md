# SharePoint document integration preparation

Status, 2 November 2026: NOT CONNECTED. Owner selected approved-site document access as the next capability but has no target site or dedicated app yet. Do not infer a SharePoint entitlement from the existing Azure or Copilot Studio billing.

First establish whether the existing Microsoft 365 tenant has a subscription including SharePoint Online. Owner checks Microsoft 365 admin center > Billing > Your products. If absent, review an eligible Microsoft 365 trial or paid plan separately before enrollment; the previous Azure/Copilot budget does not authorize this purchase. Use the existing tenant where possible.

Once licensed, prepare a private test site named Federated Copilot PoC and upload only synthetic documents. No site creation or external sharing change has been authorized/applied yet. Record the actual site URL and resolve its immutable site ID through an administrator-controlled setup step.

Prepare a dedicated certificate/workload-authenticated broker application with Microsoft Graph application Sites.Selected only, then a separate explicit read grant for the selected site. Both consent and site grant require an exact reviewed approval. The runtime must never receive administrator setup credentials or Sites.FullControl.All. Store runtime credentials in Vault under a reviewed dedicated reader. No client secret in source, prompts, fixtures or logs.

The broker maps fixed policy resource aliases to approved site/drive/item IDs. Independent current policy verifies original human, actor, organisation, grant, mode, scope and resource before each data operation. The Entra token represents the broker application, never the external PF human. No arbitrary URL, unrestricted search, caller-controlled scope or provider-token forwarding to Graph. Begin with bounded metadata/list and synthetic document reads; define supported content types and extraction limits before implementing content retrieval.

Negative acceptance: unknown resources, wrong organisation/agent/human, revoked/expired grant, unapproved site/drive/item, redirects or pagination leaving approved paths, oversized content, service failure and insufficient site permission must fail closed. Preserve the existing simulation and diagnostic. Live acceptance needs a separately approved bounded test after setup; all existing browser test allowances are spent.

Official references:
- https://learn.microsoft.com/en-us/office365/servicedescriptions/sharepoint-online-service-description/sharepoint-online-service-description
- https://learn.microsoft.com/en-us/sharepoint/create-site-collection
- https://learn.microsoft.com/en-us/graph/permissions-selected-overview

## Current preparation - 2 November 2026

Owner reports a one-month25-user Microsoft 365 Business Basic trial and created https://nirvingukhotmail.sharepoint.com/sites/FederatedCopilotPoC. Existing admin metadata access independently resolved its site ID and tenant. No dedicated broker app exists. Exact credentialless app/Sites.Selected/read-site setup is prepared in sharepoint-broker-setup-review.md; it has not been applied. The data runtime and Vault credential reader remain unimplemented/unconnected. No document has been read by this setup.

## Provisioning outcome - 2 November 2026

The dedicated broker app and its Sites.Selected application assignment are created. One exact read-only grant on the owner-supplied site was independently verified after separate approved administrator setup authorization. The setup client's sole newly added Sites.FullControl.All consent scope was removed and both original consent records restored exactly. The broker remains credentialless and has no data-plane connection. No document or Copilot test was run. See docs/microsoft365.md and local setup-completed.json for evidence boundaries.
