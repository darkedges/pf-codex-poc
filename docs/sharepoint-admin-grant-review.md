# Review: administrator authorization for the selected-site grant

Status: PREPARED, NOT APPLIED. The approved broker application and Sites.Selected app-role assignment exist. Its selected-site grant remains UNVERIFIED: the attempted operation did not return a confirmed result, and the current Azure CLI administrator token cannot read site permissions (HTTP403 accessDenied). Do not rerun the original setup or create another application.

Existing tenant:4161be3f-bf2b-41d4-a02b-e6f82b529d53.
Broker appId:cddeda93-51e4-42ad-bba7-b85b38b51b72.
Broker app object:3909f112-ddaf-4a34-b922-586179d5b5d9.
Broker service principal:d11c03ee-c0c5-4cee-9eaa-27b11b9982e8.
Exact site:nirvingukhotmail.sharepoint.com,b353bf73-309c-474b-85a2-f3635a7cceff,f8d6bb5e-6c9d-41c8-bd53-0cd08796061e.

Microsoft documents Sites.FullControl.All as the least privileged delegated permission for POST /sites/{siteId}/permissions, with an administrator who is a member of the site. The current cached Graph scope metadata lacks that permission. Source:https://learn.microsoft.com/en-us/graph/api/site-post-permissions?view=graph-rest-1.0.

## Proposed additional authorization

Authorize an interactive administrator-only session through the installed Microsoft.Graph.Authentication module, in this tenant and as admin@nirvingukhotmail.onmicrosoft.com, requesting delegated Sites.FullControl.All for Microsoft Graph PowerShell. The user completes sign-in/MFA/admin consent. No token/password is pasted into chat or captured in logs. Scope the local authentication context to the process and disconnect afterward.

This is broad setup authority: the delegated permission can manage SharePoint sites under that administrator. It is never granted to copilot-m365-resource-broker, the portal, a PF identity, an external agent or the runtime. The broker keeps only Sites.Selected. Disconnecting ends the local session but does not itself revoke Microsoft consent; any newly added delegated consent must be identified and separately reconciled/revoked without disturbing pre-existing grants. Do not claim it expires when the local script ends.

Use the authorized session only to read the exact site's permissions first. If the existing broker already has exactly one read-only grant, verify it and do not post another. If no matching grant exists and read-back is conclusive, perform at most one POST for roles:[read] and grantedToIdentities:[{application:{id:cddeda93-51e4-42ad-bba7-b85b38b51b72,displayName:copilot-m365-resource-broker}}]. Independently read back that exact app/site/role binding. Stop on conflicting, duplicate, write/fullcontrol, ambiguous or failed results. Preserve the original receipt and record reconciliation separately; never reset it. No document read, credential creation, automatic mutation retry, new app, billing change or Copilot test is included.

Approval is required because the first review explicitly excluded new administrator authority; this setup-only delegated permission expands that scope. Preparation does not authorize requesting it.
