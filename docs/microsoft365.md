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
