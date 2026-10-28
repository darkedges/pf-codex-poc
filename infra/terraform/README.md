# Infrastructure as Code — deliberately not provisioning yet

The project intentionally does **not** include a live Terraform plan that can grant Microsoft permissions or deploy a publicly reachable gateway. Codex should implement these modules after you select your remote hosting environment and approve network/security boundaries.

Suggested modules:

- `network` — private service networking and egress rules for PingFederate, Copilot and Microsoft Graph.
- `workload-identity` — dedicated runtime identities, certificate/managed-identity strategy and secret manager.
- `m365-application` — minimal Entra app with Graph `Sites.Selected` application permission; admin consent and selected-site `read` grant as a *separately approved* step.
- `gateway-deployment` — hardened images, health checks, service identity and bounded ingress.
- `telemetry` — event correlation, redaction and revocation alerts.

Never grant `Sites.Read.All` or tenant-wide Microsoft Graph permissions as a convenience. Require explicit approval of each selected site and audit the grant.
