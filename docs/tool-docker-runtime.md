# Verified tool runtime on the existing Docker host

Implemented 2026-10-30. The runtime and image build are available; **the persistent tool service is not deployed**. Production readiness, private PDP/JWKS connectivity, secret-manager custody, ingress caller verification and Microsoft SSO remain separate gates. Graph/SharePoint are disconnected.

## Runtime composition

`src/copilot/tool-runtime.ts` reads an explicit absolute JSON config path and protected secret directory. It composes `JwksTokenVerifier`, a signed decision-only `PolicyClient`, `PolicyProtectedTool`, the fixed diagnostic `ToolApi` and mandatory-mTLS `createToolServer`. It neither issues tokens nor loads a grant database. No mock backend is available.

`src/copilot/tool-main.ts` is the process entrypoint. It starts HTTPS on 8443, emits fixed structured events and handles shutdown. A host launch defaults to loopback; `0.0.0.0` is permitted only in the container context. Compose publishes container 8443 only on host `127.0.0.1:9480`. The container listener alone does not prove safe host publication; use the reviewed Compose boundary.

Required environment:

| Setting | Container value |
|---|---|
| `TOOL_MODE` | `verified` only |
| `TOOL_CONFIG_FILE` | `/run/config/tool-runtime.json` |
| `TOOL_SECRETS_DIR` | `/run/secrets` |
| `TOOL_AUDIT_DIR` | `/var/lib/tool-audit`, dedicated writable restricted mount |
| `NODE_EXTRA_CA_CERTS` | `/run/secrets/tool-outbound-ca.pem`, set before Node starts |
| `TOOL_BIND_ADDRESS` | `0.0.0.0` inside the isolated container |

The runtime config has a closed schema: version, one issuer trust entry, policy origin/workload IDs, workload certificate pins, bounded timeouts and explicit admission limits. `infra/tool-api/runtime.example.json` intentionally has null/empty authority fields and **cannot start the service**. Populate a private reviewed copy; do not put private keys or token values into JSON or environment variables. The review record `deployment.review.json` remains separate and is never loaded as runtime config.

The current runtime is deliberately limited to audience `api://copilot-tool`, scope `copilot.invoke`, RS256, maximum JWT lifetime 120 seconds and diagnostic capability `sharepoint:approved-research`. That capability is synthetic and confers no Graph access. Issuer/JWKS, approved key IDs, organisations, actor issuers, PDP endpoint and certificate pins must be explicit; they are never selected by request content.

## Secret mount contents

The dedicated read-only mount must contain only these runtime files, with appropriate host/secret-manager permissions:

- `tool-server-key.pem` — TLS private key.
- `tool-server-cert.pem` — TLS certificate/chain with the caller-facing SAN.
- `tool-client-ca.pem` — approved workload-client CA bundle.
- `tool-outbound-ca.pem` — approved outbound CA bundle, loaded by Node before requests.
- `tool-policy-key.pem` — PKCS#8 RSA key, at least 2048 bits, registered with the independent PDP under the configured decision-only workload/key IDs.
- `tool-audit-key` — protected 32-byte random HMAC key encoded as 64 hex characters; separate from JWT/PDP keys.

The [restricted audit and monitoring contract](tool-observability.md) is mandatory in this runtime. Compose also requires `TOOL_AUDIT_SOURCE`; no persistent service has been started. Audit keys are never copied into an image, and the policy database is not mounted into the tool.

The loader bounds file sizes, requires regular files, rejects leaf symlink redirection, checks certificate dates and server key/certificate correspondence, and rejects disabled TLS verification, unknown config fields, missing trust and unsafe timeouts. Files are read at startup; rotation requires a reviewed drain/restart. The loader does not replace host filesystem isolation or a production secret manager. Do not mount `.local`, the workspace, PF admin credentials, Vault operator/signing credentials, a Direct Line secret, an Entra credential or the policy database.

Startup validates local configuration/material; it does **not** prove JWKS/PDP reachability or perform a readiness decision. JWT and policy validation occur on protected requests, and dependency failures deny operation. [Authenticated readiness and bounded admission](tool-readiness-admission.md) are now implemented and locally verified; production audit/alert sink, monitoring identity and load sizing remain pending.

## Image and Compose

`infra/tool-api/Dockerfile` uses the existing pinned Node image digest; its binary reports Node v22.23.2. It installs locked JOSE 6.2.3 with install scripts disabled. The Dockerfile-specific context allowlist excludes `.local`, `.git`, environment files and test artifacts. The final image copies only the tool runtime and its required adapter/policy modules, not mock services or harness scripts. Production image vulnerability review/approval remains outstanding; a local build is not image promotion.

Build only:

```powershell
docker build -f infra/tool-api/Dockerfile -t federated-copilot-tool:local .
```

`compose.yaml` requires an explicit `TOOL_IMAGE` (reviewed local image ID or immutable registry digest), `TOOL_CONFIG_SOURCE` (absolute runtime config file), and `TOOL_SECRET_SOURCE` (absolute dedicated runtime secret directory), and `TOOL_AUDIT_SOURCE` (absolute dedicated restricted writable audit directory). It mounts them read-only without creating missing host paths. The service runs as UID/GID 1000, with read-only root, no capabilities, no new privileges, 64 PID limit, 0.5 CPU and 256 MiB memory. It has no automatic restart policy and bounded local Docker logs. Compose was rendered/validated; **no Compose up was run**.

The draft network is `internal: true`. It has no approved JWKS/PDP peers yet. `localhost` inside the container names that container, not the Windows host or existing PF containers. Do not disable the network restriction to make a request succeed. Review exact private service DNS/SAN/CA names and attach only the necessary approved peers/private paths. This is still a deployment blocker. No Cloudflare route is added.

## Verified evidence and limits

The [actual private Docker integration harness](tool-container-network.md) now supplies a separate, isolated test path to real PF/Vault/PDP using a three-route TLS backend bridge. It does not change the unstarted Compose service or resolve production network/egress approval.

`npm run tool:docker-test` runs disposable smoke containers with `--network none`, no host ports and generated synthetic certificates/workload keys. It tests missing-config rejection, valid local configuration startup, UID 1000, read-only/capability restrictions and exclusion of lab/mock files. It stops the container and removes generated credentials; receipts contain fixed labels only. A successful synthetic startup is **not readiness or a live PF/PDP check**. OpenSSL is required on the host for disposable test material.

All seven Docker smoke checks pass, including explicit null-admission rejection. Runtime tests exercise actual signed JWT verification, signed PDP requests and mTLS over loopback with an injected HTTPS transport for JWKS/PDP, plus wrong audience, unknown fields, missing authority, TLS bypass and key/cert mismatch rejection. All **283 production tests and 210 baseline tests pass**. The prior 27 actual PF/Vault/PDP-to-tool HTTPS checks remain independent evidence; they have not yet been repeated through this container network.

The [private Docker lab harness](tool-container-network.md) now verifies the actual PF/Vault/PDP path in 37 container checks, including both modes and real token aging; all 283 production and 210 baseline tests pass. It uses a trusted three-route TLS bridge for the host's existing loopback services, not the persistent Compose service. Readiness/admission are now implemented; next are operational audit/alerts and persistent routing/custody review before deployment. Actual Copilot calling-workload authentication and secure token-post acceptance remain UNVERIFIED; no additional Microsoft attempt is included.
