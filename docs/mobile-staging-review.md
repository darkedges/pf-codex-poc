# Mobile credential and disabled-PF staging review

**Requested action: stage dedicated mobile credentials and four disabled token-exchange clients.** This does not activate the website/app, sign in a user, issue PF access tokens, call Microsoft, install a Windows task or change a public route. The APK candidate exists, but live installation/verification is not ready yet.

## Exact custody changes

Apply only the public recipe in `scripts/vault/mobile-custody-plan.mjs`, using the existing local Vault operator credential for this named bootstrap. Operator/root credentials must not become a runtime dependency, be copied into the APK or be installed in a startup task.

Create dedicated KV-v2 mounts `mobile-runtime` and `mobile-provider`, both with CAS required and one retained version. Create non-exportable, non-backupable RSA3072 Transit keys `mobile-agent-v1` and `mobile-authority-v1`, version1. Their private keys stay in Vault; retain only their public pins locally.

Create `mobile-runtime/data/credentials` at CAS0 with five new RSA3072 private client keys: `mobile-copilot-login`, `mobile-chat-gateway-1`, `mobile-chat-gateway-2`, `mobile-document-gateway-1` and `mobile-document-gateway-2`. Copy **only `directLineSecret`** from the existing `federated-copilot-tool-secrets/data/portal-controller` record into this dedicated record. No other existing credential field is copied or modified. The mobile login key is reserved for the later reviewed OIDC client; this stage does not create or enable that client. The provider mount remains empty of user tokens.

Create these five exact policies and certificate roles under existing `auth/tool-cert`:

| Policy / role | Allowed Vault path | Capabilities / token bound |
| --- | --- | --- |
| `mobile-runtime-read` / `copilot-mobile-runtime-read` | `mobile-runtime/data/credentials` | read; one use,120 seconds |
| `mobile-provider-store` / `copilot-mobile-provider-store` | `mobile-provider/data/*` | create/read/update;300 seconds |
| `mobile-agent-sign` / `copilot-mobile-agent-sign` | `transit/sign/mobile-agent-v1/sha2-256` | update;300 seconds |
| `mobile-authority-sign` / `copilot-mobile-authority-sign` | `transit/sign/mobile-authority-v1/sha2-256` | update;300 seconds |
| `mobile-graph-read` / `copilot-mobile-graph-read` | existing `federated-copilot-tool-secrets/data/sharepoint-broker` | read; one use,120 seconds |

Each role has its own new RSA3072 client certificate, valid30 days, and no default policy. Store only those workload certificate keys under `.local/tool-vault/mobile`, protected to the owner's Windows account and SYSTEM. No CA, existing role, existing Transit key, existing secret record or Graph permission is changed. No unattended operator access or automatic unseal is authorized.

## Exact disabled PF objects

Use `scripts/pf/mobile-profile.mjs` and the read-back/idempotence controller `scripts/pf/mobile-stage.mjs`. Existing `copilot.invoke` and `m365.document.read` scope catalogs must already match; do not modify global catalogs.

For `Chat` and `Document`, create on PF A: `mobile{Kind}Proof`, `mobile{Kind}Agent`, `mobile{Kind}APolicy`, `mobile{Kind}AJWT`, and their mapping; on PF B: `mobile{Kind}Upstream`, `mobile{Kind}BPolicy`, `mobile{Kind}BJWT`, and their mapping. Here `{Kind}` is exactly `Chat` or `Document`.

Generate four RSA4096,30-day PF signing keys: `mobile-chat-a-signing`, `mobile-chat-b-signing`, `mobile-document-a-signing`, `mobile-document-b-signing`. Read back and pin only each newly owned exact signing-key ID; PF B trust must use that read-back PF A key, never an arbitrary newly discovered key.

Create `mobile-chat-gateway-1`, `mobile-chat-gateway-2`, `mobile-document-gateway-1`, `mobile-document-gateway-2` with `enabled=false`, only `TOKEN_EXCHANGE`, replay-protected RS256 `private_key_jwt`, and their single corresponding scope/resource/manager. Preserve human `partner-a:user-123`, actor issuer `https://partner-a.test/agents` and actor subject `partner-a:agent-research`, organisation `partner-a`, current delegation, interactive mode and all original-login/device-presence fields. Numeric time fields require numeric fulfillment, not strings. Scope, resource and assurance conditions are fixed in the signed profile; a prompt cannot select them.

PF A/B issued tokens have120/60-second maximum lifetimes under the explicitly proposed180-second mobile authority profile. Staging creates no authority grant and enables no evidence acceptance path. Hardware attestation remains UNVERIFIED. Exact original-login issuer/client binding is proposed as `https://pf-a.copilot.darkedges.com` / `mobile-copilot-login`; it must be verified with the dedicated OIDC profile before any enablement, and a mismatch must stop activation.

## Verification, limits and recovery

Permit read-back, one idempotence rerun, narrowly scoped credential retrieval checks, at most four synthetic non-grant Transit signatures and at most60 access-denial checks against fixed unrelated paths/roles. These checks must not issue a PF/Graph/Direct Line token, read a document, or start a Copilot conversation.

Persist intent before each write. Unknown existing objects, changed pins/configuration or an uncertain write stop the run; do not overwrite, regenerate, delete history or blindly retry. Retain the private journal for reconciliation. A failed stage leaves any created exchange clients disabled and reports incomplete status. Existing clients/routes and all spent PoC packets remain unchanged.

This staging is needed to obtain real public key pins and verify PF compatibility before finishing the protected runtime and activation packet. **A later concrete activation review is still required** for the OIDC client, enabling the four exchange clients, persistent hosting/startup, public mobile routes/App Link association and live Microsoft/phone tests. No new subscription or billing policy is included.

Approval is required by repository `AGENTS.md`: “No public ports, production IAM policy changes or tenant-wide admin grants without explicit approval.”
