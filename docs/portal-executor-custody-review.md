# Review: local portal gateway credential enrollment

Status: **PREPARED, NOT APPROVED OR APPLIED**. Automatic approval review rejected the attempted enrollment because the general instruction to continue did not explicitly authorize persisting registered-agent and gateway private keys under a new Vault reader. The rejected command did not execute. This packet makes that specific change reviewable; it does not authorize a Microsoft test or public website activation.

## Exact change requested

Create one version1 record at `/federated-copilot-tool-secrets/data/portal-executor` in the existing local PoC Vault. Copy the following existing credentials; do not generate or rotate agent, PF or gateway signing keys.

| Record field | Existing credential / purpose |
| --- | --- |
| `agentKeyPem` | Registered research agent proof key, pinned to `agent.jwks.json` |
| `pfAClientKeyPem` | `consent-gateway-1` private JWT client-authentication key |
| `pfBClientKeyPem` | **`consent-gateway-2` broker client key**, pinned to that client's JWKS; not `copilot-sso-exchange` tool-client key |
| `policyAgentKeyPem` | Existing `policy-agent` authenticated authority-request key |
| `policyGatewayKeyPem` | Existing `policy-gateway` online decision key |
| `gatewayKeyPem` | Existing private mTLS handoff client key |
| `gatewayCertificatePem` | Matching handoff client certificate, pinned to existing gateway trust |
| `gatewaySigningKeyPem` | Existing exact-body handoff envelope signing key |

Metadata is only `schemaVersion:1` and `purpose:portal-gateway-executor`. The source is the existing local relay authority/gateway Vault records plus the existing protected project agent and broker-client key files. The relay authority record is read during copying, but its PF B **tool-client** key is replaced in the new candidate with the independently pinned **broker-client** key. Nothing writes back to either source record.

Create policy `copilot-portal-executor-read` with exactly:

```hcl
path "federated-copilot-tool-secrets/data/portal-executor" {
  capabilities = ["read"]
}
```

Create a dedicated 30-day client-authentication certificate in the existing current-user/SYSTEM protected custody directory (`portal-executor-cert.pem` and `portal-executor-key.pem`). Bind role `copilot-portal-executor-reader` to that exact certificate. Grant only the policy above, no default policy, service token with one use,120-second TTL/max TTL/explicit max TTL. Runtime certificate login performs one exact KV read; it receives no operator token or Vault administration permission.

## Verification and limits

Validate all signing keys against independently stored public keys before writing and after reading. Validate the handoff certificate fingerprint, key pair, client-authentication usage and lifetime. Use CAS0 only when the record is absent. Refuse unknown existing data, versions, policies, roles or certificate bindings; never overwrite them. Repeat enrollment to prove reconciliation preserves version1 and all existing identities.

After the permitted read, prove denials for the portal-controller record, relay connection key, unrelated runtime record, authority Transit key and the other portal reader role. Each credential-read denial consumes its own bounded token. Print only fixed receipt metadata and counts; never keys, tokens or Vault response bodies. No raw values are included in this packet or its manifest.

This is an exportable-key PoC workload. Possession of the reader certificate can expose these client/agent keys and allow workload proof signing. The independent consent/grant/policy checks remain mandatory; key possession alone is not human consent. The selected Windows account can access the protected files: separating controller and web code is **not production OS isolation**, and that isolation remains UNVERIFIED. The future web worker must not be given these fields, this reader certificate or an API to select arbitrary Vault paths.

This approval covers **only enrollment and its read/denial/idempotency verification**. It does not approve public DNS/ports/ingress, PF callbacks or client enablement, any Microsoft conversation/token POST/tool operation, a new test allowance, Graph, tenant grants, production promotion or an automatic restart/renewal policy. Existing consumed Microsoft ledgers remain unchanged. No current grant is created or revoked by enrollment.

## Implementation and receipt

The exact command is `node scripts/vault/enroll-portal-executor.mjs --enroll`. Default invocation is a network-free preview. Implementation is in the enrollment script, `portal-executor-profile.mjs` and `portal-executor-trust.mjs`. Preparation writes a non-secret hash manifest to `.local/tool-vault/portal-executor-review/manifest.json`, covering this review, implementation and selected public trust files. Recheck those hashes against the approved packet before applying. The enrollment receipt would be `.local/tool-vault/portal-executor-enrollment.json`.

If enrollment is interrupted, inspect the protected receipt/metadata and reconcile the same fixed objects; do not broaden the policy or overwrite a mismatched record. Rollback, if needed after approval, is to disable the dedicated certificate reader and soft-delete only this unused record version, after confirming it has no running consumer. Existing clients, Vault source records and public routes must remain untouched.
