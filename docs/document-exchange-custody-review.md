# Review: dedicated document exchange client custody

Status: PREPARED, NOT APPLIED. This review covers only local Vault enrollment and verification. It does not authorize PF staging, enabling a client, issuing a token or reading Microsoft data.

## Exact change

Generate two distinct new RSA3072 client signing keys in trusted controller memory, named by public key IDs `document-gateway-1` and `document-gateway-2`. Do not copy or replace existing agent, consent, Copilot, SharePoint, gateway or authority keys. Store only these two new keys in version1 of `/federated-copilot-tool-secrets/data/document-exchange`, using CAS0. Record fields are exactly `schemaVersion`, `purpose`, `clientAKeyPem`, `clientBKeyPem`; purpose is `document-exchange-clients`. Publish only their public JWK pins in `.local/tool-vault/document-exchange-trust.json`.

Create one new RSA3072 non-CA clientAuth reader certificate/key valid30 days under the existing Windows owner/SYSTEM custody directory: `document-exchange-reader-cert.pem` and `document-exchange-reader-key.pem`. Register only the Vault cert-auth role `copilot-document-exchange-reader` and ACL `copilot-document-exchange-read`. Its sole capability is read on the one KV record above. Certificate login yields a one-use120-second service token with no default policy. It cannot read the SharePoint app credential, portal executor/controller, relay authority record or consent Transit key. It cannot log in as the portal executor or SharePoint reader. Verify one positive retrieval, those five exact-path403 responses and two cross-role denials. Verify idempotence with the same public pins, record version and reader role; never rotate or overwrite drifted state.

Client keys are exportable in Vault KV and loaded into trusted controller memory. No private PF client key file is written by this enrollment. The reader's bootstrap private key remains in the protected Windows directory. Existing Windows owner/SYSTEM custody, root-operator access and same-account process isolation remain PoC limitations. Client keys do not have certificate expiry; their activation/retirement must be reviewed with subsequent PF deployment. Reader certificate expiry is separate from one-day audit retention.

## Failure handling

Write public pins and a restricted intent before the sole CAS0 credential POST. Existing unknown state, version drift, missing pins or differing keys/role/policy fail closed. An ambiguous write is not permission to regenerate or retry: preserve intent/pins and independently inspect the exact record. A second invocation may validate an already stored version1 and complete missing reader enrollment without changing either client key. No renewal, key rotation, deletion or permission expansion is included.

The reviewed entry point is `node scripts/vault/enroll-document-exchange.mjs --enroll`. It refuses enrollment unless the source/review manifest and separate explicit owner approval match exactly and approval is at most24 hours old. Preview without arguments reads no credential and makes no network request. The operator bootstrap credential is read only after this guard; it is never printed or stored in a new record. All existing Vault mounts and cert-auth configuration are assumed; this does not create/reconfigure a mount.

## Explicit exclusions and next stage

Zero PF administration/token requests, zero Entra/Graph/Copilot requests, zero consent/grant or registry changes, no new app/site permissions, no public route/listener, service restart, publication or billing change. Existing spent-test counters remain untouched. Document authority Transit and policy workload keys are excluded and still pending. This approval creates no document-read allowance.

The offline `scripts/pf/document-stage-plan.mjs` describes dedicated disabled PF objects only. It is not an apply workflow: approved authority/public signing pins, scope-registration review, an ownership/reconciliation journal and expiry configuration remain prerequisites. PF staging needs its own completed review and approval after those details are concrete. No activation readiness is claimed.

Local validation:710 production and372 simulation tests pass. Eight new custody/enrollment/planning tests cover public/private key binding, distinct client keys, strict lease/version checks, role/policy drift refusal, idempotence and uncertain-write failure, and non-enabling offline stage plans. Actual Vault enrollment/reader denials and PF document-profile acceptance remain UNVERIFIED until separately applied and verified.

Approve only with: **Approve document exchange credential enrollment**. This explicit approval is requested because it creates persistent Vault credential custody and a new reader ACL/role; the earlier SharePoint credential approval did not cover these PF keys.
