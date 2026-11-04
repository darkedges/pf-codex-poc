# Review: document authority and policy workload custody

Status: PREPARED, NOT APPLIED. This review authorizes no live PF configuration, policy service deployment, grant/assertion issuance or Microsoft request. The separately enrolled document PF client keys remain untouched.

## Exact new Vault material

Create one new Transit RSA3072 key `document-authority`, version1, non-exportable, with plaintext backup and deletion disabled. Pin its public key as `document-authority-v1` in `.local/tool-vault/document-authority-transit.json`. Do not rotate, export, change or reuse the existing `consent-authority` key. Only the existing Transit mount is used; no mount initialization, unseal, backend reconfiguration or existing key mutation is included.

Create three distinct RSA3072 signing keys in trusted controller memory, each in its own new KV version1 using CAS0:

| Caller identity | Public key ID | Exact KV suffix |
|---|---|---|
| `policy-document-consent` | `document-policy-consent` | `document-policy-consent` |
| `policy-document-agent` | `document-policy-agent` | `document-policy-agent` |
| `policy-document-reader` | `document-policy-reader` | `document-policy-reader` |

All records are under `/federated-copilot-tool-secrets/data/`. Each has exactly `schemaVersion`, `purpose`, `clientId`, `keyId`, `privateKeyPem`, purpose `document-policy-workload`. No other credential is copied into them. The matching public pins are separate local `document-policy-{name}-trust.json` files. No private workload-key file is written by this enrollment. These credentials are **not** registered with a policy service by this approval. Their intended roles are consent, authority and decision respectively, limited to partner-a and document capability; no grant-admin or registry-admin role is intended or granted.

## Four independent cert-auth roles

Generate four new non-CA RSA3072 digitalSignature/clientAuth bootstrap certificate/key pairs, valid30 days, under the existing Windows owner/SYSTEM directory. Their filenames are `document-authority-{signer|consent|agent|reader}-{cert|key}.pem`.

| Cert-auth role | Sole ACL |
|---|---|
| `copilot-document-authority-signer` | `copilot-document-authority-sign`: update only `transit/sign/document-authority/sha2-256` |
| `copilot-document-policy-consent-reader` | `copilot-document-policy-consent-read`: read only its consent KV record |
| `copilot-document-policy-agent-reader` | `copilot-document-policy-agent-read`: read only its agent KV record |
| `copilot-document-policy-reader-reader` | `copilot-document-policy-reader-read`: read only its reader KV record |

Every role issues a one-use120-second service token, no default policy, maximum/explicit TTL120 seconds. No periodic or renewal workflow is introduced. The signing ACL permits signing arbitrary input with this one key; it does not enforce policy itself. Future trusted authority service composition must independently verify human/actor/consent and cannot expose the signer to browsers/models. This enrollment opens no listener and issues no grant assertions.

The Transit private key is non-exportable. The three workload keys are exportable Vault KV credentials loaded into trusted controller memory by their exact readers. Four local bootstrap private keys remain protected by the Windows account/SYSTEM custody boundary. Root operator access, same-account isolation, rotation/retirement and production process separation remain PoC limitations. Client-key activation/retirement is separate from one-day audit retention and30-day bootstrap certificate validity.

## Verification and failure handling

Reverify the frozen source/review manifest and a separate exact owner approval at most24 hours old before reading the local operator credential. The reviewed entry point is `node scripts/vault/enroll-document-authority.mjs --enroll`. Without arguments it only previews, with no credential/network access.

Retain public intents before each new key/record write; preserve public pins. Refuse existing foreign keys, key version/pin/configuration drift, unknown KV versions and differing roles/policies instead of overwriting. Uncertain writes require independent reconciliation, never automatic regeneration or blind retry. Exclusive local enrollment is assumed; no concurrent operator edits to these exact new objects are authorized. An already present version1 can be revalidated and missing owned enrollment steps completed.

Per invocation, verify three positive workload reads and one random32-byte synthetic signing challenge against the pinned Transit public key. This challenge is not a JWT or user/agent/grant assertion. Verify48 total negative checks across the four identities: unrelated new records, existing PF client/SharePoint/portal credentials, old authority metadata/signing, document signing by readers, and cross-role logins. Keep each denied request under a fresh one-use lease. Failed checks stop and preserve state; no broader access is substituted.

Approve an initial enrollment/verification and one same-material idempotence invocation (at most two synthetic challenges total). Independently confirm unchanged Transit public key/version/config, three KV contents/versions, four reader certificates/keys and four roles/ACLs. Save only sanitized summaries/hashes. No tokens, signatures, private key values or raw Vault responses in chat or the receipt.

## Exclusions

Zero PF admin/token calls, policy database/grant/registry mutations, policy workload registration, service startup/restart, external route, new listener, Entra/Graph/Copilot request, document read, publication, billing change or new test allowance. The next phase still needs a guarded disabled-profile PF staging review and real absolute-expiry verification before activation. Existing PF, SharePoint and Copilot custody/budgets are preserved.

Local validation:718 production and372 simulation tests pass. Eight new authority-custody/enrollment tests cover exact key/schema/role separation, non-exportable version1 Transit pins, excessive leases/policies, idempotent narrow roles, drift refusal, invalid identities, independent challenge signatures and wrong versions/signatures without retries. Actual new-key enrollment,48 denials and document PF acceptance remain UNVERIFIED until separately applied and verified. Script previews and syntax checks pass without credential access or network requests.

Approve with **Approve document authority credential enrollment**. Explicit approval is required because this creates a new signing authority, persistent workload-key custody and four reader/signing ACLs/roles; the previous approval covered only the two PF exchange client keys.
