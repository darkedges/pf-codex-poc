# Review: SharePoint certificate custody and public-key registration

Status: PREPARED, NOT APPLIED. Tenant/site permission setup is verified separately; no broker credential exists yet. This review requests credential generation/enrollment and public certificate registration only.

## Exact identity and custody

Tenant4161be3f-bf2b-41d4-a02b-e6f82b529d53; single-tenant app cddeda93-51e4-42ad-bba7-b85b38b51b72; application object3909f112-ddaf-4a34-b922-586179d5b5d9. The app retains only Sites.Selected and the existing read grant on FederatedCopilotPoC. No other app, resource grant or permission is changed.

Generate one new dedicated RSA3072 signing key and self-signed, non-CA, digitalSignature/clientAuth certificate, valid30 days. Generate under the existing protected Windows-owner/SYSTEM custody directory; do not reuse agent, PF, portal, gateway or authority keys. Store the signing key and certificate in version1 at /federated-copilot-tool-secrets/data/sharepoint-broker using CAS0. Record fields are exactly schemaVersion,purpose,tenantId,clientId,certificatePem,privateKeyPem. Purpose is sharepoint-broker. Public SHA256 pin/trust and certificate files remain outside Vault under .local/tool-vault; no private signing-key file remains after independent Vault confirmation. Preserve restricted staging/intent on uncertain enrollment and stop; never silently regenerate or overwrite.

Create one separate local RSA3072 clientAuth reader certificate/key, valid30 days: .local/tool-vault/sharepoint-reader-cert.pem and sharepoint-reader-key.pem. Enroll only auth/tool-cert/certs/copilot-sharepoint-broker-reader and ACL copilot-sharepoint-broker-read. The ACL permits read on the single KV record above. Certificate login issues a one-use120-second service token with no default policy, no renewal mechanism and no authority/transit/portal/relay access. Actual positive retrieval, five unrelated-path denials and two cross-role denials must pass. Existing role/policy/record drift fails closed instead of being overwritten.

This PoC uses an exportable certificate key in Vault KV, loaded only into the trusted controller's memory by the exact-path reader. It is not a non-exportable HSM/Transit signer. The reader's bootstrap private key remains in the existing protected Windows directory. Same-account process isolation, rotation/retirement, remote production workload identity and production OS custody remain unverified. Audit retention is still one day; credential validity/storage is a separate30-day lifecycle, not an audit-retention promise.

## Exact Entra change

Register only the new public DER certificate as one AsymmetricX509Cert/Verify keyCredential on the existing application. No client secret, redirect URI or new permission. Re-read current tenant/admin identity, app audience and exact Sites.Selected-only profile first. Refuse any existing unexpected key/password. Preserve existing state by stopping on drift. New registration writes an intent before one PATCH; an uncertain attempt is never blindly repeated. An already present single exact pinned certificate can be read-verified without another PATCH. Read back the exact public certificate and zero password credentials. This is an exclusive setup step on this dedicated app; no concurrent operator edits are authorized.

No Microsoft access token is requested, no document/list metadata is read, no file uploaded, no Copilot conversation/token POST is started, no PF scope or policy grant added, no listener/public route/connector/publication/billing/trial change, no service startup or renewal. This approval does not authorize the later live document test.

## Prepared runtime and verification boundary

Local EntraCertificateTokenSource uses fresh60-second PS256 assertions, x5t#S256 pinned to that public certificate, the exact tenant token endpoint and scope https://graph.microsoft.com/.default. It has bounded responses/timeouts, no redirect/retry/mock fallback, and never treats an app access token as a PF user's identity.

Local GraphDocumentAdapter permits operator-configured document aliases and immutable site/drive/item/unique IDs only. It requires separately verified document-audience PF proof plus current external human/agent/organisation/grant/mode/scope/resource authorization before outbound boundaries and release. It checks actual metadata and permits only bounded UTF8 text/plain .txt content (at most64KiB). It supports one constrained same-host/unique-file SharePoint download redirect without forwarding the Graph bearer token. No arbitrary URL, search, write, PDF/Office extraction or model-selected scope. Returned document text is marked untrusted data. These factories are not connected to the running portal, policy scopes or a real document allowlist yet.

Validation:646 production and372 baseline simulation tests pass.18 focused adapter/custody tests include actual PolicyStore grant/identity substitutions and mid-read revocation, issuer/audience provenance, signature/header checks, certificate pin/key binding, strict Vault lease handling, resource/metadata/redirect substitution, size/MIME limits, timeout and sanitized failures. Operator scripts parse and preview locally; actual enrollment/Entra certificate registration and Graph data acceptance remain UNVERIFIED until applied/verified.

## Apply after explicit approval only

Reverify the exact .local/sharepoint/custody-review-manifest.json and its bound files, then record approval in custody-owner-approval.json. Run node scripts/vault/enroll-sharepoint.mjs --enroll; independently verify version1/public pin and seven denials, then rerun the same command to verify idempotence without changing key/record/role. Run node scripts/sharepoint/register-broker-certificate.mjs --register; verify exact public certificate and app profile. A second registration run may verify the existing certificate without another PATCH. Preserve all setup and spent-test evidence; no new test allowance is created.

Approval is required because this creates private-key custody, a persistent Vault reader role and a new certificate credential on the Entra app. Existing site-grant approval did not include credentials.
