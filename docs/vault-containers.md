# Live Vault signing with PingFederate

The local authority now signs through an actual Vault Transit container. Its RSA key is generated inside Vault with `exportable=false` and `allow_plaintext_backup=false`; no copy of that private key is written into the host's development-key directory. PF A trusts the published public key and exchanges the signed assertion through PF B in both execution modes.

This is a local integration, not an approved production deployment. The official image is pinned by digest in `infra/vault/compose.yaml`; its binary reports Vault **1.21.4**. Image vulnerability review and production version approval remain deployment gates.

## Start and operate

First prepare/configure the existing [PF pair](pingfederate-containers.md). Then:

```powershell
npm run vault:up
npm run vault:test
npm run pf:test
npm run consent:serve
```

Vault binds only **127.0.0.1:9470**, with verified TLS at `https://localhost:9470`. The Compose project `federated-copilot-authority` owns its volume/network and uses a configurable private subnet, default `10.235.0.0/24`. The container receives only its configuration, three read-only TLS files and its dedicated storage volume. It does not mount the authority's host credential directory, agent keys, PF administration credentials or policy database. No public host port is opened.

`vault:up` starts normal persistent Vault server mode, initializes only new storage, unseals using local operator material, enables Transit and HMAC-protected file audit logging, provisions the non-exportable key and sign-only policy, obtains an eight-hour runtime token, and updates only PF A's existing consent processor public JWKS. Existing issuer, audience, exchange policy and ATM settings are preserved. No production IAM or Microsoft tenant settings are changed.

The ignored `.local/pingfederate/authority-backend.json` explicitly selects Vault for subsequent policy/portal/test processes. The ignored Transit config pins its origin, mount, key name, version, kid and public JWK. Missing/invalid selected Vault configuration or credentials fails closed; it never silently changes to development signing. `consent:configure`/`pf:configure` now preserve the selected authority backend's public trust.

Other commands:

| Command | Action |
|---|---|
| `vault:status` | Inspect the dedicated container |
| `vault:setup` | Unseal if needed, reconcile policy/audit, retire the old runtime lease, issue a fresh eight-hour lease and refresh PF public trust |
| `vault:start` | Start existing container, unseal, reconcile and refresh its lease/trust |
| `vault:stop` | Stop only this project's Vault |
| `vault:down` | Remove only this Compose project's container/network; retain its volume and recovery files |
| `vault:rotate` | Create a new signing version, publish old/new public-key overlap to PF A, then select the new version for newly started authority processes |
| `vault:retire` | Disable older signing versions and remove them from PF A trust immediately |

Restart the authority/portal processes after rotating so they load the new pinned version. For routine rotation, drain every old authority process and wait at least the maximum assertion lifetime plus clock tolerance (60 + 5 seconds) before `vault:retire`. Retirement deliberately invalidates outstanding old-key assertions; the test suite exercises this emergency rejection. Never retire old keys while old-version authority processes are still expected to serve requests.

The runtime token is read from its file for each signature; refreshing the lease does not require a restart when the signing version is unchanged. Expiry or revocation blocks issuance. There is no background token renewal: run `vault:setup` for local renewal. A production deployment must use approved workload authentication and renewal.

The single-share lab unseal key and initial root token are stored only in ignored `.local/pingfederate/vault/bootstrap.json`. Do not print, commit or paste this file. The authority process receives only the runtime token file, never this operator file. Initialization refuses both an initialized volume with missing operator material and an uninitialized volume with existing recovery material, rather than overwriting recovery data. Preserve the original volume and recovery material together. The scripts never delete the storage volume.

## Permissions and evidence

The runtime policy grants only `update` on `transit/sign/consent-authority/sha2-256`, without the default Vault policy. It cannot read key metadata, export/backup keys, rotate/create keys, or inspect mounts. An unregistered agent credential is denied by Vault. Operator calls also receive explicit export/plaintext-backup refusals for this key; the running version returns HTTP 400 for export and 500 with an explicit refusal for plaintext backup. The test validates the refusal and absence of key data, rather than treating any arbitrary server error as success.

The **nine actual-container tests** verify:

- Non-exportability, sign-only runtime permissions and unregistered workload rejection.
- Real PF browser consent and both exchange modes retaining the original human and actor.
- Revoked and expired Vault credentials denying both modes, with recovery after credential replacement.
- Sealed/stopped Vault denying both modes and persisted keys surviving explicit unseal/restart.
- TLS rejection with an empty CA trust store.
- Old/new PF key overlap, new-version issuance, explicit retirement denying both old-key signing and an otherwise valid unexpired old-key assertion at PF A, and mismatched public-key rejection.
- Vault audit/server logs and authority telemetry containing no compact JWTs, root/unseal material or test runtime credentials.

`vault:test` is an operator integration test: it uses private local operator material, stops/seals/restarts this one container, and rotates/retires this lab's authority key. It uses a separate SQLite database and short-lived test lease, cleans up its service processes, and leaves the selected authority profile on the latest version. Run it without other jobs using this local authority. `pf:test` independently checks consent, request replay, PF exchange, revocation and PF log redaction. Docker log checks have hard deadlines so an unavailable daemon cannot hang validation indefinitely.

Final validation on 2026-10-29: **38 baseline tests, 112 production/API/signer tests, nine live Vault/PF tests and all 35 PF regression tests passed**. The final live sequence ran Vault outage/recovery and rotation/retirement tests first, then the full PF suite against the resulting active key state, including PF log redaction. Local credential-free evidence is recorded in `.local/pingfederate/vault-validation.json` and `validation.json`. The original simulation smoke checks also pass.

## Docker recovery evidence

The earlier regression run stalled on Docker log collection and the daemon subsequently stopped responding. With explicit user approval, Docker Desktop was restarted. Its initial startup failed on inaccessible zero-byte AF_UNIX runtime sockets (Windows error 1920), matching [Docker's reported startup issue](https://github.com/docker/desktop-feedback/issues/531). Windows refused a single-socket rename. With Docker stopped, the IPC-only `Docker/run` and `docker-secrets-engine` directories under the user's local application data were verified to contain only zero-byte reparse-point sockets and reversibly renamed to timestamped `.stale-*` archives. Docker then started successfully. Settings, images, containers, data volumes and recovery material were preserved; no Docker feature flag was changed. Leave the archived IPC directories in place unless their later cleanup is explicitly requested.

The project PF containers were restored, Vault was explicitly unsealed and its sign-only runtime credential refreshed. PF A had changed its default OIDC signing keys across restart; the verifier correctly rejected callbacks with unapproved kids. Running the existing operator command `npm run consent:configure` reconciled the trusted local OIDC configuration while preserving Vault authority trust. Signature/kid checks were retained. If PF regenerates default OIDC keys on a future lab restart, repeat that explicit reconciliation before using the portal; production signing-key approval/rotation must follow its own controlled process.

## Remaining production gates

**UNVERIFIED:** OS-enforced separation between host workloads, production workload federation/certificate authentication and automatic token renewal, HA/auto-unseal/HSM, backup/restore, audit shipping/retention, production TLS/network policy, image security approval and deployment review. Local files run under the same Windows account: API permission tests do not prove that a compromised same-user host process cannot read other local files. Root/unseal material on the same development host is not a production custody design. Dynamic PF-to-PF signing-key rollover remains a separate gate; this milestone rotates the consent authority key trusted by PF A.

Copilot Studio, Entra, Graph and SharePoint remain disconnected. Their live integration/authorisation gates are unchanged.

References: [Vault Docker deployment](https://developer.hashicorp.com/vault/docs/deploy/run-on-docker), [Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit), [token API](https://developer.hashicorp.com/vault/api-docs/auth/token).
