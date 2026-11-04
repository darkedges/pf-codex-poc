# Persistent local tool backend and enrollment

Implemented 2026-10-31 Australia/Sydney. This milestone prepares the selected Windows/Docker PoC for persistent operation. It does not start a continuous service, publish a route, enable PF B issuance, change Microsoft settings or connect Graph. The [enrolled private Docker path](enrolled-tool-network.md) subsequently passed 23 readiness/transport checks and was stopped after verification; continuous activation remains a separate gate.

## Durable policy profile

`npm run tool:policy-serve` runs the dedicated foreground policy/authority process at `https://localhost:9452`, bound to `127.0.0.1`. It uses `.local/tool-vault/policy.sqlite` and an immutable public workload snapshot in that protected directory. Existing default services and disposable harnesses retain their own bootstrap behavior and database locations.

This profile explicitly requires Vault, the dedicated database, fixed port and fixed decision audience `https://tool-backend:7443`. It registers only the existing synthetic PoC organisation, consent human and registered agent. **It creates no fixture grant or automatic consent.** A fixture database or mismatched existing registry is rejected. Repeated startup preserves suspension, grants, terminal revocation and the replay ledger. No external human is created in Entra. Browser consent will require its own explicit connection to this backend; the existing portal is not silently redirected.

The initial public snapshot copies the already registered gateway/admin/consent/agent lab workload keys. It is not refreshed from test files on restart. Enrollment replaces the tool entry with a separately generated RSA 3072 key stored in Vault's tool runtime record. Each role has a distinct public key, fixed ID/kid and RS256; private JWK parameters, incomplete roles, duplicate/weak keys and unreviewed expansion fail closed. Existing non-tool lab credentials remain host-scoped PoC credentials; production workload isolation remains unverified.

The controller obtains its own sign-only eight-hour Vault lease and verifies an actual signature against the pinned Transit public key/version before opening the policy listener. Its token is separate from both the existing authority runtime lease and the tool renderer token. Shutdown revokes this lease before removing its protected token and releasing the single-instance lock. It stops 30 seconds before lease expiry; there is no privileged automatic renewal or Windows autostart. A restart obtains a fresh lease. Decision health verifies the signed policy API, not continuous availability of assertion signing; assertion requests still fail closed if Vault becomes unavailable.

If startup/shutdown cannot independently complete cleanup, the lock remains for review. Never remove a policy-service lock while its exact process/listener might be alive. Confirm process ownership, stop only the owned process, revoke the tracked accessor with the operator, and verify absence before retiring stale custody files. Do not erase the database or restore a revoked credential as recovery.

## Dedicated local enrollment

`npm run vault:tool-enroll-local` is a first-enrollment operation. It requires no persistent policy process, no prior enrollment receipt/config and no existing metadata for the four reserved records. It holds the same custody lock as enrollment/verification. It generates a local RSA 3072 CA, distinct 30-day TLS server (`localhost`, `tool-api`, `tool`), backend (`tool-backend`) and monitoring client certificates, a separate RSA 3072 tool policy key and random audit HMAC key. The local CA lasts 90 days. This is exportable local PoC PKI; managed production PKI, rotation, revocation and ownership are not established by it.

All records are stored through KV v2 CAS 0:

| Record under `federated-copilot-tool-secrets` | Custody and delivery |
|---|---|
| `runtime` | The closed six-field tool record; certificate reader may read it once per token |
| `local-pki` | CA maintenance key/certificate; operator only, never mounted in tool |
| `private-backend` | Separate bridge key/certificate; operator only, future dedicated backend mount |
| `monitoring` | Dedicated local diagnostic caller key/certificate; operator only, never mounted in tool |

The current tool reader has no access to the other three records. No container receives Vault operator material. Enrollment stages certificate operations inside the protected custody directory, removes the staged CA/leaf private files after storing them in Vault, reads back the runtime using the certificate reader, and renders one explicit six-file snapshot. It writes public runtime config and the non-secret `runtime-enrollment.json` receipt locally. The loader validates that config/snapshot without opening a listener; its temporary audit directory is removed. No permanent audit directory is initialized or retention decision inferred.

The snapshot's outbound CA trusts the dedicated backend certificate. The tool JWKS endpoint is fixed to `https://tool-backend:7443/pf/JWKS`, issuer `https://pf-b.copilot.darkedges.com`, audience `api://copilot-tool`, kid `copilot-tool-signing`, RS256 and maximum lifetime 120 seconds. The policy endpoint is fixed to `https://tool-backend:7443`, with decision-only `policy-tool` / `copilot-policy-tool`. The monitoring leaf is the only pinned inbound caller. This is a local diagnostic workload, not evidence of Copilot caller authentication.

Enrollment is not a rotation command. It refuses existing records/configuration. Failed writes use owned-content/version checks before deleting newly created records; uncertainty retains the lock. Partial credential enrollment never triggers activation. Subsequent credential rotation needs a reviewed CAS/key-overlap and drain/replacement procedure.

## Verification and current state

- `npm run tool:policy-test`: **14 actual TLS/Vault/process checks**, including authenticated health, wrong audience, tool administration denial, invalid delegated proof, real process restart, persisted replay, and signing-lease revocation/removal on stop. Existing grant/consent counts are compared across restart; the test creates no grant and leaves the service stopped.
- `npm run vault:tool-enrolled-test`: **8 live checks** preserve the enrolled records, verify tool key/public trust and caller pin agreement, deny reader access to all three private maintenance records, and run the actual renderer. It removes only its additional verification snapshot; the selected snapshot remains.
- **247 baseline** and **283 production** tests pass, including persistent bootstrap/settings/trust negatives and local certificate issuance/names/usages/key separation.

The earlier `vault:tool-test` verifies destructive synthetic first-enrollment behavior and intentionally refuses to run now that a persistent runtime record exists. Use the non-destructive enrolled test for this state. Neither verification command consumes a Microsoft SSO attempt or creates a consent grant.

The fixed private Docker backend and [consent-backed canary](enrolled-tool-canary.md) now pass **47 combined live checks**, including actual dependency outages, both PF execution modes, identity audit, real token expiry, renewal and owner-authorized revocation. Verification leaves services stopped and all canary grants revoked. PF B remains disabled outside controlled tests. Next is the concrete local start/recovery plan and audit/operations acceptance. Continuous activation, production deployment, Microsoft secure-token-post, Copilot-originating caller authentication and Graph/SharePoint remain separate gates.
