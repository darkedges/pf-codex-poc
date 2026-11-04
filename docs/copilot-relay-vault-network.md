# Relay Vault enrollment and isolated Docker routing

Follow-up: [caller activation and runtime/audit preparation](copilot-relay-activation-runtime.md) are now implemented. The live private tool accepts the pinned relay certificate alongside its monitor, seven actual workload checks pass, and a strict eight-file loader/durable journal is validated. The persistent relay listener/issuing authority remain unstarted/unwired; statements below about pending trust describe this earlier enrollment milestone.

Completed 31 October 2026 on the selected Windows/Docker host. This advances the [HTTPS/lifecycle composition](copilot-tool-relay-hosting.md). **Actual Copilot-originated tool invocation remains UNVERIFIED.** No connector, public route, Graph access or Microsoft conversation was created.

## Enrolled custody

The existing encrypted KV v2 mount now has two new CAS-created version-1 records:

| Record | Contents / access |
|---|---|
| `federated-copilot-tool-secrets/relay-runtime` | Separate relay server and outbound client certificates/keys, tool CA/server pin, connector-key digest and relay audit key; exact-record renderer read |
| `federated-copilot-tool-secrets/relay-connection` | Original random connector key; operator-only, excluded from runtime snapshots |

The existing local CA issued separate RSA-3072 server, client and renderer certificates for 30 days. The relay server covers `localhost` and `tool-relay`; its serverAuth key is separate from the clientAuth identity `copilot-tool-relay`. CA maintenance material is not delivered to a runtime. Staging copies of the CA/private keys were removed after issuance. The renderer bootstrap certificate/key and selected eight-file snapshot remain under the current Windows account/SYSTEM custody directory.

The pinned certificate-auth role `copilot-relay-renderer` grants only `copilot-relay-runtime-read`, no default policy, a maximum 120-second lease and one use. Its exact read policy is [checked into the draft infrastructure](../infra/copilot/vault-relay-runtime-read.hcl). The renderer cannot read the original tool runtime, connector key or local CA, and cannot sign through Transit. The existing tool renderer cannot read the relay runtime. Credential-safe Vault auditing was checked before writing secrets; no raw/non-HMAC credential audit fields are enabled.

**22 live Vault checks passed.** Record schemas, keys, certificate roles/names/CA/validity, selected snapshot and connector-key digest are verified without printing originals. The original tool KV version/data and runtime configuration are unchanged. No tool/PDP/CA key or existing credential was rotated.

The first enrollment saved valid records but failed because its comparison depended on JSON key ordering. The fail-closed cleanup retired the new role/policy and preserved the records when their comparison was uncertain. The dedicated reconciliation checked first-version timestamps, the original connector digest and current tool identity, recreated only the renderer access, and completed enrollment without rewriting either record. Canonical record comparison now has a regression test. `reconcile-relay.mjs` is a narrowly guarded recovery for that interrupted first enrollment, not a rotation or general retry command.

`npm run relay:enroll -- --enroll` is a one-shot operation; it now refuses the existing enrollment. Do not remove receipts/records or reset it to rotate keys. Future rotation needs explicit version/pin overlap and retirement handling. The eight-file snapshot carries only the connector-key digest, not the original connection key. The original connector key stays in Vault until an approved connection-enrollment or rotation workflow uses it. The one-day tool audit policy does not delete credential records.

## Private network verification

`npm run relay:network-test` previews the candidate; `-- --run` starts a disposable isolated verification on the same Docker host. The successful run passed **14 checks** at **15:31:15 AEDT on 31 October**:

- Current relay snapshot matches the enrolled Vault version and the renderer certificate is valid.
- The immutable existing tool image runs on a new internal network with no host ports, a read-only root filesystem, UID 1000, dropped capabilities and bounded resources.
- A new relay client reaches authenticated signed readiness through pinned mTLS when explicitly added to the **candidate's** trust configuration.
- Missing workload certificates and invalid tool proof are rejected. Body-supplied human/resource values are rejected before operation execution.
- The private backend returns public PF JWKS and rejects PF administration routes.
- The original tool/backend container identities, networks, selected configuration and Vault record remain unchanged throughout the successful run.

The candidate uses a separate temporary server certificate and private network (`10.236.250.64/28`). Its backend follows the existing fixed-route TLS bridge to host PF B and the active policy service. That bridge is an application route allowlist, not a production egress firewall. It never joins or mutates the running service's network. The probe receives only its outbound client identity, CA and public peer pins; it receives no connector key, Vault/operator token, CA maintenance key or signing credential.

The candidate's containers/network and all temporary credential directories were removed. Restricted verification receipts/audit and the non-secret pending configuration remain. The candidate readiness check proves workload connectivity/trust and signed dependency health, **not a delegated tool operation**: no grants or PF access tokens were created, and no Microsoft call occurred.

The existing tool's live trust still contains only its original monitoring caller. The new relay certificate is **not yet activated there**. The pending configuration adds only its approved fingerprint alongside the monitor; it has not replaced the selected runtime file:

`E:\development\projects\copilot\federated-copilot-codex\.local\tool-vault\relay-network-e8f4a85f-c8b7-4a59-8274-517dfbb42ce9\pending-tool-runtime.json`

## Existing service lifecycle

The first network preflight found the original service already stopped after its bounded authority lease ended. No candidate resources were created in that attempt. Following the user's standing instruction to restart stopped services, the original controller was restarted under the saved Windows account and one-day journal policy, with no trust change, public port, automatic renewal or restart loop. Current service state is **ready**.

The new signing lease expires at **23:30:36.490 AEDT on 31 October 2026** (`2026-10-31T12:30:36.490Z`); policy shutdown is scheduled approximately 30 seconds earlier. This replaces the expired activation window in older service notes. Current PF lifecycle remains A human login enabled, B tool exchange disabled.

## Verification and next step

All **310 baseline tests pass**, including 13 new custody/network-plan tests. The unchanged relay transport/core production suite retains its **361 passing tests** from the preceding milestone. The current live evidence is 22 Vault checks and 14 isolated Docker checks; it is not a real Copilot tool call.

Next is reviewed activation of the new caller pin in the running tool, plus a relay runtime loader using the selected Vault snapshot and durable audit sink. The current controller expects exactly its original caller and must be extended with an explicit enrolled-relay activation receipt before a controlled restart; editing the pin array alone would fail startup. The host/container relay topology and its exact public hostname/path still require a concrete deployment review. Keep the tool private. Enroll the connector key securely, verify system-token handling, and obtain a new bounded Microsoft-test approval only after that composition is ready. All nine prior conversation allowances remain consumed.
