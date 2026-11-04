# Tool API deployment review artifacts

`deployment.review.json` is a non-secret design record, **not application configuration or a deployment manifest**. No runtime imports it; no deployment/apply command is provided. `deploymentEnabled` is false and changing it does not deploy anything. Nulls and empty trust lists are intentionally unresolved and cannot be used to start the existing secure server/verifier.

The operator selected the existing Windows/Docker PoC host. The proposed workload is an isolated Linux container on that existing Docker engine. The proposed host publication is only `127.0.0.1:9480`, mapping to the container's HTTPS listener on 8443. No listener or container has been created. An off-host gateway needs a separately reviewed private-network design; this loopback mapping cannot serve it. There is no public Cloudflare route in this package.

See [deployment review and operations plan](../../docs/tool-api-deployment-review.md) for trust, workload identity, secret mounts, monitoring, blockers and promotion/rollback. The existing PF container/consent harness remains the executable local integration proof.

The [Docker runtime](../../docs/tool-docker-runtime.md) now implements the secure composition/configuration loader and has a built local image plus network-isolated disposable smoke checks. `Dockerfile`, `compose.yaml` and `runtime.example.json` are separate from the review record. Compose remains unstarted; private dependency connectivity and production gates are unresolved.

The [persistent-service runbook](../../docs/tool-service-runbook.md) records activation prerequisites and recovery, plus the measured bounded-load acceptance. `vault-runtime-read.hcl` and `secret-record.schema.json` are non-secret proposals only; no Vault mount, role, policy or secret record has been created by adding them.

Offline review commands:

```powershell
# Syntax and agreement checks only; no credentials/network/container access.
node scripts/pf/review-tool-deployment.mjs
npm test
npm run test:production
```

Production HTTPS tests need OpenSSL on PATH and loopback access. They use disposable test certificates. The separate `npm run tool:http-test -- --run` changes local lab PF B state temporarily and takes about two minutes; it is not a deployment command and is not necessary merely to inspect this package.

Local Vault custody is now implemented and installed: see [credential enrollment and rendering](../../docs/tool-vault-custody.md). The persistent runtime record and service remain absent. The certificate reader has no authority-signing or administration rights; the tool container receives only six rendered files, never a Vault credential.
