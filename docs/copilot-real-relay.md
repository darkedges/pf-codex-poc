# Real PF issuance through the local relay and private tool

Verified 31 October 2026 at **17:35:31 AEDT**. The local chain now uses actual PF A/B credentials, independent policy, enrolled caller authentication and the running private Docker tool. **Actual Copilot-originated tool invocation remains UNVERIFIED.** This test created no Microsoft conversation, public route or Graph request.

## Verified flow

1. The synthetic lab human completes real PF A PAR/S256 OIDC login and owner consent for one registered-agent grant in the existing persistent policy service.
2. Actual PF A/B exchange issues the broker-audience token with the original human, acting agent, organisation, grant, mode and scope. A separate PF A configured-provider user access token is acquired and independently verified. The registered Microsoft callback is captured locally, never followed.
3. The internal issuer re-verifies the broker signature/current policy and human OIDC signature, issuer, audience, subject and nonce before retaining that proof for the exact broker token. The relay independently verifies its exact provider-token binding and trusted identity mapping.
4. An HTTPS request to an ephemeral **127.0.0.1-only** relay supplies the configured connection credential and provider user token in protected headers, with body `{}`. This is an operator harness acting as the future connector client, not a Microsoft-originated request.
5. The relay consumes the binding once, checks policy, and invokes the real issuer. Fresh grant-backed PF A/B issuance supplies a separately audienced PF B tool JWT. The relay independently verifies the tool JWT and compares all delegated identity fields.
6. An operator-only, fixed-destination Docker probe carries that tool token over pinned mTLS to the existing private tool. The tool independently verifies its workload, JWT and current PDP before/after the fixed read-only diagnostic. The relay rechecks authority and releases only `{"authorized":true}`.

The Docker probe is a **test transport**, not the production relay implementation: it is launched by the Windows operator and receives tokens on stdin and only the outbound client identity/CA in a read-only temporary mount. No Docker socket is mounted into a service. The persistent container deployment must use the already implemented standard private HTTPS client, not spawn privileged Docker commands per request.

## Issuer custody

`src/copilot/relay-issuer.ts` implements `InteractiveRelayIssuer`. Its `remember` method is internal broker orchestration, not an HTTP route. It independently validates exact broker proof and fresh human OIDC evidence and checks current grant policy. Proof custody is bounded by 120 seconds, broker expiry and human-login expiry, with finite capacity and no persistence or automatic reconstruction.

`issue` consumes that proof once, re-verifies broker/login and every context identity field, checks current policy, and passes only verified claims plus the retained human evidence to a configured issuer. It rechecks policy/expiry/cancellation before returning. Failure never restores proof; close/forget erases it and leaves a short replay tombstone. Autonomous provider issuance is intentionally unsupported; the independent autonomous PF/tool path is unchanged. The relay still independently verifies the returned token; a string from the issuer alone is not authority.

The lab callback uses the existing registered-agent key and real policy/authority/PF exchange. It cannot select a grant/actor from request fields. These local protected workload keys are not a claim of production hardware/workload-federated custody or a general production directory implementation.

## Actual checks

**All 15 checks passed:** real broker/user/human-proof binding; separate connection credential; body authority rejection; fresh real-PF issuance/private-tool success; consumed-binding replay denial; missing downstream certificate; rejection of PF A user proof as a tool credential; tool body override rejection; independent human/actor/org/grant/mode/resource audit; same-human but unbound-token denial; owner revocation blocking prepared relay issuance; direct issuer revocation denial; rejection of the previously minted tool token after revocation; terminal revoked-version PDP evidence; credential-free authenticated relay journal.

Exactly **one new synthetic owner-consented grant** was created and revoked. Pre-existing grant states/versions were independently preserved. PF A human login remains enabled and PF B tool exchange was enabled only for the bounded test and restored disabled. The running tool/container identity and its private networking were preserved. Temporary credential copies/probes were removed, the loopback listener and consent portal closed, and the exclusive execution lock released. No token, nonce or original connection key was written to test fixtures/logs/prompts; the operator-only connector key entered the worker on stdin. Restricted grant/evidence metadata and authenticated audit remain locally retained.

Receipts are under:

`E:\development\projects\copilot\federated-copilot-codex\.local\tool-vault\real-relay-ebd444b0-7144-4c15-b2ac-27a20de3cdcc`

`worker-result.json` records the 15 checks; `verification.json` independently confirms revoked owned grant, restored PF clients, removed temporary credentials, preserved service and byte-for-byte unchanged historical Microsoft budgets. All **nine Microsoft conversation reservations remain consumed**.

## Commands and regression coverage

```powershell
npm run relay:real-test
npm run relay:real-test -- --run
```

The first command previews scope. The second performs a bounded **local** test with one new synthetic consent, temporarily enables the dedicated PF B client, and cleans up only owned resources. It requires the activated private tool and policy service with more than four minutes remaining on its bounded authority lease. No Microsoft channel or Direct Line credential is used.

All **318 baseline and 381 production tests pass**, including 11 new signed-JOSE issuer custody/identity/nonce/revocation/expiry/replay tests. These tests and the 15 real-container checks are separate evidence from the earlier successful Copilot sign-in.

## Remaining gates

The permanent relay process is still stopped. Its earlier selected runtime preparation correctly retains `authorityWired=false`; this successful bounded harness does not silently install a production composition. Next, package the real issuer/control-plane context lifecycle and private container networking, with appropriate secret-manager custody and operations/stop handling. Then review the exact public ingress and connector secure-input/trace behavior before approval and a separately bounded live Copilot tool test. Exact token continuity inside Copilot, autonomous provider SSO and in-Copilot expiry behavior remain unverified. Graph/SharePoint remain disconnected.
