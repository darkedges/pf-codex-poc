# Relay HTTPS and broker lifecycle composition

Follow-up: [Vault enrollment and isolated Docker routing](copilot-relay-vault-network.md) now pass 22 live custody and 14 candidate-network checks. The new caller has not yet been activated in the existing tool, and the persistent relay is not started. The running tool was restarted after its original bounded signing lease expired.

Local implementation completed 2026-10-31 Australia/Sydney. **Actual Copilot tool invocation remains UNVERIFIED.** This milestone adds transport and lifecycle wiring to the [relay core](copilot-tool-relay.md). Factories do not open listeners, read credentials, choose mock mode, enroll Vault records or change the running controller. Tests open only ephemeral `127.0.0.1` HTTPS listeners with disposable certificates and synthetic credentials; none remain running.

## Composition root

`composeProviderToolConnection` in `src/copilot/provider-relay-http.ts` constructs the relay, `DirectLineAdapter` and relay HTTPS server. It rejects mismatched broker audiences, scope and provider issuer/audience/scope between the channel and relay profiles. It shares the explicitly supplied broker/provider verifiers and trusted provider-to-broker identity mapping across those components, installs the relay's lifecycle hooks, and constructs the fixed private mTLS tool invoker. There is no default network destination or mock fallback.

The caller must still supply approved channel credentials, connector authentication, independent online policy, grant-backed fresh issuance, audit, TLS identity and the private tool's exact origin/CA/server leaf pin/client identity. This is a typed composition factory, **not an environment loader or persistent runtime deployment**. It has not been installed into the running local controller or live agent. The generic Direct Line adapter retains its existing behavior when no relay hook is composed.

## Broker lifecycle

Before posting the independently verified PF A token to a fresh OAuth card, the composed adapter registers the exact token and current broker proof internally. Registration failure prevents the token POST. A POST failure, session error, expiry, end-of-conversation or explicit close invalidates the corresponding relay binding while clearing channel credentials. Replacing the session's provider token invalidates the preceding binding first.

Binding preparation receives the adapter's cancellation signal. The relay checks that signal before committing authority, so a late verifier/policy/audit completion after an adapter deadline cannot create a usable binding. Session invalidation also suppresses release from an in-flight relay operation. Registration occurs immediately before the POST to avoid a callback racing ahead of binding availability; it is not a claim that Microsoft has already accepted the token. Both independently authenticated connection possession and pre-existing broker authority are still mandatory.

This wiring opens no additional Microsoft conversation. All nine live conversation reservations remain consumed.

## Inbound HTTPS

`createProviderRelayServer` uses TLS 1.2 or newer, requires explicit server key/certificate, and exposes only `POST /v1/copilot-tools/verify-access`. It maps the draft connector's single `X-PF-User-Access-Token` header and separate `X-Copilot-Connection-Key` credential into the core API. It rejects duplicate credentials, an additional Authorization header, known identity/resource override headers, query strings, other paths, alternate media types, content encoding, nonempty JSON properties and bodies over 1 KiB. The connection key header is capped at 512 characters and the provider token at 16000.

Responses are fixed JSON with no-store and nosniff. No request header, token, body or URL is logged; the optional observation contains only a fixed event name and status. Bounds are explicit: 1–32 simultaneous requests, at most 128 connections, a global fixed-window ceiling of 1–1000 requests/minute, 20 KiB headers, 32 header fields, five-second header/handshake limits and ten-second request/socket limits. Admission fails with 503 or 429. `beginDrain()` refuses new work. This is process-local admission, not a distributed rate limiter or a guarantee against connection-level denial of service.

The factory does not enforce a listen address: the trusted host composition must bind loopback for this PoC and require explicit approval before any public listener/route. No CORS/browser credential endpoint is added. The separate connection key authenticates possession, not Microsoft tenant attestation. Safe connector secret handling and deterministic system-token header binding remain live verification gates.

## Outbound private tool

`createPrivateToolInvoker` snapshots an explicit fixed HTTPS origin, client key/certificate, CA and server certificate SHA-256 fingerprint. It uses hostname/CA validation **and** the leaf pin, mandatory TLS verification, no connection agent reuse and the one fixed diagnostic path. It sends only a tool-audience bearer and `{}`. It never follows redirects or retries. It checks external cancellation and a total 100–10000 ms deadline, bounds the response at 1 KiB, and accepts only HTTP 200 JSON containing exactly `{"authorized":true}`. All failures have a sanitized unavailable contract.

The existing private tool still independently verifies the approved mTLS workload, tool JWT and before/after PDP authorization. Server certificate rotation requires an explicitly updated approved pin and composition restart. Network reachability between a future host/container relay and the currently private Docker tool is **not yet established**; do not publish the existing tool or infer Docker Desktop routing from these tests. Certificate enrollment, selected Vault snapshots, internal-network placement and approved route forwarding must be reviewed as a concrete deployment package.

Disconnect/deadline failure cannot undo a downstream operation already completed. This path remains a read-only authorization diagnostic; write operations would need their own idempotency design and approval.

## Verification and next gates

All **297 baseline and 361 production tests pass**. Sixteen new tests cover lifecycle success/failure/close/cancellation, complete composed local relay-to-mTLS invocation, duplicate/authority header and oversized-body denial, wrong peer/workload certificate, redirects, response projection, fixed endpoint selection, rate/concurrency ceilings and drain. The earlier signed-JOSE relay tests remain in the full suite. The HTTPS transport tests use synthetic verifier dependencies; they are not a real PF/container or Microsoft acceptance test.

Next, prepare the actual selected Vault credential enrollment, durable audit sink, fixed issuance composition and private Docker routing for the existing Windows/Docker host. Review runtime/startup/stop ownership and exact ingress hostname/path before requesting public-route approval. Then configure the dedicated connector with secure inputs, publish a deterministic diagnostic action and request a separately bounded live test. Do not copy the connector key into topic YAML, model instructions or chat. No production IAM, Graph grant, tenant configuration, public route, certificate issuance or persistent service was changed here.
