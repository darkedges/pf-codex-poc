# Persistent relay deployment review

The [real local integration](copilot-real-relay.md) passes, but the diagnostic harness cannot be deployed unchanged. Its operator launches Docker probes and signs lab agent evidence using local test keys. A persistent relay must do neither. This review creates no resources and authorizes no public ingress.

The proposed callback is `https://relay.copilot.darkedges.com/v1/copilot-tools/verify-access`, forwarded only to loopback `127.0.0.1:9464`. These are proposals, not configured DNS/tunnel routes. The private tool remains at `https://tool-api:8443` with no published port. Its existing enrolled relay caller stays active.

The blocking authority boundary is concrete: the current local issuer helper constructs the agent proof with a lab agent private key. The persistent service must receive fresh independently authenticated agent evidence through the trusted gateway/control plane, bind it to the verified broker/human/grant, and retain it only for the short session. It must not receive an external agent's private key or accept grant/identity values from a topic or ordinary header. The current public relay API deliberately exposes no registration route. A new authenticated control-plane registration contract is needed before service startup.

The container must join the tool's private network and use the standard pinned HTTPS client directly. Network access to PF, PDP, Vault and Direct Line must be explicit; the internal tool network alone provides no Microsoft egress. Do not attach arbitrary networks, publish the tool, or grant Docker socket access to bridge that gap. A selected immutable relay image and controller-owned startup/drain/credential retirement are still required.

The runtime receives only its selected credential snapshot and approved workload material. The connector key remains separately enrolled in the connection. Deterministic `System.User.AccessToken` handling and suppression from model inputs/run history require tenant verification before publishing a connector action. Local HMAC journals follow the selected one-day stopped-maintenance policy; custody/operations records and verification receipts are separate.

Run `node scripts/vault/relay-deployment-review.mjs` to validate the non-deploying draft. It always reports `deployable:false` while the recorded gates remain unresolved. Negative tests reject public activation, agent private-key/Docker socket mounts and mock fallback. No new Microsoft test allowance is inferred; all nine historical reservations remain consumed.

Next implementation is the authenticated gateway-to-issuer proof handoff. Public-route approval should be requested only after that contract, persistent hosting and secure connector configuration are concrete and locally verified.
