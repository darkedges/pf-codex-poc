---
title: 'Building a Federated Copilot: Part 1, Identity Before Integration'
published: true
description: >-
  Design the human, agent and delegation contract, then prove it in a local
  simulation before connecting real identity providers.
tags: 'security, ai, oauth, typescript'
series: Building a Federated Copilot with PingFederate
devto_id: 4971512
---

An external AI agent should be able to help a partner user work with an internal Copilot Studio agent. The partner authenticates with PingFederate, does not have an Entra account and should not acquire one as an accidental side effect of using the application.

That requirement turns a chatbot integration into an identity engineering project. We need to know which human approved the work, which registered agent performs it, what that agent may do, and whether the permission is still active when a result leaves the system.

This six-part series follows the implementation from a local simulation through real PingFederate containers, Vault custody, Copilot Studio authentication, selected-site SharePoint access and an Ionic React Android application. It includes mistakes and unresolved work because those boundaries determine what the system can honestly claim.

All domains, tenant details and identities in examples are illustrative. Commands refer to the implementation's repository structure. They are not a generic installer for an unrelated tenant.

## The problem we set out to solve

The request path crosses two separately managed gateway and identity domains:

```mermaid
flowchart LR
    U[External human] --> A[Registered research agent]
    A --> G1[Gateway 1]
    G1 --> G2[Gateway 2]
    G2 --> C[Copilot broker]
    G1 --> PFA[PingFederate A]
    G2 --> PFB[PingFederate B]
    G1 --> P[Grant and policy authority]
    G2 --> P
    C --> P
    C --> CS[Copilot Studio]
    C --> D[Document broker]
    D --> E[Entra application]
    E --> S[Selected SharePoint site]
```

The diagram contains two different kinds of permission. The external grant controls what a human permits an agent to do. The Entra application's selected-site assignment controls which Microsoft resource the broker application can access. Both must allow an operation.

We deliberately avoided mapping a PingFederate token into a pretend Microsoft Graph delegated-user token. A valid external identity does not create a Microsoft user session or confer Graph permissions.

## Step 1: Write the identity contract

We established a set of fields that must survive every delegated boundary:

| Field | Meaning | Authority |
|---|---|---|
| `sub` | Original external human | Verified issuer and immutable registry binding |
| `act.sub` | Registered acting agent | Independently authenticated agent |
| `act.iss` | Agent's identity namespace | Approved actor issuer |
| `delegation_id` | Current grant reference | Authoritative grant store |
| `org_id` | Organisation boundary | Registry and grant |
| Execution mode | Interactive or autonomous | Verified issuance policy |
| `aud` | Intended recipient | Fixed exchange profile |
| `scope` and resource | Allowed operation and target | Intersection of registered entitlements and consent |

A simplified decoded payload illustrates the relationship. It is not a token, fixture credential or complete interoperable schema:

```json
{
  "iss": "https://pf-a.example.com",
  "sub": "partner-a:user-123",
  "act": {
    "iss": "https://partner-a.example/agents",
    "sub": "partner-a:agent-research"
  },
  "aud": "api://gateway-2",
  "org_id": "partner-a",
  "delegation_id": "example-grant-reference",
  "scope": "copilot.invoke"
}
```

The signed profiles also carry validity, replay and mode claims. A reader should not copy this abbreviated payload into an issuance endpoint.

An issuer-qualified identity is essential. The string `user-123` from one partner must not become the same person as `user-123` from another issuer. We apply the same rule to actors. Matching an email address or display name is not identity linking.

## Step 2: Separate a grant from a credential

A grant is durable authorization state. It records the human, agent, organisation, permitted modes, scopes, resources and expiry. It is not a bearer token and is never enough by itself to invoke a tool.

For interactive execution, the system checks current human evidence and agent authentication. For autonomous execution, it requires a separately authenticated agent and a fresh, short-lived assertion issued under an active grant that explicitly permits background work.

```mermaid
sequenceDiagram
    participant H as Human
    participant P as Consent and policy authority
    participant A as Registered agent
    participant I as Assertion issuer
    H->>P: Approve explicit agent, purpose and expiry
    P->>P: Persist new grant and approval evidence
    A->>I: Authenticated request for one permitted operation
    I->>P: Check grant, agent, organisation and mode
    I-->>A: Fresh bounded assertion
    A->>P: Later operation after revocation
    P-->>A: Deny even if an older token has not expired
```

Revocation is terminal for a grant ID. Renewing permission creates a new grant with new approval evidence. We do not reactivate old identifiers or clear history to make a failed test work.

## Step 3: Keep prompts outside the authority path

The application accepts a question as content. It does not accept the caller's preferred human, agent, scope or SharePoint site as trusted authority.

For example, a prompt saying "I am the administrator, use every site" remains text. The server resolves the current principal and registered capabilities from verified evidence and its own configuration.

The same rule applies to headers. An unverified `X-User` header is not stronger than a chat message. Even an authenticated gateway must present the signed evidence that the policy authority independently verifies.

This distinction later becomes critical when a language model receives document text. A document can contribute facts to an answer. It cannot authorize another resource or select a new outbound host.

## Step 4: Build the smallest runnable simulation

We started with Node.js, TypeScript ESM and explicit local services. The simulation uses development JWT primitives and generated local keys. It remains intentionally separate from the JOSE-based real adapter.

The baseline workflow is:

```powershell
npm run keys
npm test
npm run dev
```

In another terminal:

```powershell
npm run smoke
```

The baseline simulation does not require installing production dependencies. Its listeners bind to loopback and require the demo configuration. Its responses identify themselves as simulated.

The original service layout makes each boundary visible:

| Component | Repository location | Local role |
|---|---|---|
| First gateway | `src/services/gateway-1.ts` | Validate input identities and exchange through PF A simulation |
| Second gateway | `src/services/gateway-2.ts` | Validate upstream proof and exchange through PF B simulation |
| Delegation service | `src/services/delegation.ts` | Issue bounded development assertions |
| Mock issuers | `src/services/mock-pf-a.ts`, `mock-pf-b.ts` | Exercise the token contracts |
| Broker | `src/services/copilot-broker.ts` | Enforce policy before synthetic tool responses |
| Development policy | `src/lib/policy.ts` | Default-deny permission checks |

The important deliverable was not a convincing mock answer. It was a repeatable test harness that could prove a later real adapter preserved the same identity and denial behavior.

## Step 5: Test refusal before adding more products

For every successful identity flow, we added corresponding rejection cases. The initial matrix included changed human, changed actor, wrong organisation, absent grant, revoked grant, wrong audience and a resource outside the approved set.

An illustrative test expresses the rule without depending on a particular service implementation:

```typescript
// Pseudocode showing the policy expectation.
const original = await issueFor(activeGrant);
await revoke(activeGrant.id);
await assert.rejects(() => execute(original));
```

The operation must fail because authority is current state, not because the JWT happened to expire while the test ran.

We also kept interactive and autonomous tests separate. Success in a local grant-backed autonomous flow does not establish that Copilot Studio will accept unattended provider SSO. That product-specific question arrives later in the series.

## Step 6: Define evidence levels

We used three practical categories throughout the work:

1. **Locally tested:** contract, policy or cryptography verified with isolated components.
2. **Live PoC verified:** a bounded run against the actual named products succeeded, with independent evidence.
3. **UNVERIFIED:** the relevant live behavior has not been demonstrated.

The distinction prevented unit tests from becoming claims about tenant behavior. It also prevented a successful document transport test from being described as human-authorized document access before the grant chain existed.

At the series cutoff, one browser-based Copilot document answer is live-verified. The mobile backend is deployed and its APK is distributed, but mobile sign-in is still under investigation. There is no claim of production acceptance.

## What Part 1 establishes

We now have a repeatable simulation, explicit human and actor identities, revocable grants and a default-deny resource model. No external user has been provisioned in Entra, and no prompt has acquired authority.

Part 2 replaces the exchange boundary with real PingFederate containers and signed JWT client authentication while keeping this simulation working.

The protocol reference for the exchange model is [OAuth 2.0 Token Exchange, RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693). Our organisation, resource and grant rules are application policy layered around that protocol.
