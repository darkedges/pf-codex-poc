# PingFederate Integration Configuration (Target)

Gateway 2's production library adapter is now implemented; see [configuration and live integration approval plan](gateway-2-production.md). Live server behavior remains **UNVERIFIED**. PF A and the HTTP demo remain simulations.

Reference: https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_oauth_exchange.html

## PingFederate A

1. Register an interactive frontend OIDC client (Authorization Code + PKCE).
2. Register an external agent workload and a Gateway 1 confidential client. Prefer `private_key_jwt` or mTLS.
3. Configure a token-exchange processor policy with actor token **required**, valid user token processor, agent token processor, contract mappings, issuance criteria and audience checks.
4. Add an autonomous **delegation-assertion processor** only after a security-reviewed signed assertion issuer is implemented. This is custom integration and not an assumed out-of-box grant.
5. Map immutable subject, original actor, external organisation, grant ID, mode and narrowed scopes to a signed access token for `api://gateway-2`.
6. Permit only an approved requesting client and explicit target audience.

## PingFederate B

1. Trust *only* the approved PingFederate A issuer with the correct HTTPS metadata/JWKS (including key rollover policy) and configured JWT token processor.
2. Create a Gateway 2 confidential OAuth client with token exchange enabled and a scoped processor policy.
3. Require signed upstream token to have `aud=api://gateway-2`; enforce issuer, algorithm, signature, timestamps, actor and grant policy.
4. Map subject and actor into a locally issued `api://copilot-broker` access token and separate tool-audienced token for protected APIs.
5. Ensure requested scopes cannot expand beyond the original grant and resource policy.
6. Configure inbound OIDC/SAML federation to PingFederate A only if interactive fallback requires a user browser login. This is separate from the JWT trust for token exchange.

## Claims

`iss` must be the actual current issuer, `sub` the original human, `act.sub` the external agent, `client_id` the technical OAuth client where included, `aud` the next-hop intended audience, and `delegation_id` the independently verified grant reference. Do not turn gateway identity into a replacement for the original actor.

## Verification

- Reject wrong `iss`, `aud`, signature, alg, `kid`, expired/early tokens.
- Reject inactive grant, mismatched human or agent, wrong client, unregistered partner, unapproved audience and scope elevation.
- Validate interactive and autonomous flows independently; include revocation while a Copilot session remains open.
- Do not log access tokens, subject assertions, signing material or SAS challenge URLs.

## Caveat

The local demonstration has **no client authentication at mock token endpoints**. It deliberately simplifies PingFederate behaviour and must not be deployed with real data or internet access.
