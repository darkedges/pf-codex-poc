# Portal OIDC signing-key pin refresh

Prepared, not applied. The owner reached the public portal callback after password entry. PF audit reports a successful login and OAuth activity; the portal returns its generic failure before consent. The exact callback exception is not retained, so its cause is not conclusively identified. No authorization code supplied in chat was replayed.

One concrete trust mismatch exists: PF A uses dynamic OAuth/OIDC signing keys and publishes a newer RSA signing key absent from the approved OIDC key-ID list. The existing explicit allowlist correctly rejects unapproved keys. [Ping documents automatic dynamic signing-key rotation](https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_config_dynamic_signing_keys.html). An approved pin refresh is a candidate fix, not proof of successful callback validation.

Add only these two identifiers for the same RSA2048 signing public key, retrieved through the existing TLS-trusted `https://localhost:9033/pf/JWKS` endpoint:

- `woK5AoNRouuZp6flPUA24xU8mnc`
- `woK5AoNRouuZp6flPUA24xU8mnc_RS256`

RFC7638 JWK thumbprint: `UeRr6Pmb-hpZCKqVH4w_OK8bdkZX33U7hbJ-axEwZ3s`. Verify both aliases have the identical modulus/exponent, signature use and RS256-compatible metadata; refuse if either changes. No private key is read or copied. Do not trust all published keys or use a key URL from a token.

Only `.local/pingfederate/oidc-config.json` changes, by adding those two pins. Keep the existing pins, issuer, JWKS URL, audience/client ID, redirect rules, algorithm, nonce, lifetime and signature requirements. The candidate config SHA256 is `63fbc9ff17930c644fe3d6d4980d1362783ee50cd9609dd9deb8f5a9a18d4327`; candidate activation manifest SHA256 is `9d2695631576e057b5c5ae18c523206592a5b3c3717e0c4b4e8f99463d116124`. No runtime source changes are included. Ten OIDC tests pass, including explicit-rotation acceptance and unknown-key, wrong-signature, issuer, audience, nonce and expiry rejection.

The portal is stopped. Before applying, verify the exact candidate and unchanged packet, unused approved trial, no pending owned grant, original unexpired activation window and disabled PF tool client. Archive current manifest, approval, window and OIDC config byte-for-byte. Record explicit key-refresh approval, replace the one config hash in the manifest, and rebind only the window's manifest hash. Preserve original review, start, original approval timestamp, expiry **2026-11-01T04:54:36.553Z (15:54 AEDT)**, trial database and all counters. Refuse expired/reserved/spent state; never reset the allowance.

Stop/restart only the existing owned relay/private-tool services as required to load the new OIDC pins; preserve policy data, credentials, audit retention and all historical test ledgers. No autostart or automatic renewal is installed. Their ordinary service leases do not extend the portal window. Restart disabled portal stage, reverify public HTTPS/no-store/denied paths and read-only Microsoft connectivity, then resume live under the existing remaining allowance. PF B tool enable/disable remains owned by the existing bounded lease.

No PF signing configuration/key rotation, OAuth client change, public route, new identity provisioning, billing, agent publication or Microsoft test is authorized by this amendment. No automated human login; the owner may retry manual sign-in before the original expiry. Callback success and the delegated diagnostic remain UNVERIFIED until observed.

Explicit approval is required because this updates a public-trust pin and the original live packet requires exact configuration hashes; do not silently broaden trust under the prior source-only amendments.
