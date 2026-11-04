# Key-only amendment to the approved five-session deployment

The owner approved the five-session deployment and the exact earlier key refresh in `docs/portal-repeatable-session-review.md`. That session approval stands. Deployment preflight then found one further RSA signing key published since preparation; it refused activation. No live config, journal, allowance, public route or PF client was changed.

Approve adding only these two public identifiers to the already reviewed OIDC pin list:

- `Q-jBFA9PcCV2HWmSw6WsFUGViEc`
- `Q-jBFA9PcCV2HWmSw6WsFUGViEc_RS256`

They are aliases for the same RSA2048 signing public key from the existing TLS-trusted `https://localhost:9033/pf/JWKS` endpoint. RFC7638 thumbprint: `LovAeCMg2w7YKVqhLcAxRoSyRQjpYYzI1X8xSC1nO8k`. Reverify the exact public material before applying; refuse drift. No private key is read/exported and no PF key generation or rotation is requested.

The approved candidate manifest SHA256 is `93f3b5efcf3c34a431400fc6399f6099f5570d6391c495fdd6d4dd56b41c8e8d`; the amended candidate is `5215aef0a40b4c5fa3b6643e8a8b8b7328074e4b4605f4db8ac39e767e152d98`. Its only difference is the OIDC config hash, now `03ee5541d148f73f272310b2441ab675805e876a5b6ff7cd5ba2817889d9d901`, adding these aliases. Source and all existing pins, exact issuer/audience/signature/lifetime checks, callbacks, credentials, billing, routes and predecessor records stay unchanged. The618 production and372 simulation test results still apply to unchanged source.

This amendment permits completing the already approved deployment after its normal fresh readiness checks, with the same run ID `5047fea6-ce89-4d4c-b62d-06652af5a094`, at most five manually consented sessions in one fixed hour, one active at a time. The window and new ledger have not started. It is not another session allowance or an extension; no original spent record is reset. Existing service restarts, cleanup, expiry and maintenance constraints remain as reviewed.

Separate approval is required only for this additional public-key admission; the prior packet named the earlier key precisely and does not authorize automatic trust of subsequent keys.
