# Corrected provider test — actual cURL capture

Executed 2026-10-31 Australia/Sydney following the user's explicit request to run one test and capture real data for support. **One new interactive conversation and one token POST were reserved and used. No POST retry occurred.** The original four historical allowances were unchanged. The Microsoft result remains a rejection, not a successful SSO test.

## Observed result

| Field | Captured value |
|---|---|
| Microsoft request ID | `7da611c1417a7063c88ae1f2bbbcf00d` |
| Application POST invocation | 2026-10-30 20:38:38.920 UTC / 2026-10-31 07:38:38.920 AEDT |
| Provider issuer | `https://pf-a.copilot.darkedges.com` |
| Provider audience/scope | `api://copilot-login` / `copilot.login` |
| Signature and trusted identity binding | Verified before POST |
| Provider token lifetime remaining at POST | 174 seconds |
| Challenge remaining at POST | 57 seconds against host / 58 against provider Date |
| Measured card-to-cURL interval | **161.787 ms** |
| Response | **HTTP/1.1 400 Bad Request** |
| Response Content-Type / Content-Length | `application/json; charset=utf-8` / `18` |
| Exact response body | `"Token is expired"` |

The body is a JSON string, not an error object. It required no redaction and was preserved verbatim. The returned text does not identify whether the expired object was the secure URL, OAuth state, connection/user binding, or posted token. The PF A token matches the recorded agent provider configuration; current live tenant settings were not independently inspected. Copilot acceptance remains **UNVERIFIED**.

Timing is now directly measured with a monotonic clock from the parsed OAuth card being available in the client to cURL invocation. The recorded wall timestamps are card observation `20:38:38.758Z`, invocation `20:38:38.920Z`, response receipt `20:38:39.307Z`. This does not claim packet-level delivery/first-byte timing or include cURL process/TLS setup after invocation.

## Capture mechanism

`npm run copilot:provider-capture` previews the bounded action; `-- --run` uses a separate one-use `configured-provider-capture` allowance. That specific allowance is now consumed, and cannot be replayed. Future attempts require fresh explicit approval and a separate bounded allowance; do not delete/reset this ledger or use old retry flags.

The worker uses the corrected PF A token verifier/binding and independently checks the separate delegated tool proof. Only the secure token POST uses installed cURL 8.21.0. `--disable` prevents loading curlrc, no redirect-following or retry flag is enabled, HTTPS/TLS verification remains on, and timeout/response limits are bounded. The original signed URL and actual provider token are supplied through process stdin, not command arguments, shell text or credential files. cURL stdout is parsed only in memory; raw request credentials and unredacted headers are not logged.

Before writing artifacts the capture removes known credentials, signed query values, JWTs, bearer values, sensitive JSON/query fields and cookies. Only selected response headers are retained. Automatically generated request headers were not captured; omitted response header names are listed explicitly. The request URL/body representations are credential-redacted, not byte-for-byte replay material.

The protected packet contains `agent-report.md`, `request-response.json`, `request-redacted.curl.txt`, `response-redacted.http` and `run-cleanup.json`. This packet is the corrected-provider evidence to share; the older approved support packet describes historical PF B-token failures and was not rewritten or submitted.

## Cleanup and checks

The parent independently confirmed the test's owner-consented grant revoked, PF A login enabled/PF B tool client disabled, historical allowance hashes unchanged, and retirement/removal of the dedicated five-minute sign-only Vault lease. The running private controller was not stopped or reconfigured. No Microsoft settings, Graph access, public route or support case was changed. Only interactive execution was attempted. The harness now requests foreground-only consent for provider-capture mode.

Seven new failing-first tests cover one-use allowance isolation, request destination/header/body constraints, actual response parsing and credential-redaction behavior. All **288 baseline** and **315 production** tests pass. These test passes do not turn the actual Microsoft HTTP 400 into SSO acceptance.

Microsoft service-side tracing can now use the new request ID, correct provider-token profile, actual response body and measured short delay. No further live attempt is authorized by the completed capture.
