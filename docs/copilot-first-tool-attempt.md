# First Microsoft delegated diagnostic attempt

Status: **sign-in verified; delegated tool acceptance UNVERIFIED**.

The user explicitly approved continuing the existing token-as-tool-input design for this PoC despite unverified Microsoft credential trace protection. The local exception does not change production approval or local credential logging rules.

## Publication and correction

The first publication failed with `InvalidPropertyPath` on the connector action. Its hyphenated header required a quoted Power Fx property identifier: `propertyName: "'X-PF-User-Access-Token'"`. The separate `MakerConnectionIsUsed` item was a warning. After the correction, PAC reported publication success. A subsequent pull reported `publishedOn: 2026-10-31T14:23:44.0000000Z` and the saved action/topic matched the reviewed candidates. This timestamp is the platform value; the user-facing date is 1 November 2026 Australia/Sydney.

## Bounded live result

Run: `222091e0-bbf1-4fa6-8fc6-04d0cce8ced0`.

- One new Direct Line conversation and one token POST; no automatic retry.
- Existing adapter extracted the fresh OAuth card's exact secure URL and posted the configured PF A provider token as JSON `{token: ...}`. No token or signed URL was written to local evidence.
- Exact provider token and independently verified broker/agent/human evidence registered through the private mTLS/signed gateway handoff. Restricted relay audit records show that handoff completed.
- Microsoft token POST returned **HTTP 200**.
- Published runtime diagnostic reported `User.IsLoggedIn=true`.
- The fixed delegated-tool trigger was submitted once. No verified success message or `policy-tool` authorization decision was observed for this grant.
- Owned grant revoked; existing grant states/versions and historical allowance files preserved; PF B tool client restored disabled; managed services remain ready.
- No Graph calls. Local raw credentials were not retained.

The failure is after successful sign-in, during the diagnostic stage. It is not a recurrence of token-post HTTP 400. The absence of a tool policy decision does not distinguish orchestration/input/connector problems from a callback rejected before policy evaluation.

Evidence: `.local/tool-vault/microsoft-tool-222091e0-bbf1-4fa6-8fc6-04d0cce8ced0/verification.json`. Separate consumed allowance: `.local/copilot/live-sso-tool-diagnostic-1-budget.json`. Publication receipt and PoC exception are under `.local/copilot/relay-microsoft-review/`.

## Next evidence

Inspect the existing conversation's sanitized tool error when Microsoft makes its transcript available. A scoped read-only PAC FetchXML query for this agent and test window returned no matching transcript content immediately after completion. The inspector keeps any raw transcript in memory and emits only fixed diagnostic categories. Do not interpret unavailable transcripts as successful execution or absence of platform logging.

Correction from subsequent inspection: the inspector's earlier `on-or-after`/`on-or-before` filters compared calendar dates, not the intended precise test window. The returned fragment belonged to a 14:01 UTC session and must not be attributed to this test. Timestamp `ge`/`le` filters return no matching record for 14:24–14:27 UTC. A failing-first regression now guards the query. Fixed stage markers and sanitized transport evidence are prepared for a [separately approved follow-up](microsoft-tool-followup-review.md); no root cause is claimed.

Do not reset the ledger, rerun `--run`, or open another conversation under this consumed allowance. Diagnose from existing evidence, correct the draft, and obtain a separately bounded attempt only when another live test is needed. Autonomous SSO, Graph and production readiness remain UNVERIFIED/not connected as previously documented.
