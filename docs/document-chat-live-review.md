# One question with the approved SharePoint sample — deployment review

Status: FRESH WINDOW PREPARED, NOT STARTED. The timestamp-corrected deployment was ready and independently verified on3 November2026 at08:06AEDT, then stopped at its fixed08:50:53AEDT deadline without a sign-in, grant, document read or Microsoft request. All four PF clients were independently confirmed restored; zero pending consents and empty operation counters. The complete359-file packet, spent window, activation and expiry confirmations are preserved in .local/tool-vault/document-chat/expired-unused-spent. This review requests exactly one new45-minute window under the same limits, starting only after fresh approval. It does not reopen or extend the expired window. The first approved startup is spent: it stopped at the callback-baseline check before any Vault secret read, client change, listener, grant, content read or Microsoft request. Cleanup was independently confirmed. Its complete 351-file packet and ownership/results remain under .local/tool-vault/document-chat/startup-ciphertext-spent. Live document-backed Copilot chat remains **UNVERIFIED**. This is an interactive PoC, not production approval. The successful PF-only verification and every earlier Microsoft/content allowance remain spent.

## Result to approve

Run the new browser flow at the existing https://agent.copilot.darkedges.com address for **one session, one question, in one fixed 45-minute window**. The window begins at startup and cannot be renewed or restarted. The original browser session has a five-minute deadline; additional logins do not extend it. This first version is a document answer, not an unrestricted chat history or site search.

The user signs in to PF A, approves one `copilot.invoke` chat, connects the existing Generic OAuth provider, signs in again as the same human, then separately approves one `m365.document.read` operation for five minutes. A second ID-token proof is necessary because each persisted consent is bound to its own fresh login proof. Neither grant is a token. The registered agent must authenticate independently, and PF A/B, local and remote policy, signature, issuer, audience, human/actor/organisation/mode/grant and current revocation checks remain mandatory.

Only the existing synthetic **201-byte federated-copilot-poc.txt**, alias `poc-sample`, in **FederatedCopilotPoC** is available. The document SHA-256 must equal `d37938e1dd000ca43886ac0a36806e7218e70b7f92a1cbca68ea5926adeb9a09`. The broker still uses its existing resource-scoped Entra application with **Sites.Selected** and the existing read-only grant. External users receive no Entra identity. App-only Graph permission and external human/agent authorization remain separate.

The server sends the approved document text, document name and the user's question as data to the existing published Copilot agent. It does not publish a new agent, install a native SharePoint tool, enable arbitrary URLs or search, or treat document/chat instructions as authorization. The existing diagnostic connector gets no provider-session binding from this runtime and cannot acquire delegated access through this session.

## Exact temporary operational changes

- Start only owned loopback policy listeners on **9452** and **9453**, plus the isolated TLS web worker on the existing **9466** origin. Refuse occupied ports, an existing controller/policy lock or any prior instance of this packet. Reuse existing tunnel/DNS/TLS/routes; no new public port, ingress rule or hostname.
- Temporarily enable only `document-gateway-1` on PF A, `document-gateway-2` on PF B, `consent-gateway-1` on PF A and `consent-gateway-2` on PF B, if their reviewed baseline disabled them. Their full reviewed configurations, private_key_jwt authentication, replay protection and single scopes must match. Restore their exact prior enabled flags on normal completion/stop; never overwrite foreign drift. Existing OIDC/provider client configurations and callbacks are read-only preconditions.
- Retrieve existing credentials through their existing narrow Vault readers: portal controller/executor/TLS, document PF clients, three separate document policy callers and SharePoint broker. Use the existing non-exportable document Transit signer. No new key, role, policy, custody record, certificate, IAM grant or Microsoft billing policy.
- The legacy chat policy bootstrap uses the existing local operator credential to issue one **one-hour** scoped consent-authority signing lease and perform a synthetic signature preflight. It retires only its tracked lease at shutdown. The document signer retains fresh one-use 120-second leases per signature. No operator credential reaches the web worker or Microsoft.
- The new SQLite session journal and instance record are separate from all spent diagnostic/PF/content budgets. Consent intent is committed before requests. Only independently owned grants created after that intent can be adopted for recovery. A lost consent response with no confirmed grant remains pending; absence is never assumed to prove cleanup.

## Maximum live request allowance

One attempt only; failure consumes the attempt. No automatic retry of token POSTs, content reads or the question.

| Operation | Ceiling |
|---|---:|
| Fresh chat OIDC login / fresh document OIDC login / Generic OAuth login | 1 each |
| Fresh chat consent / document consent | 1 each |
| PF token POSTs, including login and exchanges | 12 |
| Entra broker token request | 1 |
| Graph GETs for exact sample metadata and content redirect | 2 |
| Constrained SharePoint download, without Authorization/Cookie forwarding | 1 |
| Direct Line token generation / conversation start | 1 each |
| Fresh OAuth-card SAS token POST | 1 |
| Direct Line activity POSTs: sign-in status warmup and one question | 2 |
| Direct Line GETs, including bounded polling retries | 50 |
| Document reads / user questions | 1 each |

Use the exact `content.tokenPostResource.sasUrl` received in this new conversation, validated against the saved endpoint contract; never reconstruct or reuse it. The posted credential is the independently verified configured PF A user access token, not a Direct Line or Graph token. JSON body is `{"token":"<provider access token>"}`. Raw values are not retained in the deployment packet, terminal output or diagnostics. Known JWT/broker credential forms are removed from the escaped answer; this is not a Microsoft trace-redaction guarantee.

## Cleanup and limitations

Document consent is revoked and independently confirmed before text is released to the chat executor. Chat consent is revoked and independently confirmed before the answer is released. Cleanup failure withholds output. Each known owned consent is attempted even if the other consent cannot be reconciled. Once the journal is closed, PF flags and owned policy services are retired; the worker may display the answer until the fixed window ends, without further reads or authority. A normal stop drains the worker, recovers known grants, restores PF flags and retires the owned policy lease. Failed cleanup retains locks/status/evidence and blocks restart; no silent retry or allowance reset.

This remains a single Windows-account PoC. A forced process/host termination requires operator recovery of retained ownership records, grants, PF flags and any tracked legacy lease before another deployment. There is no independent PF-disable watchdog, automatic restart or privileged recovery service. The final live activation must not proceed if a previous owner is present. The one-hour lease and short-lived proofs bound credential use but are not proof of cleanup after a crash.

No question, answer, downloaded text, access token, SAS URL or OIDC code is written to this journal. Recovered journal identity references are eligible for removal after one day when maintenance runs; pending recovery records and spent counters remain to prevent replay. This change does not promise offline deletion, change Microsoft retention, or claim that all existing shared policy audit/telemetry stores have a new retention job. The user's existing one-day audit-retention preference remains an operational requirement for broader hosting.

Microsoft receives the question, sample content and provider sign-in credential under the previously accepted PoC trace exception. Microsoft conversation/tool trace protection remains **UNVERIFIED**. Do not use business records, secrets or confidential questions. The model answer is untrusted output and does not establish document accuracy or broader resource access. Existing subscription/metered usage continues; no new billing arrangement is created.

## Verification and success criteria

Local regression: **782 production tests and the previously verified 372 simulation tests pass**. Negative tests cover foreign/older consent adoption, lost responses, cleanup despite an uncertain second consent, persistent spent allowances, new-login denial during execution, identity/grant substitution, escaped model output, RPC credential boundaries, actual isolated loopback worker and owned PF configuration restoration. Startup preview imports successfully without Vault reads, listeners or Microsoft requests. The full live composition has not yet been activated.

After approval, recheck the frozen source/public-config manifest, callbacks, ports and owned state; start once and verify local authenticated readiness without Microsoft requests. The user then operates the one session and asks: **“What is the approved research colour, and what is the document reference? Cite the document name.”** Success requires a real Copilot answer grounded in the hash-verified sample, correct human/agent/grant continuity, request counters within these ceilings, both grants revoked, PF flags restored and owned listeners/lease stopped. The expected synthetic facts are **teal**, **FEDERATED-COPILOT-POC-001** and the sample filename. Record sanitized evidence and the limits actually verified. Failure remains UNVERIFIED and does not authorize another attempt.

The corrected callback fingerprint excludes only the primary clientAuth.encryptedSecret bytes of the configured Generic OAuth SECRET client, because independent consecutive read-only PF responses re-encrypt that field. Every other field, including modificationDate, secondary-secret fields, authentication settings and redirects, remains pinned. The Vault loader separately pins the stored provider secret digest; actual provider authentication must still succeed and is never inferred from configuration. No credential value or permission changes. A new negative regression proves redirect/scope/authentication/metadata changes are still detected. Fixed startup-stage labels now identify the stage without credential details. Independent reads confirm all four exchange clients remain at their original flags/configurations. The corrected packet permits exactly one fresh attempt under the same limits above; it does not revive the failed attempt or extend its window. The ciphertext-corrected startup subsequently passed actual private Vault runtime and authenticated policy readiness, then stopped when its first owned enabled-flag write changed PF modificationDate. No browser worker, grant, document or Microsoft request ran. Both document clients are now independently confirmed disabled, other clients unchanged, private policies/lease stopped and the dead owner lock released. The complete 355-file second packet and independent cleanup/reconciliation evidence are preserved in startup-modification-date-spent; this attempt also remains spent.

For the four fixed PRIVATE_KEY_JWT exchange clients only, preflight/enable/monitor/restore fingerprints now omit PF-managed modificationDate. Every other field, including creationDate, client authentication, public keys, scopes, policies and flags, remains exact. Callback fingerprints still retain modificationDate. Two new regressions reproduce automatic timestamp changes during both enable and restoration, and reject foreign policy or creation-date changes. Independent reconciliation reconstructed the original exact baseline hash before performing the one authorized cleanup write. This new packet requests one fresh attempt with unchanged ceilings; neither earlier allowance is revived. No timestamp-corrected deployment has run.

Approval phrase: **Approve timestamp-corrected document chat deployment**.
