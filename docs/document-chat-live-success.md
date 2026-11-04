# Live document-backed Copilot answer — verified PoC

On **3 November 2026**, the user completed the approved browser flow at https://agent.copilot.darkedges.com and received the expected answer: the research colour is **teal**, the reference is **FEDERATED-COPILOT-POC-001**, and the cited source is **federated-copilot-poc.txt**. Independent verification completed at **09:44:37 AEDT** (22:44:37 UTC on2 November).

Status: **VERIFIED_POC_DOCUMENT_COPILOT_ANSWER**. This establishes one interactive question using the single approved synthetic sample. It is not production acceptance, unrestricted SharePoint search, autonomous document access or ongoing multi-turn chat.

## Observed flow

The browser obtained distinct fresh OIDC login proofs for the same PF-authenticated human and separate chat/document consents. The registered agent authenticated independently. Actual Vault, PF A, PF B and policy services authorized the document chain, preserving original human, actor, organisation, execution mode, distinct grant and audience bindings. The certificate-authenticated Entra broker used its existing **Sites.Selected** app permission and read-only site grant to fetch only the pinned **201-byte** sample. No external user was provisioned into Entra, and no PF token was treated as a Graph delegated-user token.

The server verified the sample hash and independently confirmed document-grant revocation before releasing text to the chat executor. A separate `copilot.invoke` chain established a new Direct Line conversation, posted the configured provider's user token to that conversation's fresh OAuth-card secure URL, then sent the question and approved sample as untrusted data. Chat-grant revocation was confirmed before the escaped model answer was released. No native SharePoint connector or new agent publication was involved; the server supplied the bounded document context.

## Independently checked evidence

- Session journal is closed, both distinct consent records are recovered and no cleanup is pending.
- The authoritative policy database shows both exact owned grants revoked, bound to different login fingerprints, the expected human/agent/organisation, their separate scopes and the approved resource.
- Actual policy permit records for both downstream audiences preserve human and agent identity, agent issuer, interactive mode, capability, resource and PF B issuer. This check used existing records, not another token or document request.
- Exactly one document-read reservation is recovered.
- All four PF exchange-client configurations match their pre-deployment flags and policy fingerprints. Both document clients are disabled; pre-existing chat clients retain their original state.
- Both owned private policy listeners and the tracked legacy signing lease are retired. The remaining web worker is answer-only until the fixed **10:23:37 AEDT** window ends; it cannot start another question or read.

| Recorded operation | Count |
|---|---:|
| Chat OIDC / document OIDC / provider login | 1 each |
| PF token POSTs, including login and both exchange chains | 7 |
| Entra broker token request | 1 |
| Exact-sample Graph metadata/content GETs | 2 |
| Constrained SharePoint download | 1 |
| Document read | 1 |
| Direct Line token generation / conversation start | 1 each |
| Fresh-card secure token POST | 1 |
| Direct Line activity POSTs: sign-in warmup and question | 2 |
| Direct Line GETs | 7 |
| User question | 1 |

The user supplied the rendered answer in chat. The server journal records successful completion and the independent audit/cleanup checks above; it does not retain the model answer or downloaded document text. The sample's required SHA-256 is `d37938e1dd000ca43886ac0a36806e7218e70b7f92a1cbca68ea5926adeb9a09`.

Local sanitized receipt: `.local/tool-vault/document-chat/success-confirmed.json`. Instance: `8705240f-73bb-4c5a-a2f0-ce577c70cd58`. Approved source/public-config manifest: `79b6c94309ae1fa17cae07c771db38a1ef31b5fe00b33458a3c6d83e48833164`. Earlier failed/expired windows remain preserved and spent. This successful allowance is also spent; no automatic retry or renewal.

## Remaining limits

The accepted Microsoft credential/trace PoC exception remains; execution-trace protection and production credential isolation are not established. Only synthetic data was approved. The shared Windows-account custody, forced-termination recovery, independent watchdog, comprehensive one-day audit retention, production monitoring/rotation and sustained hosting still require operational work. Autonomous Copilot provider SSO, broader document authorization, multi-turn chat and live Microsoft expiry/revocation behavior remain separately unverified. Local regression remains **782 production** and **372 simulation** tests passing; this verification changed no production source or test behavior.
