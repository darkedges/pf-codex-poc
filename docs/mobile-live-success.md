# Android document chat: owner-verified PoC

On 4 November 2026, the owner confirmed that the v9 Ionic React Android app returned the expected document-grounded answer after a fresh PingFederate sign-in. The question was "What is the approved research color and document reference?" The expected answer is teal and FEDERATED-COPILOT-POC-001 from federated-copilot-poc.txt.

The owner previously verified fingerprint enrollment and subsequent biometric unlock. The successful answer exercises the live mobile flow through independent PF A/B document and chat exchanges, Vault-backed credentials, the resource-scoped Entra application, the approved SharePoint site and Copilot Studio. This is interactive PoC evidence, not production approval or acceptance of autonomous Microsoft access.

## Corrections leading to this result

- Use the correct native browser discovery and browser intent selection.
- Anchor phone proofs to authenticated server time without relaxing JWT clock tolerance.
- Register replay protection for only the explicitly approved 180-second mobile assertion profile, retaining the generic 65-second bound.
- Correct all four dedicated mobile managers to their existing strict verifier audiences; preserve the original human, registered acting agent and resource/grant bindings.
- Permit only one bounded continuation watermark on GET activities at the existing Direct Line endpoint.
- Record credential-free Copilot operation/error categories to distinguish downstream failures without capturing credentials, messages or signed URLs.

## Remaining defect

An earlier provider-token refresh did not complete, leaving its Vault record in the deliberately spent `refreshing` state with both credential fields cleared. Fingerprint unlock cannot recover that state. Fresh PF sign-in enrolled new provider credentials and restored document chat. The original refresh failure's precise cause remains UNVERIFIED. Do not revive a historical token, reset the record or automatically replay a refresh request.

Reliable refresh, fresh-chat/lifecycle and revoke/resume acceptance remain follow-up work. Microsoft execution-trace protection for provider tokens remains UNVERIFIED under the explicit synthetic PoC exception. The standing approved resource boundaries, revocation checks and usage ceilings remain in force. Entra workload identity federation is a separate planned migration; the broker currently uses its Vault-held certificate.
