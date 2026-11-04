# Mobile PF audience correction review

Prepared 4 November 2026. **Not applied.** The latest owner question reached PF A after successful mobile assertion authorization, but the issued token's configured audience does not match the mobile verifier. Counters show three spent questions, one PF token request and no Graph or Copilot request. PF audit reports success for the mobile request. This is a copied token-manager template defect, not evidence that the verifier should accept the older document audiences.

## Exact correction

Change only `Audience Claim Value` in these four dedicated mobile JWT managers:

| Node | Manager | Current value | Correct value already required by mobile trust |
|---|---|---|---|
| PF A | mobileChatAJWT | api://gateway-2/documents | api://gateway-2/mobile-chat |
| PF B | mobileChatBJWT | api://federated-copilot/documents | api://copilot-broker |
| PF A | mobileDocumentAJWT | api://gateway-2/documents | api://gateway-2/mobile-document |
| PF B | mobileDocumentBJWT | api://federated-copilot/documents | api://federated-copilot/mobile-documents |

Temporarily disable only `mobile-chat-gateway-1/2` and `mobile-document-gateway-1/2`, verify all four audience updates, then restore their original enabled flags. Preserve every other manager/client setting, key, issuer, lifetime, scope, policy, mapping and resource. Ignore only server-managed manager modification time/sequence during comparison. Stop on unknown drift or an uncertain write; retain the journal rather than repeating the request. A partially failed repair can leave these clients disabled until reconciled.

Also apply the prepared one-line plan-builder correction in `scripts/pf/mobile-profile.mjs`, so future mobile staging explicitly sets the same audience as its verifier. Preserve its original bytes and update only that source pin in the existing approved runtime manifest, with amendment history retained. Restart the owned mobile service as necessary. Existing enrollment, consent, revoked/spent history and aggregate usage limits remain; a restart invalidates foreground sessions and requires another fingerprint unlock.

## Verification and scope

Four isolated repair tests pass: exact field-only changes, wrong identity/audience/duplicate-field denial, disable-before-update/restore-after-readback, and uncertain-write refusal. The prepared builder reproduces zero of four audience matches before the correction and all four afterward with synthetic public material. Earlier full runtime regression remains 902 production and 374 simulation tests passing; the new repair helper is separately tested.

The plan contains exact read-only snapshots and expected resulting objects. Application requires this amendment's exact source/plan approval and the original standing activation approval. No new signing key, Graph permission, external identity binding, public route, billing change, document read, token issuance or automatic question retry is included. The three spent questions stay spent. After verified repair, the owner can unlock v9 and manually ask the next question under the existing allowance. No APK update is needed.

AGENTS.md requires **“No public ports, production IAM policy changes or tenant-wide admin grants without explicit approval.”** Correcting these persistent PF issuance audiences requires this specific approval. Application token validators and their expected audiences are not widened.
