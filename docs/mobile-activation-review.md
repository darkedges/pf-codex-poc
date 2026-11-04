# Persistent mobile demo activation review

Prepared 2026-11-04. **Not approved or deployed.** The approved credential enrollment and disabled PF staging are complete; their verification allowances remain spent.

This review authorizes the following deployment as one package, followed by installation and owner-operated verification. It replaces repeated timed demo windows with persistent, revocable mobile access.

## Exact changes

- Create only the dedicated `mobile-copilot-login` client, `mobileLoginJWT` token manager, `mobileLoginOIDC` policy and mapping from the frozen login plan. Require PAR, PKCE S256 and signed JWT client authentication. Allow authorization code and rotating refresh tokens with a 30-day absolute/idle ceiling and zero reuse grace. Bypass the identity-only PF approval page; application resource consent remains independently enforced, with the default-on checkbox and manual opt-out.
- Enable that client and the four already staged `mobile-chat-gateway-1/2` and `mobile-document-gateway-1/2` clients. Existing shared Copilot OAuth and browser clients remain unchanged. These five mobile clients remain enabled for ongoing use; stopping the application does not disable them.
- Add one dedicated 30-day localhost TLS certificate/private key to the existing mobile Vault record using CAS version 1 → 2. Preserve all five client keys and the Direct Line secret unchanged. No new Vault policy, Graph permission or tenant-wide grant. The service reads credentials using its existing scoped certificate roles; unattended startup does not use operator/root credentials or unseal Vault.
- Run the service only on loopback HTTPS port 9468. Replace the existing agent hostname's route with the frozen mobile route set, publish Android App Links, and add only `/as/par.oauth2` to the existing PF A route whitelist. Keep PF B, relay, DNS and certificate settings unchanged. Restart only the verified owned Cloudflare connector; this can briefly interrupt PF routes. Retain TLS verification and suppress request URL/header logging.
- Create the mobile device/session, audit and durable usage stores in the protected local directory. Bind the existing human, registered agent, organisation, approved site and purpose-specific audiences. Restart invalidates foreground sessions, while retaining absolute enrollment expiry, revocation and spent history. Delete mobile audit records after one day, with a 2 MiB journal ceiling; this is logical retention, not a forensic erasure guarantee.
- Install the signed v5 candidate in place on the owner's connected Pixel 6 Pro using ADB, verify package/signing identity and Android App Links, then let the owner perform sign-in and fingerprint interaction. No automation enters passwords or approves biometrics. After successful owner verification, record acceptance and install `FederatedCopilotMobile` as a limited task under the existing Windows account, at logon, with no stored account password.

## Standing demo allowance

Permit manually initiated use without a deployment expiry window: up to **100 attempted questions and 20 conversations** in this deployment's durable ledger. Each entry/unlock starts a fresh chat; multiple questions are allowed while foreground. Preserve spent counters across restarts and failures; no automatic reset or load testing.

Additional aggregate ceilings are 400 PF token requests, 100 Graph tokens, 6,400 Graph metadata requests, 1,600 constrained downloads, 40 Direct Line tokens, 120 activity posts, 14,000 activity polls and 20 secure token posts. Failed/reserved operations count. These are operational limits, **not a dollar meter or guaranteed $50 spending cap**. The existing $50 budget remains; this approves no new subscription, billing policy or permission. Pause use if the existing billing budget is reached; a larger allowance requires review.

Only supported UTF-8 `.txt` documents inside `FederatedCopilotPoC` are eligible. Each read remains bounded to 16 documents, 128 nodes, 64 requests and 262,144 bytes. Other formats are reported unsupported. Prompts and documents cannot select another site or grant authority. Graph remains app-only Sites.Selected, with separate human/agent authorization.

## Verification and limits

896 production, 372 simulation and 41 mobile tests pass; the candidate build passed 12 native tests. APK SHA256: `6aabdbab5b7307bd51c7d500a9c3af16bcf1b5eab5345a581fefcc12af7e6ae0`. Signing certificate SHA256: `4d8b412744cc5a821ca093c265a6b4fa28317a520ec5f9445001839d9a14c68a`.

Phone verification covers fresh sign-in, one document question, background/biometric unlock into a new chat, a second question and revocation. These consume the standing allowance, rather than an additional allowance. Use a fresh OAuth card and its exact secure URL for every new conversation; never reconstruct or reuse that URL. No automatic retry of an uncertain credential or tool operation.

**UNVERIFIED until live acceptance:** the new private-key-authenticated provider client's compatibility with the published Copilot Generic OAuth configuration, mobile PF issuer/refresh behavior, App Links, full protected runtime and mobile document chat. Hardware key attestation and Microsoft tool-input trace protection remain UNVERIFIED under the explicit PoC exception. Tokens remain server-side; the phone holds its biometric-bound device key, not provider credentials.

Availability still depends on the Windows host, Docker, reachable/unsealed Vault, Cloudflare, Microsoft services/trial and valid certificates. Credential expiry needs reviewed rotation; no implicit extension of the 30-day enrollment. Setup stops on uncertain writes and retains reconciliation evidence. Partial configuration can remain after failure; inspect and reconcile owned objects before repeating. The ingress helper can restore the previous route, but this is not a promise of transactional rollback for all IAM changes.

AGENTS.md requires explicit approval: **“No public ports, production IAM policy changes or tenant-wide admin grants without explicit approval.”** The completed staging approval expressly excluded activation, public routing and installation. Approval of this review authorizes these named changes and the standing manual demo allowance; it does not authorize broader resources or permissions.
