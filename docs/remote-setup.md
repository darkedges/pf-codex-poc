# Remote Instance Setup and Codex Handoff

## 1. Transfer ZIP from your workstation

Copy the ZIP to the remote machine. Example using SCP (replace the placeholders; do not put credentials in the command):

```bash
scp federated-copilot-codex.zip <ssh-user>@<remote-host>:~/
ssh <ssh-user>@<remote-host>
unzip ~/federated-copilot-codex.zip -d ~/
cd ~/federated-copilot-codex
```

Alternatively upload to a **private** Git repository and `git clone` it on the machine. Do not commit `.local/`, `.env` or real tokens/keys.

## 2. Run a local proof

```bash
node --version    # >=22.16
npm run keys
npm test
npm run dev
```

In another SSH session:

```bash
cd ~/federated-copilot-codex
npm run smoke
```

Check results: interactive and autonomous permit, revoked and unapproved resource deny. All service ports bind `127.0.0.1` in the Node-based demo. For Docker see Compose alternative in `README.md`. **Never expose the demo externally**.

## 3. Give Codex the repository

Open the folder as the workspace in your installed Codex terminal/desktop/remote workflow. `AGENTS.md` is the project instruction file. Example task:

```text
Read AGENTS.md and docs/implementation-plan.md. Start with phase 1:
extract typed interfaces for PingFederate A/B exchanges and token verification,
keep mock adapters intact, create a production adapter using a mature JOSE library,
add tests for audience/issuer/algorithm/key rotation and failed token exchange,
and report any tenant-specific prerequisites before activating real mode.
```

Let Codex execute tests after each step. The mock baseline has no dependencies; production integration will typically need approved libraries and secret-manager access.

## 4. Remote production prerequisites

- Private network routes to both PingFederate servers and the Copilot/Graph endpoints.
- TLS trust policy, client certificates or signed JWT client assertions; approved outbound HTTPS.
- PingFederate A and B administrators; client IDs, trusted issuers, JWKS and policy configuration.
- Power Platform environment admin; Copilot Studio agent, secured Direct Line channel, Generic OAuth settings and tool definition.
- Entra tenant admin and SharePoint site owner; dedicated app, `Sites.Selected` consent and site-level `read` grant.
- External organisation/user/agent registration policy and delegation lifecycle API.
- Secret management, logs, identity-aware policy services and deployment platform.

## 5. Verify before going live

See `docs/threat-model.md` and `docs/implementation-plan.md`. Switching `COPILOT_MODE` or `M365_MODE` away from `mock` currently causes fail-closed denial because **real integrations have not been written**. That is intentional.

## Hosting note

This bundle was created locally and was **not installed on your remote host**. Deployment requires your own SSH or private Git access. There is no built-in remote machine connection associated with this project.
