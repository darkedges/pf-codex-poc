# Local tool service controller

Current caller/lease checkpoint: [enrolled relay activation](copilot-relay-activation-runtime.md) adds the selected relay fingerprint beside the monitor only when its explicit receipt matches the current Vault version, fingerprint and complete runtime configuration hash. The private service is ready. Its replacement lease expires `2026-10-31T12:48:08.236Z` (**23:48:08.236 AEDT on 31 October**), with policy shutdown about 30 seconds earlier. Older monitor-only and lease timestamps below are historical; no automatic renewal/restart or host port is enabled.

Latest restart (31 October 2026): the original bounded lease shut down cleanly at 14:52 AEDT. During [relay custody/network verification](copilot-relay-vault-network.md), the controller was explicitly restarted under the saved Windows-owner/one-day settings and is ready. Its new lease expires at `2026-10-31T12:30:36.490Z` (**23:30:36.490 AEDT**), with policy shutdown about 30 seconds earlier. Existing caller trust remains unchanged; no automatic renewal/restart is enabled. Older activation timestamps below are historical.

Implemented and locally verified 2026-10-31 Australia/Sydney. After the user selected their Windows account and one-day tool-journal retention, the controller was configured and started in a hidden background process. Independent enrolled mTLS readiness is **true**, PF A remains enabled and PF B disabled, and no tool host port is published. This is a running local PoC, not production deployment approval or a Windows service installation.

## Commands

`npm run tool:service` prints the available actions without starting anything.

| Action | Behavior |
|---|---|
| `--configure --retention-days 1` or `7` | Explicitly selects the current Windows SID as service/audit owner and the service journal maintenance threshold; saves restricted operations settings without starting services |
| `--serve` | Requires saved owner/retention settings, starts the foreground controller, verifies enrolled readiness and monitors its owned policy/tool/backend |
| `--status` | Returns a fixed-schema cached controller state and observation age; old/missing state is unknown, not proof of readiness or authorization |
| `--stop` | Sends an instance-bound stop request to the live controller and waits for owned cleanup; it never kills an arbitrary PID |
| `--recover` | Refuses live/uncertain recorded controller or policy processes and foreign resources/locks/leases; removes only the recorded dead instance's owned resources and retires its tracked lease, preserving audit and selected credentials |

The user selected one day: `npm run tool:service -- --configure --retention-days 1` saved the current Windows SID, followed by a hidden background `--serve` launch. Verification itself saved no operations choice; the subsequent explicit user answer authorized this configuration. Use `--status` to observe the current state and `--stop` before maintenance. A future foreground restart is `npm run tool:service -- --serve`.

The controller is deliberately foreground and has no privileged automatic renewal, automatic Docker restart, scheduled task or Windows autostart. Stop/restart explicitly to obtain a fresh authority lease. The policy controller stops before its eight-hour signing lease expires; the tool controller then stops dependents and awaits the same lease-retirement result. Do not restore old/revoked credentials or remove a lock to bypass recovery checks.

## Fixed service boundary

The private network is `federated-copilot-local-private`, with explicit subnet `10.236.250.32/28`. The tool and trusted backend names are fixed and labeled with a newly generated controller instance. The tool attaches only to the internal network; the backend also uses the existing Docker bridge to reach fixed host PF/PDP TLS endpoints. No host ports are published. The trusted bridge remains the previously documented local TLS terminator/application route allowlist, not a production egress firewall.

The controller checks current Windows ownership, exact operations fields, immutable image ID, enrolled KV version and every selected snapshot value. It validates separate backend/monitor certificate keys, CA/name/pin agreement and readiness. The tool receives only its six credential files, public runtime config and writable service audit directory. Vault operator access stays in the host controller; no CA maintenance key or Vault/operator/authority/monitoring credential enters the tool container.

Resource names and label ownership are checked before any stop/removal. Container mutations use the verified immutable container ID to avoid name reuse. Docker auto-removal between lookup and inspection is accepted only after independent absence confirmation. Foreign resources or unavailable state fail closed and retain locks. Recovery refuses a recorded PID that is still present, even if PID reuse is suspected; it does not guess ownership or terminate that process.

## Health and shutdown

The controller checks authenticated readiness every 30 seconds without overlapping probes. A running but unavailable dependency makes state `unready`; protected operations still enforce their own online authorization. An exited owned policy process or missing/stopped tool/backend stops the service, retires its lease and removes owned resources. Audit integrity/maintenance faults also stop it. There is no restart loop or fail-open mode.

Shutdown drains the tool, stops the backend, removes the internal network, awaits policy shutdown/lease revocation, removes temporary role credential copies, and then releases ownership locks. Concurrent stop requests share one completion promise, retain the first reason and all observe any cleanup failure. An uncertain step produces `recovery-required` with a fixed failure category. Selected Vault credentials, durable registry and restricted audit evidence are preserved.

## Audit ownership and maintenance

The persistent service journal lives under `.local/tool-vault/service/audit`, restricted to the selected current Windows account and SYSTEM. The runtime retains at most two 1 MiB files. This capacity limit can remove records earlier than the selected day threshold; it does not promise a minimum retention period.

The current selected threshold is **one day**. Eligible whole journal files are removed only while the service is stopped, at startup/shutdown maintenance. If a journal reaches its threshold during operation, the controller stops before performing maintenance. A file containing any expired record is eligible as a whole, so newer records in that file may also be removed. Partial/malformed records, symlinks, hard links and unexpected files block maintenance. No active journal is rewritten or truncated to force recovery.

Maintenance runs when the controller or an explicit operational action runs. No offline Windows retention job is installed; files can remain until the next maintenance action while the controller/host is stopped. These settings cover only this service's bounded tool journals, not consent/PDP database audit, old verification receipts, backups or a production retention requirement. Those records remain separately restricted and need their own policy.

Verification uses explicit in-memory `retentionDays: null`, creates no saved operations choice, and never prunes actual service journals. Unit tests use only disposable synthetic journals. Automatic approval review rejected an earlier diagnostic command that could prune real journals before the retention selection; the safe diagnostic/recovery path preserved them. The user's subsequent explicit one-day selection now authorizes maintenance for this service's journals.

## Evidence

- **11 live lifecycle checks:** enrolled readiness, second-controller exclusion, missing sender/invalid token denial, shared concurrent stop, complete lease/resource cleanup, durable registry preservation on restart, actual owned-policy exit, actual backend loss, no automatic restart and unchanged PF lifecycle.
- **7 live command/crash checks:** current status, refusing recovery while controller is live, instance-bound graceful stop, token/lock removal, a real cold controller-process crash, recovery of its recorded resources/lease, and byte-for-byte journal preservation.
- **14 persistent policy integration checks** remain the separate restart/replay/signing-lease regression.
- **274 baseline** and **283 production** tests pass. Negative coverage includes unsafe operations settings, foreign resource/name reuse, Docker auto-removal races, concurrent/failed cleanup and stopped-only audit maintenance.

The command/crash run completed at 2026-10-30 19:49:43 UTC / 2026-10-31 06:49:43 AEDT. Verification leaves services stopped, all selected credentials intact and no new consent or PF client changes. The earlier enrolled consent canary's 47 live checks remain separate evidence of both execution modes, expiry and revocation; this controller test does not issue tokens or recreate grants.

Activation check: the owner matches the current Windows account, retention is one day, the tool is running with no host ports, and independent mTLS readiness passes. The current authority lease ends **2026-10-31 03:52:48 UTC / 14:52:48 AEDT**; the policy stops 30 seconds beforehand and the controller then stops dependents. This is not automatic lease renewal or Windows autostart. Copilot token-post/calling-workload verification, Graph/SharePoint, production PKI/networking and production monitoring/retention remain independent gates.
