# Investigation Pivots

Read this reference when selecting an assisted-investigation profile or scoping
the next forensic checks. Profiles prioritize review; they do not suppress the
full timeline or prove the selected threat type.

## Profile Selection

| Profile | Use for | Minimum corroboration to seek |
|---|---|---|
| `comprehensive` | Unknown or mixed Linux compromise | Authentication, execution, persistence, accounts, network, and filesystem coverage. |
| `ransomware_extortion` | Staging, transfer, destructive impact, or recovery inhibition | Initial access, archive/file staging, destination or transfer evidence, and file/command impact. |
| `public_facing_exploitation` | Suspected service or web exploitation | Request/service evidence, file creation, execution by the service identity, and process/network follow-on. |
| `credential_compromise` | Valid-account, SSH-key, password, token, sudo, or account-control concerns | Authentication source, identity change records, privilege activity, and identity-provider or network telemetry. |
| `persistence_backdoor` | Cron, systemd, PAM, loader, SSH-key, profile, rc, or account persistence | Configuration state, target file metadata/hash, activation evidence, and process/network behavior. |
| `cryptomining_resource_hijacking` | Miner processes, pool traffic, cloud/container abuse, or resource spikes | Process/command evidence, network destination, persistence, and resource/cloud telemetry. |
| `apt_like_intrusion` | Low-noise valid accounts, layered persistence, tunneling, selective collection | Multiple independent evidence classes and explicit contradictory evidence; report profile similarity only. |

## Evidence Pivots

### Authentication And Identity

- Correlate auth logs, `last`/`lastb` exports, audit records, SSH keys, account
  files, group changes, sudo records, and identity-provider telemetry.
- For repeated failures followed by success, verify source, target user, protocol,
  bounded failure window, success raw line, and subsequent activity.
- Treat backup account-file differences as state transitions. Attribute the actor
  or exact change time only when another source supports it.

### Execution And Tooling

- Correlate shell history, audit `EXECVE`, process snapshots, package logs,
  filesystem metadata, service logs, and created binaries/scripts.
- Treat `rclone`, `anydesk`, tunneling tools, miners, cloud CLIs, archive tools,
  and native utilities as dual-use names. Require command context, process/file
  evidence, configuration, destination, or surrounding behavior.
- Exclude defensive search commands and documentation/package strings from claims
  of execution unless another source records execution.

### Persistence And Privilege

- Review cron, systemd, PAM, dynamic-loader configuration, SSH authorized keys,
  shell profiles, rc/init scripts, sudoers, privileged groups, file capabilities,
  SUID/SGID metadata, and kernel-module evidence.
- Hash and stat every referenced target. Compare against package ownership,
  configuration management, backups, and known-good baselines.
- Distinguish a risky configuration from evidence that it was used.

### Network And Lateral Movement

- Correlate socket snapshots with process identity, shell/audit commands, SSH host
  history, firewall/flow logs, DNS, proxy data, and destination ownership.
- A collection-time connection is state evidence. Establish start time and intent
  from another source where possible.
- Require directionality. A remote login to host A does not show that host A later
  accessed host B.

### Collection, Exfiltration, And Impact

- Correlate archive/database-dump commands with created files, file volume,
  transfer commands, network/cloud audit data, and destination identifiers.
- Separate staging from exfiltration. A local archive alone does not prove data left
  the host.
- Correlate destructive commands with filesystem changes, service/VM impact,
  recovery inhibition, ransom material, and external operational telemetry.
- Do not assign a malware or ransomware family from command/tool overlap alone.

## External Evidence Requests

When endpoint evidence is insufficient, request the smallest relevant set:

- Identity-provider, VPN, bastion, MFA, and key-management audit logs.
- Firewall, NetFlow, DNS, proxy, load-balancer, and cloud network telemetry.
- EDR process trees, file events, detections, and isolation/remediation history.
- Application, database, container, Kubernetes, hypervisor, and cloud control-plane
  logs relevant to the host role.
- Known-good configuration, package manifests, deployment records, and backups.
- Memory, disk image, suspicious binaries/scripts, and volatile captures when UAC
  artifacts cannot answer execution, lineage, or malware questions.
