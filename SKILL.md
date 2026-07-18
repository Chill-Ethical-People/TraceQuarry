---
name: uac-linux-forensic-timeline-analysis
description: Parse Unix-like Artifacts Collector (UAC) output into Linux forensic timelines, extract common attacker TTPs, and produce incident-window mini timelines for DFIR analysis.
domain: cybersecurity
subdomain: digital-forensics-incident-response
tags:
  - UAC
  - Linux
  - DFIR
  - timeline
  - TTP
  - incident-response
  - lateral-movement
  - credential-compromise
  - persistence
  - account-lifecycle
version: 0.2.0
---

# UAC Linux Forensic Timeline Analysis

## When To Use

Use this skill when analyzing a UAC archive or extracted UAC directory from a suspected Linux, Unix, cloud, container, or ESXi incident.

Use it to answer:

- Who logged in, from where, and when?
- What commands were run?
- What files changed around the suspected incident period?
- Was persistence created through cron, systemd, SSH keys, or shell profiles?
- Were credentials, cloud metadata, kube configs, or SSH keys accessed?
- Was there evidence of tunneling, exfiltration tooling, mining, ransomware, or destructive actions?
- **Was there lateral movement from this machine to other hosts?**
- **Were user accounts created, deleted, modified, locked, or unlocked?**
- **Were passwords changed, and which accounts were affected?**
- **Were users added to privileged groups (wheel, sudo, docker)?**
- **What was the brute-force campaign scope — source IPs, targeted users, timeframes?**
- **Were plaintext passwords leaked into shell history?**
- **What is the network connection state — listening ports, inbound/outbound connections?**
- **What processes were running at collection time — any suspicious or unexpected?**

Do not treat actor-like findings as attribution. They are tradecraft hints only.

## Required Inputs

- UAC archive or extracted UAC directory
- Incident start and end if known
- Host/timezone context if UAC timestamps are ambiguous

If the incident period is unknown, generate the full timeline first and identify a candidate window from high-severity events.

## Command

```bash
python3 -m uac_parser.cli /path/to/uac-output.tar.gz --out /path/to/out \
  --incident-start 2026-06-16T08:00:00Z \
  --incident-end 2026-06-16T12:00:00Z \
  --timezone UTC
```

Optional:

```bash
--year 2026
--timezone Asia/Hong_Kong
--host compromised-host01
--ioc 198.51.100.50
--ioc-file /path/to/iocs.txt
```

Use `--year` for syslog-style logs that omit the year.
Use `--timezone` for syslog/auth/cron timestamps because those logs are usually local time.
Use `--ioc` (repeatable) or `--ioc-file` to match known indicators against all parsed events.

## Outputs

- `timeline_full.jsonl`: every parsed event
- `timeline_full.csv`: spreadsheet-friendly full timeline
- `timeline_mini.jsonl`: incident-window timeline
- `timeline_mini.csv`: incident-window CSV
- `findings.json`: high-signal detections and storylines
- `summary.md`: analyst summary with lateral movement, account lifecycle, brute-force, network state, and storyline sections
- `source_index.json`: discovered evidence sources
- `ioc_hits.json` / `ioc_hits.csv`: IoC match results
- `parser_errors.log`: parser failures that did not stop analysis

## Analysis Workflow

### Phase 1: Triage

1. Validate source coverage in `source_index.json` — ensure auth logs, shell history, network state, process lists, and account files were all discovered.
2. Review `parser_errors.log` for missed critical sources.
3. Open `summary.md` and triage high-severity findings top-to-bottom.

### Phase 2: Investigate Key Questions

#### Persistence

Review findings for:
- Suspicious cron entries or systemd units
- Unrestricted SSH authorized keys
- LD_PRELOAD or PAM backdoor candidates
- Shell profile modifications
- rc.local / init.d changes

#### Lateral Movement

The summary includes a **Lateral Movement Assessment** section that automatically evaluates:
- Outbound SSH commands in shell history (`ssh user@host`, `scp`, `rsync`)
- Outbound SSH connections in network state (`ss`/`netstat` showing port 22 outbound)
- SSH `known_hosts` entries (indicates prior outbound SSH connections)
- Network connectivity probes (`telnet`, `nc -zv` to remote hosts)

A **negative finding** ("No outbound lateral movement detected") is explicitly reported when no evidence is found — this is as important as a positive finding for scoping the incident.

#### Credential Compromise

The parser detects:
- **Password changes via backup diffing**: compares `/etc/shadow` vs `/etc/shadow-` to identify which accounts had password hashes changed, and converts the shadow epoch-day field to real dates for the timeline
- **Account unlocks**: detects when an account goes from locked (`!!`) to having an active password hash
- **Root password changes**: flagged as high severity in both auth log events and shadow diff events
- **Plaintext passwords in shell history**: single-word entries with high character complexity (upper + lower + digit + special) that do not match any known command, using only synthetic examples in documentation
- **Password hash types**: identifies MD5 ($1$), SHA-256 ($5$), SHA-512 ($6$), yescrypt ($y$) — MD5 hashes are flagged as weak

#### Account Lifecycle

The **Account Lifecycle Changes** section in the summary automatically reports:
- **Accounts created since backup**: detected by diffing `/etc/passwd` vs `/etc/passwd-`
- **Accounts deleted since backup**: users present in backup but missing from current
- **Password changes**: detected via `/etc/shadow` vs `/etc/shadow-` with real timestamps
- **Group membership changes**: detected via `/etc/group` vs `/etc/group-`, especially additions to privileged groups (wheel, sudo, docker, lxd, admin)
- **Auth log account events**: `useradd`, `groupadd`, `userdel`, `usermod`, `passwd` events parsed from secure/auth.log

The backup file diffing technique is critical because account creation events (useradd) may have rotated out of current auth logs, but the backup file comparison always reveals what changed.

#### Brute-Force Analysis

The **Brute-Force Campaigns** section automatically:
- Aggregates failed SSH attempts by source IP
- Reports total attempt count, timeframe, and targeted usernames
- Links to the "Successful SSH login after repeated failures" findings when an attacker succeeded
- Generates a storyline connecting the brute-force campaign to post-access activity

#### Data Exfiltration

Review findings for:
- Exfiltration tool usage (rclone, megacmd, cloud CLIs, scp, rsync)
- Archive creation targeting sensitive directories
- Database dumps (mysqldump, pg_dump, mongodump)
- Outbound connections to unusual destinations

### Phase 3: Validate and Correlate

4. Review `timeline_mini.csv` around the incident window.
5. Validate every high-severity finding against the original raw source line.
6. Pivot from suspicious commands to bodyfile events for created/modified binaries and scripts.
7. Correlate SSH, sudo, shell history, cron, systemd, and file timeline events.
8. Cross-reference network state connections with process list to identify what initiated each connection.
9. Report actor-relevant matches as "tradecraft resembles," not attribution.

## TTP Categories

The parser extracts:

### Authentication & Access
- SSH brute force and successful login after failures
- Brute-force campaign aggregation (per-source-IP summary with targeted users)
- Invalid user SSH attempts
- `last`/`lastb`-style login history exports
- Password change events from auth logs
- Account lock/unlock events

### Execution
- Suspicious shell commands
- Download-execute chains (`curl|bash`, `wget|bash`, `base64 -d|bash`)
- `chmod +x` followed by execution indicators
- Execution or staging under `/tmp`, `/var/tmp`, `/dev/shm`, or `/run`
- Process list analysis — miners, reverse shells, C2 tools, processes from suspicious paths

### Persistence
- Cron persistence (scheduled tasks, crontab entries)
- Systemd persistence or service changes
- Unrestricted SSH authorized keys
- LD_PRELOAD hijacking
- PAM backdoor candidates
- Shell profile modifications
- rc.local and init.d scripts

### Privilege Escalation
- UID 0 non-root accounts
- Privileged group membership, including Docker/LXD risk
- NOPASSWD and dangerous sudoers rules
- SUID/SGID files from bodyfile data
- Dangerous Linux file capabilities
- Privileged group member additions detected via backup diffing

### Credential Access
- SSH key and credential material access
- Cloud metadata access (169.254.169.254)
- Password hash analysis (type identification, weak hash detection)
- **Plaintext passwords leaked into shell history** (critical severity)
- Shadow file timestamp extraction (epoch-day → ISO date)

### Lateral Movement
- **Outbound SSH commands** in shell history
- **Outbound SCP/rsync file transfers** in shell history
- **Outbound SSH connections** in network state (ss/netstat)
- SSH known_hosts entries (evidence of prior outbound SSH)
- **Network connectivity probes** (telnet, nc to remote hosts)
- **Explicit negative finding** when no lateral movement evidence exists

### Account Lifecycle (Backup File Diffing)
- **Accounts created** since last backup (passwd vs passwd-)
- **Accounts deleted** since last backup
- **Account modifications** (shell, UID, home directory changes)
- **Password changes** with real dates (shadow vs shadow-)
- **Account unlocks** (locked `!!` → active hash)
- **Account locks** (active hash → locked)
- **Group membership additions/removals** (group vs group-)
- **Privileged group additions** (wheel, sudo, docker, lxd, admin)
- Auth log: useradd, groupadd, userdel, usermod events

### Network State
- **Listening ports** with process attribution
- **Inbound connections** (who is connected to this machine)
- **Outbound connections** (what this machine is connecting to)
- **Suspicious listening ports** (4444, 5555, 1337, 31337, etc.)
- **Outbound SSH connections** (lateral movement indicator)
- **Outbound connections to uncommon ports**

### Defense Evasion
- Log and shell history tampering
- Risky SSH daemon settings (PasswordAuthentication yes, PermitRootLogin yes)

### Collection & Exfiltration
- Archive creation targeting sensitive directories
- Database dumps
- Exfiltration tools (rclone, megacmd, cloud CLIs, scp, rsync)
- Tunneling and proxy tools (chisel, frp, ngrok, socat)

### Impact
- Destructive/ransomware-like commands
- ESXi/VMware administrative commands
- Mining tools (xmrig, kinsing, minerd)

### Audit
- Grouped auditd events and configured audit keys
- Credential access, exec from tmp, SSH key tampering, kernel module load, log tampering audit keys
- World-writable sensitive files from bodyfile mode data
- Correlated install-time hints for state artifacts using bodyfile and audit path matches

## Storylines

The parser automatically constructs narrative storylines:

- **Brute-force → successful login**: connects a campaign of failed SSH attempts to a subsequent successful login, including post-access activity (sudo, shell commands, account changes)
- **Credential modification activity**: clusters password changes and account unlocks across the timeline with affected users
- **Initial access → execution/persistence**: login or web request followed by download-execute chains, cron modifications, or chmod+execute patterns

## DFIR Investigation Techniques

### Backup File Diffing (Most Valuable Technique)

Linux maintains backup copies of critical account files:
- `/etc/passwd-` → previous state of `/etc/passwd`
- `/etc/shadow-` → previous state of `/etc/shadow`
- `/etc/group-` → previous state of `/etc/group`

These are updated by `useradd`, `usermod`, `passwd`, `groupmod`, etc. before modifying the live file. Diffing current vs backup reveals:
- New accounts created (present in current, absent in backup)
- Deleted accounts (present in backup, absent in current)
- Password hash changes (different hashes between files)
- Account unlocks (backup shows `!!`, current shows a real hash)
- Group membership additions (backup shows empty members, current shows new members)

This technique is critical because the actual `useradd` commands may have rotated out of auth logs, but the file-level evidence persists.

### Shadow Epoch-Day Conversion

The `/etc/shadow` file stores password last-changed dates as days since January 1, 1970. Converting these to real dates places password changes on the timeline:
- `20616` → 2026-06-12 (root password changed by IR team)
- `20558` → 2026-04-15 (printer account unlocked)
- `20516` → 2026-03-04 (nessus_adminsrv account created)

### Shell History Password Leak Detection

Administrators sometimes accidentally type a password at the shell prompt instead of a password prompt. These appear as single-word, high-complexity entries in `.bash_history` that don't match any known command. The parser flags these as critical severity because they expose credentials in a file that may be world-readable.

### Network State Correlation

The `ss -tanp` and `netstat -anp` outputs captured at collection time provide:
- **Listening ports**: what services are exposed (backdoor detection)
- **Established inbound connections**: who was connected at collection time
- **Established outbound connections**: what the machine was talking to (C2, lateral movement)
- **Process attribution**: which process owns each connection

Cross-referencing network state with the process list identifies what initiated each connection.

### Brute-Force Campaign Reconstruction

Rather than reviewing thousands of individual failed login events, the parser aggregates them by source IP to produce campaign-level findings:
- Total attempt count
- Timeframe (first and last attempt)
- Targeted usernames (useful for understanding attacker wordlists or targeting)
- Whether any attempts succeeded (linked to "successful login after failures" findings)

### Negative Findings

Explicitly reporting the absence of evidence is as important as reporting its presence:
- "No outbound lateral movement detected" scopes the incident — the machine was a target, not a pivot point
- "No known_hosts file exists" means no outbound SSH connections were recorded (or the directory was cleaned)
- "No ADD_USER/DEL_USER events in audit logs" means account creation occurred before the audit log rotation window

The parser generates explicit negative findings for lateral movement to prevent analysts from having to prove a negative manually.

## Evidence Handling Notes

- Preserve the original UAC archive and hash it before parsing.
- Do not modify the extracted evidence directory.
- Record timezone assumptions in the final report.
- Treat shell history without timestamps as low-confidence ordering evidence.
- Use raw source lines for final conclusions.
- Treat untimestamped state artifacts as current-state evidence, not as installation-time proof unless correlated with bodyfile or auditd timestamps.
- Treat `correlated_*` timestamps as inferred timeline placement. Validate against the linked `related_event_ids` and raw bodyfile/audit rows.
- Shadow hash values are redacted in parser output (`[shadow hash redacted]`) to avoid exposing crackable hashes in reports.
- Account diff events have `high` confidence because file-level diffing is deterministic.
- Brute-force campaign findings have `high` confidence when based on auth log counts.
- Plaintext password detections use heuristics (complexity scoring) — always validate against the original history file.

## Worked Example: Synthetic SSH Compromise

This example uses reserved documentation addresses and synthetic evidence only.

### Scenario

A generated UAC fixture records repeated SSH failures from `198.51.100.50`, a
successful root login from the same source, archive staging, `rclone` execution,
destructive commands, and history or log tampering.

### Expected Parser Leads

1. **Brute-Force Campaign**: repeated SSH failures grouped by source, user, and bounded time window
2. **Successful Login After Failures**: the successful root event linked to preceding failed attempts
3. **Collection and Exfiltration**: archive creation and `rclone` activity retained with raw event references
4. **Impact**: destructive commands treated as behavioral evidence, not automatic malware-family identification
5. **Evidence Cleanup**: history and log tampering promoted for analyst validation
6. **Storyline**: authentication pressure, account access, staging, transfer, impact, and cleanup ordered in UTC

### How the Parser Automated This

| Manual step (hours) | Automated equivalent |
|---|---|
| Grep 97K secure log lines, count failures by IP | Brute-Force Campaign finding with counts and timeframes |
| Diff shadow vs shadow- manually | Account diff events with real timestamps |
| Search bash_history for `useradd`/`passwd` commands | Shell history + TTP enrichment detections |
| Check for outbound SSH in history, known_hosts, ss output | Lateral Movement Assessment (positive or negative) |
| Read ss -tanp and identify connections | Network State section with process attribution |
| Convert shadow epoch days to dates manually | Automatic timestamp conversion in timeline |
| Identify a synthetic password-like token as a possible leak | Plaintext password detection heuristic |
