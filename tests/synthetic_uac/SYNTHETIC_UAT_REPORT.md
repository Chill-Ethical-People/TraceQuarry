# TraceQuarry Synthetic UAC UAT Report

## Purpose and safety

This UAT evaluates TraceQuarry against three deterministic, synthetic Linux UAC-style collections representing ransomware/extortion activity, public-facing software exploitation, and APT-like tradecraft. The fixtures contain text evidence only. They use reserved documentation IP ranges and `.invalid` domains and contain no executable payloads.

The collections are test evidence, not threat-actor attribution. An APT-like or ransomware-like result describes observed tradecraft and must not be treated as a malware-family or actor identification without independent corroboration.

## Test results

| Scenario | Host | Incident window (UTC) | Full events | Mini events | Findings | Storylines | IoC match occurrences | Parser errors |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ransomware/extortion | `finance-db01` | 2026-07-10 01:00:00 to 02:30:00 | 64 | 49 | 11 | 2 | 37 | 0 |
| Software exploitation | `web-app01` | 2026-07-11 08:00:00 to 09:00:00 | 40 | 25 | 5 | 3 | 22 | 0 |
| APT-like intrusion | `research-jump01` | 2026-07-12 03:00:00 to 05:00:00 | 59 | 34 | 21 | 1 | 10 | 0 |

Validation passed for all 163 full-timeline events:

- Event IDs are unique within each collection.
- Every finding and storyline event reference resolves to an emitted event.
- All `parser_errors.log` files are empty.
- All 17 automated tests pass.
- Archive provenance, SHA-256 hashes, source coverage, parser status, settings, and output hashes are retained in each `run_manifest.json`.

`IoC match occurrences` counts matched events/fields reported by the IoC matcher. It is not a count of unique indicators, unique systems, or confirmed compromises.

## Ransomware/extortion scenario

### Reconstructed activity

1. From 01:00 through 01:23 UTC, `198.51.100.50` produces 24 failed SSH authentications.
2. At 01:25 UTC, the same source successfully authenticates as `root`.
3. The session performs a download-and-execute sequence, stages data, and invokes `rclone`.
4. Commands consistent with destructive impact and recovery inhibition follow.
5. Shell history and security logs are cleared or removed.

### TraceQuarry findings

TraceQuarry promoted the important chain: known IoC match, successful SSH login after repeated failures, brute-force campaign, download/execute, exfiltration tool usage, destructive commands, suspicious cron, execution from temporary storage, and history/log tampering. It also produced two useful storylines linking initial access to execution and the failed-to-successful root authentication sequence.

The medium-severity `Ransomware Extortion Like Tradecraft` result is appropriately phrased as behavioral similarity. The literal `lockbit` string is retained in evidence but is not sufficient to claim LockBit malware or operator attribution.

### Assessment

This is the strongest scenario. TraceQuarry recovers the complete intended attack narrative and applies suitable attribution restraint.

## Software exploitation scenario

### Reconstructed activity

1. `203.0.113.88` sends suspicious web requests containing traversal/import behavior and a web-shell-like `shell.php?cmd=id` request.
2. A payload is downloaded to `/tmp/.cache/kworker`, made executable, and run.
3. Reverse-shell behavior targets `203.0.113.88:4444`.
4. A cron entry establishes persistence.

### TraceQuarry findings

TraceQuarry emitted the relevant web, shell, audit, process, network, bodyfile, and cron events. It promoted known IoC matches, reverse-shell/tunnel behavior, execution from `/tmp`, and suspicious cron persistence. Three storylines correlate the web requests with subsequent execution or persistence.

### Assessment

Evidence coverage is good, but analyst-facing promotion is incomplete. The initial web exploitation candidate and staged download/execute chain are visible in the timeline and storylines but do not receive distinct findings. This can make the findings summary look like execution began without an initial-access lead.

Recommended uplift:

- Add a web-exploitation finding that correlates exploit-like requests with a new file, process, or outbound connection in a bounded time window.
- Promote download, permission change, and execution of the same path into a staged-payload finding.
- Include the initiating web event in the reverse-shell storyline and evidence references.

## APT-like scenario

### Reconstructed activity

1. At 03:02 UTC, `192.0.2.77` authenticates using a valid public key.
2. Credential material is accessed, including `/etc/shadow`.
3. Persistence is established through account changes, authorized keys, PAM, systemd, sudoers, and `ld.so.preload` artifacts.
4. `chisel`-like tunneling and `rclone` activity occur.
5. Outbound SSH/SCP provides direct evidence of access from the parsed host to another system.
6. Shell history is cleared.

### TraceQuarry findings

TraceQuarry promoted credential access, privileged account changes, unrestricted SSH keys, PAM and loader persistence, dangerous sudo rules, systemd persistence, exfiltration tooling, outbound SSH/SCP, lateral movement evidence, and log/history tampering. The account parser correctly preserves the full `svc-backup` username.

### Assessment

Artifact breadth is excellent, and the lateral-movement wording is defensible because outbound host-to-host access is present. However, all 21 findings are high severity, which reduces triage value and repeats parts of the same persistence/account narrative.

`chisel` is correctly tagged at event level as tunneling/proxy tooling but is not promoted to a dedicated finding. No actor name is asserted, which is correct. Actor profiles should remain profile-similarity hints and should only be evaluated when the runtime can explain the exact matched tools, techniques, and contradictory evidence.

Recommended uplift:

- Consolidate related account findings into one lifecycle finding with child evidence.
- Consolidate PAM, systemd, sudoers, authorized-key, and loader changes into a persistence cluster while retaining individual evidence references.
- Use severity based on behavioral chain and context, not artifact category alone.
- Add an explicit tunnel-tool finding when execution and network evidence corroborate the same tool.
- Expose actor-profile similarity only as an explainable, non-attributive analytic layer.

## Parser defect fixed during UAT

The first APT-like run parsed `svc-backup` as `s` in user-add/group-add authentication messages. The authentication regex used a lazy single-character capture before an optional delimiter. It now captures the complete username and group token, and `test_auth_user_creation_preserves_full_username` prevents regression.

## Overall capability verdict

TraceQuarry is already effective at normalizing heterogeneous UAC artifacts, preserving provenance, building incident-window timelines, matching supplied IoCs, and detecting common Linux authentication, persistence, credential-access, exfiltration, impact, and lateral-access behavior.

The highest-value next engineering work is finding correlation rather than adding more isolated signatures:

1. Promote web initial access and staged payload chains.
2. Cluster overlapping persistence/account findings to reduce severity flooding.
3. Promote corroborated tunneling tools from event tags to findings.
4. Complete explainable runtime evaluation of malware/tool/actor-profile YAML while preserving non-attribution language.
5. Separate unique IoCs, matched events, and total field-match occurrences in summaries and the GUI.

## Reproduction and evidence paths

Generate or refresh the safe fixtures:

```bash
python3 tools/generate_synthetic_uac.py
```

Run the automated regression suite:

```bash
PYTHONPYCACHEPREFIX=/tmp/tracequarry-pycache python3 -m unittest discover -s tests -q
```

Synthetic archives are under `tests/synthetic_uac/archives/`. Extracted source evidence and ground truth are under `tests/synthetic_uac/generated/`. Complete parser outputs are under `tests/synthetic_uac/analysis/`, with one directory per scenario.
