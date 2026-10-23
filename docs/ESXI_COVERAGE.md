# ESXi Investigation Coverage

TraceQuarry is a selective evidence parser and triage aid, not a substitute for
examining the original vm-support collection. Upload each `.tgz` separately or
use multiple CLI inputs for a case. Current and compressed rotations are read
without executing any collected command, script, or binary.

## Parsed Evidence

| Evidence | Preserved detail | Interpretation boundary |
| --- | --- | --- |
| SSH authentication | User, address, port, method, timestamp, raw record | A successful login is an observation; ATT&CK mappings remain candidates without corroboration. |
| SSH session/audit events | Open/close records, user/address when explicitly recorded, VOB ID | VOB mirrors are separate source records, not extra successful authentications. |
| Account lockouts | Account and reported failure count | No source IP is invented; repeated audit/correlator records are not summed into a brute-force total. |
| SFTP | Open/close, read/write requests, browse/remove/rename, all quoted paths, status, server byte accounting | File-open requests are not completed transfers. Bytes read/written are from the server perspective, not proof of external exfiltration. |
| hostd/vpxa | User, session ID, operation ID, task ID, created/completed stage, recorded status, selected datastore actions | Task creation is a request. Errors remain errors, not successful password changes or deletion. |
| Proxy/auth services | Selected envoy-access/rhttpproxy/vmauthd/hostdCgiServer records, HTTP method/URI/status and named API operation where available | HTTP success does not prove API task success. Proxy address positions are not guessed as source identity. |
| ESXi Shell | Recorded command, user/PID and source line; candidate working directory | A logged command proves the command was recorded, not successful execution or effects. |
| SSH key writes | SHA256 fingerprint of valid SSH wire-format key material in the command | A shared key does not identify an actor or prove it was used for authentication. |
| ConfigStore SQLite | Account identifier and `last_password_change` epoch-day value | State evidence with day precision. Midnight is a sorting anchor; actor, exact time and method are unknown. Credential values are not exported by this extractor. |

The parser also retains selected software/VIB changes, firewall and remote-service
changes, VM impact operations, host lifecycle, HA, kernel/storage and network
availability events. An outage or authorized administrative action is not
automatically an attack.

## Behavioral Tags

Contributor-facing severity, ATT&CK mappings and evidence wording live in
[`rules/tagging_registry.yml`](../rules/tagging_registry.yml). Native parsing and
command structure recognition emit stable detection names for those mappings.
Rules use generic operations, documented public artifacts and explicitly marked
filename heuristics, not private incident IPs, hostnames, key fingerprints or guest labels.

- VMkatz executable/loader invocation: credential-dumping attempt, not recovered credentials.
- Interpreter commands targeting `/vmfs/volumes/`: datastore-script review lead; no ransomware label from an arbitrary filename.
- SSH authorized-key writes, history/log truncation, tunnel commands and execution-control changes.
- VIB installation with validation-bypass options, filesystem format requests, account administration and inventory discovery.
- Precise VM-operation mappings: power-off differs from snapshot removal, destruction and unregistering a VM.
- VMkatz tool labels, Python execution, raw VMFS access and loader candidates.
- Explicit payload/name/option candidates, lockdown and VIB acceptance changes,
  snapshot removal requests, VM-process termination and VMFS encryption commands.
- A same-host, 24-hour actor-neutral ransomware tradecraft profile. No actor
  match is explicitly explained in the summary and profile-assessment JSON.

See [ESXi threat research](ESXI_THREAT_RESEARCH.md) for sources, active payload
selectors and the distinction between a candidate, a behavior and attribution.

Read-only inspection and literal command text are not treated as execution of the
strings being inspected. Shell parsing is conservative and not a full shell
interpreter: unusual wrappers, substitutions and obfuscation require manual review.

## Correlation And Provenance

SFTP context joins use the same collection/host and explicit process ID. Management
context joins use explicit session IDs. References retain the opening record's
source path, line and time. Joins expire after 24 hours, close at recorded session
termination, and reset at recognized host lifecycle boundaries. PID reuse without
a retained opening/closing record remains a limitation; context is derived, not a
new authentication fact.

Working-directory candidates use `cd` commands from the same host/user/shell PID,
expire after 12 hours, and retain their source reference. Failed `cd` cannot be
ruled out from shell command logs alone. VM datastore labels are not asserted to
be guest hostnames, DNS identities, or evidence of guest compromise.

## Timeline And Coverage

The full timeline aggregates selected normalized observations. It is not a dump
of all source lines and not a final forensic narrative. The analyst-selected
timeline and notes form the curated reconstruction; findings remain triage leads.
CSV/JSONL retain source hashes and raw records; the investigation XLSX includes
techniques, candidate mappings and saved analyst tags.

`source_index.json` and nested `case_source_index.json` entries include ESXi
`parse_coverage`: lines examined, recognized timestamped records, selected events,
filtered records, unparsed lines and truncation state. Successful read-only
management polling is excluded from the IR chronology; failures are retained.
The parser's 100,000 selected-event per-source safety cap emits a warning event
and marks source coverage partial. Unsupported/multiline records may remain only
in the preserved evidence. A zero-hit source is not proof that no activity occurred.

Existing cases are immutable parsing snapshots. Reparse the original archives
into a **new case** to use updated coverage; changing the XLSX export does not
retroactively parse missing records. Keep the original case and annotations for
comparison because additional events can change event IDs.

## Remaining Limits

- Nested support archives and bootbank `local.tgz` ConfigStore copies are not recursively expanded. The metadata parser handles standalone collected SQLite stores.
- No automatic payload reverse engineering, encrypted ConfigStore decryption, VM memory analysis or proof of encryption/exfiltration.
- No broad inference of initial access, actor identity, guest identity or lateral movement from coincident IPs/tool names.
- Session records can be duplicated across VMware components. Event counts are source observations, not unique operations or sessions.
- Vendor/version-specific log formats, missing rotations, clock skew and unknown timezone formats can limit coverage. Consult source indexes and parser errors.

## References

- [Broadcom: Location of ESXi log files](https://knowledge.broadcom.com/external/article?legacyId=2032076)
- [Broadcom: Routine hostd login/logout events](https://knowledge.broadcom.com/external/article/379626/login-events-logged-in-logged-out-messa.html)
- [MITRE ATT&CK: ESXi matrix](https://attack.mitre.org/matrices/enterprise/esxi/)
- [MITRE ATT&CK: OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [VMkatz project: ESXi deployment and supported inputs](https://github.com/nikaiw/VMkatz/blob/main/docs/esxi.md)

Mappings follow TraceQuarry's pinned ATT&CK registry; candidate mappings and
deprecated identifiers should be reviewed when updating that registry.
