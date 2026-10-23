# ESXi Threat Research and Evidence Boundaries

TraceQuarry distinguishes observed behavior, payload candidates and profile
similarity. None of these automatically establishes actor attribution.

## Source-backed rules

- [VMkatz documentation](https://github.com/nikaiw/VMkatz/blob/main/docs/esxi.md):
  executable/loader invocation and raw VMFS access. Invocation does not prove
  that credentials were recovered.
- [Sophos Python ransomware analysis](https://www.sophos.com/en-us/blog/python-ransomware-script-targets-esxi-server-for-encryption):
  reports fcker.py. The generic names enc.py, encrypt.py and encryptor.py are
  analyst heuristics, not published family indicators. A VMFS-targeted invocation
  creates a low-confidence candidate, not a confirmed encryption event.
- [INCIBE ESXiArgs](https://www.incibe.es/en/incibe-cert/blog/esxiargs-response-and-recovery-actions):
  encrypt/encrypt.sh and VM-file argument sidecars require corroboration.
- [CISA Play advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)
  and [SentinelOne BlackSuit analysis](https://www.sentinelone.com/anthology/blacksuit/):
  note names, extensions and argument combinations are candidate clues only.
- [CrowdStrike hypervisor ransomware](https://www.crowdstrike.com/en-us/blog/carbon-spider-sprite-spider-target-esxi-servers-with-ransomware/):
  historical payload names and VM shutdown behavior are not unique to one actor.
- [Mandiant ESXi persistence](https://cloud.google.com/blog/topics/threat-intelligence/esxi-hypervisors-malware-persistence)
  and [Huntress hypervisor defenses](https://www.huntress.com/blog/hypervisor-defenses-against-ransomware-targeting-esxi):
  VIB, logging and lockdown changes can also be authorized administration.

## Runtime boundaries

Only malware entries with explicit `esxi_match` selectors run as payload rules.
Other catalogue entries remain research metadata. Read-only inspection and
literal command arguments are excluded from invocation matching. Candidates use
`payload_candidate.*`, tentative technique mappings and `not_attribution`.

The actor-neutral ransomware-tradecraft profile requires a payload/encryption
candidate, at least three distinct records and two preparation stages on the
same host and collection within a trailing 24-hour window. It does not combine
unrelated hosts to manufacture a match. Named actor profiles keep their existing
thresholds and mark supporting rows as `actor_similarity.*` only when qualified.

Every new parse writes `profile_assessment.json` (or the case-prefixed equivalent).
No profile match means thresholds were not met, not that compromise is absent.
Renamed payloads, uncollected artifacts and commands inside unexamined scripts
may be missed. Validate decisive conclusions using source evidence and effects.

The native timeline contains selected normalized records, not every physical
source line. Source coverage reports omissions and parser limits. Exports do not
reprocess old cases; run a fresh parse to apply updated rules.
