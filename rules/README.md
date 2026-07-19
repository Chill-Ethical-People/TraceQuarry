# TraceQuarry Detection Pack

`tagging_registry.yml` is TraceQuarry's canonical, contributor-maintained Linux
detection pack. It contains four rule families:

- `tool_tags`: concrete tools, services, commands, and utilities.
- `ttp_tags`: behavior tags and MITRE ATT&CK mappings.
- `actor_similarity_profiles`: non-attributive combinations of observed tools
  and TTPs.
- `malware_payload_tags`: cautiously worded Linux malware and payload metadata.

The parser loads tool and TTP rules during event enrichment and evaluates actor
similarity profiles when deriving findings. Complex stateful analytics, such as
SSH failures followed by success, remain in Python and can emit detection names
that a TTP rule consumes through `match_detection_names`.

## Validate A Change

From a development checkout:

```bash
PYTHONPATH=. python3 -m uac_parser.rules_cli
```

After installation:

```bash
tracequarry-rules
```

Validation rejects duplicate YAML keys, malformed rule IDs, unsupported
severity or confidence values, invalid ATT&CK IDs, missing required fields, and
unknown source references.

## Add A Tool

Add a stable lowercase ID under `tool_tags`:

```yaml
tool_tags:
  example_transfer_tool:
    namespace: tool
    category: exfiltration
    confidence_when_matched: medium
    match_literals: ["example-transfer"]
    related_ttps: ["ttp.exfil_tool_usage"]
    mitre: ["T1567"]
    timesketch_labels: ["tool.example_transfer_tool", "attack.T1567"]
    source_refs: ["vendor_example_transfer_tool"]
    analyst_note: "Dual-use utility; confirm execution and destination context."
```

Literal matching is token-aware for simple binary names. Avoid generic values
such as `go`, `sh`, `sync`, or `agent`, which create broad false positives.

## Add A TTP Mapping

TTP rules can consume one or more parser signals:

```yaml
ttp_tags:
  example_behavior:
    namespace: ttp
    severity: medium
    confidence_when_matched: medium
    evidence: "Describe the observable evidence, not an inferred conclusion."
    mitre: ["T1059.004"]
    timesketch_labels: ["ttp.example_behavior", "attack.T1059.004"]
    match_detection_names: ["parser_detection_name"]
    match_event_actions: ["normalized_event_action"]
    match_tags: ["tool_category.example"]
```

The three `match_*` lists use OR semantics. Rules without match fields remain
reference metadata until a parser or correlation supplies a reliable signal.

## Add An Actor-Similarity Profile

Actor profiles are prioritization aids, never attribution rules:

```yaml
actor_similarity_profiles:
  example_cluster_like:
    namespace: actor_similarity
    display_name: "Example-cluster-like Linux tradecraft overlap"
    actor_refs: ["primary_source_example"]
    confidence_cap: low
    required_evidence_count: 3
    minimum_event_count: 2
    minimum_strong_indicators: 2
    minimum_supporting_indicators: 1
    required_any_indicators: ["tool.example_transfer_tool"]
    strong_indicators: ["tool.example_transfer_tool", "ttp.example_behavior"]
    supporting_indicators: ["ttp.log_or_history_tampering"]
    mitre_focus: ["T1059.004", "T1070"]
    analyst_warning: "Shared tradecraft is not proof of actor identity."
```

By default, the runtime requires two strong indicators, one supporting
indicator, the configured total number of distinct indicators, and two distinct
source events. `required_any_indicators` adds profile-specific anchors that
prevent generic tradecraft from matching a named profile. Confidence is capped
at `medium`; `high` is rejected by the validator. Profiles must preserve the
phrase "This is not attribution" in generated findings.

## Evidence And Review Requirements

- Add authoritative HTTPS references under `source_references`.
- Prefer MITRE ATT&CK, government advisories, primary vendor research, and tool
  documentation.
- Use behavior-level tags when a family or actor cannot be established.
- Treat legitimate administration, backup, RMM, and cloud tools as dual-use.
- Do not use customer evidence, live credentials, private infrastructure, or
  unredacted incident data in rules or tests.
- Add a focused unit test showing both a positive match and an important
  non-match or false-positive boundary.
- Run the full quality suite described in `CONTRIBUTING.md` before opening a PR.

The run manifest records the registry SHA-256, allowing an analyst to identify
the exact detection content used for a case.
