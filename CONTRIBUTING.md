# Contributing To TraceQuarry

Thank you for helping improve TraceQuarry. This project is intended for
defensible Linux DFIR workflows, so contributions should favor accuracy,
traceability, and cautious language over aggressive detection claims.

## Contribution Terms

By submitting a pull request, patch, issue attachment, or other contribution,
you agree that your contribution is provided under the Apache License, Version
2.0, unless you explicitly mark it as "Not a Contribution."

Do not submit code, indicators, reports, evidence, screenshots, customer data,
or third-party content that you do not have permission to share.

## What Makes A Good Change

- Keep single-collection CLI behavior backward compatible.
- Preserve source paths, raw-line context, and parser errors for analyst review.
- Treat findings as leads unless the evidence supports a stronger conclusion.
- Avoid attribution claims from TTP overlap alone.
- Add focused fixture coverage when changing parsing, enrichment, or timeline
  behavior.
- Do not include real UAC archives, extracted evidence trees, customer names,
  private IP ownership details, credentials, tokens, or generated case outputs.
- Keep test records synthetic and text-only. Use RFC 5737 documentation IPs,
  `.invalid` domains, and obvious credential placeholders.

## Detection-Pack Contributions

Tools, TTP mappings, malware/payload metadata, and actor-similarity profiles
belong in the canonical `rules/tagging_registry.yml` detection pack. Follow the
[rule-authoring guide](rules/README.md), add focused positive and false-positive
tests, and run:

```bash
PYTHONPATH=. python3 -m uac_parser.rules_cli
```

Actor entries must remain profile similarity only. The validator rejects a
`high` actor confidence cap, and submissions must not present shared tooling or
ATT&CK overlap as attribution.

## Development Smoke Test

Run the repository hygiene gate before testing:

```bash
python3 tools/check_repository_hygiene.py
```

```bash
cd tracequarry
PYTHONPATH=. python3 -m uac_parser.cli tests/fixtures/uac_sample \
  --out /tmp/tracequarry-smoke \
  --incident-start 2026-06-16T09:58:00+08:00 \
  --incident-end 2026-06-16T18:01:40+08:00 \
  --year 2026 \
  --timezone Asia/Hong_Kong
```

Confirm that `timeline_full.csv`, `timeline_mini.csv`, `findings.json`,
`source_index.json`, and `parser_errors.log` are written.

## Security-Sensitive Contributions

If your change describes a live vulnerability, bypass technique, active victim,
or sensitive incident detail, do not open a public issue with full details.
Follow `SECURITY.md` instead.
