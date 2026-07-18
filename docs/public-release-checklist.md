# Public Release Checklist

Use this checklist before changing TraceQuarry from private to public.

## Before Visibility Changes

- Confirm `main` contains only TraceQuarry source and synthetic fixtures.
- Confirm the reachable history contains no prior workspace commits, evidence,
  credentials, malware, or customer identifiers.
- Run `python3 -m unittest discover -s tests -v` from a fresh clone.
- Confirm the Python 3.11 and 3.12 CI jobs pass.
- Review open pull requests, issues, Actions logs, and release drafts for
  sensitive information.
- Confirm `contact@chillethicalpeople.com` is monitored.

## Immediately After Making The Repository Public

Run the included GitHub hardening helper:

```bash
tools/configure_github_security.sh kensho-cep/tracequarry
```

This enables private vulnerability reporting, Dependabot vulnerability alerts,
automated security fixes, and `main` protection requiring the Python 3.11 and
3.12 CI checks. CodeQL and dependency review automatically activate for public
repository events.

## First Beta Release

1. Confirm `pyproject.toml` and `uac_parser/__init__.py` contain the intended
   version.
2. Create and push an annotated `v0.4.0-beta.1` tag.
3. Confirm the Release workflow publishes the wheel, source distribution,
   CycloneDX SBOM, and `SHA256SUMS`.
4. Verify the published checksums from a fresh download.
5. Install the published wheel in an empty virtual environment and run a
   synthetic fixture smoke test.
6. Confirm the security policy and private advisory form are visible.

Do not publish real UAC evidence or generated case output as a release asset.
