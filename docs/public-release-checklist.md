# Public Release Checklist

Use this checklist before changing TraceQuarry from private to public.

## Before Visibility Changes

- Confirm `main` contains only TraceQuarry source and synthetic fixtures.
- Confirm the reachable history contains no prior workspace commits, evidence,
  credentials, malware, or customer identifiers.
- Confirm the checkout is healthy and contains no cloud-sync duplicate refs or
  sidecars:

  ```bash
  git fsck --full --no-reflogs
  find . -path ./.git -prune -o -type f -name '* 2' -print
  ```
- Install `.[dev]` and run the release gates from a fresh clone:

  ```bash
  python3 tools/check_repository_hygiene.py
  ruff check uac_parser tests tools
  ruff format --check uac_parser tests tools
  mypy uac_parser
  bandit -q -c pyproject.toml -r uac_parser
  coverage run -m unittest discover -s tests -v
  coverage report
  pip-audit . --strict --progress-spinner off
  snyk test --file=requirements.txt --package-manager=pip --severity-threshold=low
  gitleaks git --redact --no-banner --verbose .
  ```

- Confirm the `SNYK_TOKEN` repository secret is configured and the Snyk Open
  Source workflow passes. Record the Snyk Code result separately when that
  product is enabled for the Snyk organization.
- Confirm the Python 3.11 and 3.12 CI jobs pass.
- Review open pull requests, issues, Actions logs, and release drafts for
  sensitive information.
- Confirm `contact@chillethicalpeople.com` is monitored.

## Immediately After Making The Repository Public

Run the included GitHub hardening helper:

```bash
tools/configure_github_security.sh Chill-Ethical-People/TraceQuarry
```

This enables private vulnerability reporting, Dependabot vulnerability alerts,
automated security fixes, and pull-request protection on `main`. The protection
requires Python 3.11 and 3.12 CI, Snyk Open Source, Gitleaks history scanning,
CodeQL, and dependency review. CodeQL and dependency review automatically
activate for public repository events.

Confirm all six required checks pass on a public test pull request before
publishing the beta release announcement.

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
