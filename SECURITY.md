# Security Policy

TraceQuarry is a DFIR tool and may be used with sensitive incident evidence.
Please avoid sharing real evidence or confidential incident details in public
issues, pull requests, screenshots, or sample archives.

## Reporting Security Issues

For security-sensitive reports, email
[`contact@chillethicalpeople.com`](mailto:contact@chillethicalpeople.com) or use
[GitHub private vulnerability reporting](https://github.com/Chill-Ethical-People/TraceQuarry/security/advisories/new)
before publishing technical details. Include:

- A concise description of the issue.
- Affected version or commit.
- Reproduction steps using synthetic data where possible.
- Potential impact.
- Any suggested fix or mitigation.

Do not include real UAC archives, credentials, tokens, customer names, victim
identifiers, private incident timelines, or unredacted logs.

## Supported Versions

TraceQuarry is currently pre-1.0. Security fixes are expected to target the
latest public branch unless maintainers state otherwise.

## Local Security Model

- The web GUI binds only to `127.0.0.1`, `localhost`, or `::1`. Direct remote
  binding is refused, including the legacy `--allow-remote` option.
- Use an authenticated SSH tunnel when remote analyst access is required. Do not
  publish the GUI through an unauthenticated reverse proxy.
- State-changing browser requests require a per-process token and loopback Host
  and Origin values. Reload the GUI after restarting the server.
- New work directories use mode `0700`; uploaded and derived evidence uses mode
  `0600`. The analyst remains responsible for encrypted storage, backups, and
  retention appropriate to the case.
- Upload, work-directory, archive expansion, request-time, and concurrent-job
  limits are safety controls. Increase them deliberately for unusually large
  collections and monitor free disk space.

## Responsible Use

TraceQuarry findings are analyst leads, not final determinations. Validate
findings against raw source lines, source coverage, timezone assumptions, and
external telemetry before making case conclusions.
