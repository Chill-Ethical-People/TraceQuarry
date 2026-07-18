#!/usr/bin/env bash
set -euo pipefail

repo="${1:-kensho-cep/tracequarry}"
visibility="$(gh repo view "$repo" --json visibility --jq '.visibility')"

if [[ "$visibility" != "PUBLIC" ]]; then
  printf 'Refusing to configure public-only controls: %s is %s.\n' "$repo" "$visibility" >&2
  exit 1
fi

gh api --method PUT "repos/$repo/vulnerability-alerts" >/dev/null
gh api --method PUT "repos/$repo/automated-security-fixes" >/dev/null
gh api --method PUT "repos/$repo/private-vulnerability-reporting" >/dev/null

gh api --method PUT "repos/$repo/branches/main/protection" --input - >/dev/null <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Python 3.11", "Python 3.12"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true
}
JSON

printf 'Enabled public release security controls for %s.\n' "$repo"
