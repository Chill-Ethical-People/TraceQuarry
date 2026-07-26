#!/usr/bin/env python3
"""Verify that every commit in a pull-request range has a DCO sign-off."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


SIGN_OFF_RE = re.compile(
    r"^Signed-off-by:\s+\S.*\s+<[^<>\s]+@[^<>\s]+>\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def has_valid_sign_off(message: str) -> bool:
    """Return whether a commit message contains a conventional DCO trailer."""
    return SIGN_OFF_RE.search(message) is not None


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commits_since(base_ref: str) -> list[str]:
    remote_ref = base_ref if base_ref.startswith("origin/") else f"origin/{base_ref}"
    merge_base = git("merge-base", remote_ref, "HEAD")
    output = git("rev-list", "--reverse", f"{merge_base}..HEAD")
    return output.splitlines() if output else []


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check DCO Signed-off-by trailers for pull-request commits."
    )
    parser.add_argument(
        "--base-ref",
        required=True,
        help="Base branch or remote ref used to calculate the pull-request range.",
    )
    args = parser.parse_args()

    try:
        commits = commits_since(args.base_ref)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() if exc.stderr else str(exc)
        print(f"Unable to determine DCO commit range: {detail}", file=sys.stderr)
        return 2

    unsigned: list[str] = []
    for commit in commits:
        message = git("show", "-s", "--format=%B", commit)
        if not has_valid_sign_off(message):
            subject = git("show", "-s", "--format=%s", commit)
            unsigned.append(f"{commit[:12]} {subject}")

    if unsigned:
        print("DCO check failed. These commits need a Signed-off-by trailer:")
        for item in unsigned:
            print(f"- {item}")
        print("Rewrite each commit with `git commit --amend -s` and update the branch.")
        return 1

    print(f"DCO check passed for {len(commits)} commit(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
