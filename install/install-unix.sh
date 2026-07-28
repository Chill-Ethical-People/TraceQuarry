#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  printf '%s\n' "usage: install-unix.sh <linux|macos> [installer options...]" >&2
  exit 2
fi

platform=$1
shift
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(dirname -- "$script_dir")

selected=""
if [ -n "${TRACEQUARRY_PYTHON:-}" ]; then
  if command -v "$TRACEQUARRY_PYTHON" >/dev/null 2>&1 \
    && "$TRACEQUARRY_PYTHON" -c 'import sys; raise SystemExit(sys.version_info[:2] not in {(3, 11), (3, 12)})' >/dev/null 2>&1; then
    selected=$TRACEQUARRY_PYTHON
  fi
else
  for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 \
      && "$candidate" -c 'import sys; raise SystemExit(sys.version_info[:2] not in {(3, 11), (3, 12)})' >/dev/null 2>&1; then
      selected=$candidate
      break
    fi
  done
fi

if [ -z "$selected" ]; then
  printf '%s\n' "TraceQuarry requires Python 3.11 or 3.12." >&2
  printf '%s\n' "Install a supported Python release or set TRACEQUARRY_PYTHON." >&2
  exit 1
fi

exec "$selected" "$repository_root/tools/install_tracequarry.py" \
  --platform "$platform" --source "$repository_root" "$@"
