#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  printf '%s\n' "This installer is intended for Linux." >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$script_dir/install-unix.sh" linux "$@"
