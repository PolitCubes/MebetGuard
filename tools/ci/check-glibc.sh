#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
# The Linux guard must start on the oldest systems we promise: glibc 2.28 (Ubuntu 18.10+,
# Debian 10+, RHEL 8+, Steam Deck) with the libstdc++ of GCC 8. Fails when a binary asks the
# loader for a newer symbol version — on such a system it would not start at all.
#   check-glibc.sh <file>...
set -euo pipefail

GLIBC_FLOOR="GLIBC_2.28"
GLIBCXX_FLOOR="GLIBCXX_3.4.25"

newest() {  # newest "<prefix>_<version>" the files need, empty when none
  readelf -V "${@:2}" | grep -o "$1_[0-9][0-9.]*" | sort -uV | tail -1
}

bad=0
for pair in "GLIBC:$GLIBC_FLOOR" "GLIBCXX:$GLIBCXX_FLOOR"; do
  prefix="${pair%%:*}"
  floor="${pair#*:}"
  need="$(newest "$prefix" "$@")"
  echo "$prefix: needs ${need:-nothing}, floor $floor"
  if [ -n "$need" ] && [ "$(printf '%s\n' "$floor" "$need" | sort -V | tail -1)" != "$floor" ]; then
    echo "::error::the Linux guard needs $need, above the promised floor $floor: it will not start on older systems"
    bad=1
  fi
done
exit $bad
