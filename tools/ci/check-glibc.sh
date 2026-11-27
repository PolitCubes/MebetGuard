#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
# The Linux guard must start on the oldest systems we promise: glibc 2.28 (Ubuntu 18.10+,
# Debian 10+, RHEL 8+, Steam Deck) with the C++ runtime of GCC 8 (libstdc++, its ABI, libgcc_s).
# Fails when a binary asks the loader for a newer symbol version — on such a system it would not
# start at all. A static check: the build job also starts the guard in the oldest container.
#   check-glibc.sh <file>...
set -euo pipefail

GLIBC_FLOOR="GLIBC_2.28"
GLIBCXX_FLOOR="GLIBCXX_3.4.25"
CXXABI_FLOOR="CXXABI_1.3.11"
GCC_FLOOR="GCC_7.0.0"

command -v readelf >/dev/null || { echo "::error::readelf not found: cannot check symbol versions"; exit 2; }
for f in "$@"; do
  [ -f "$f" ] || { echo "::error::no such file to check: $f"; exit 2; }
done
# Read every file's version info once (captured, so readelf exiting non-zero on one file does not fail
# the whole pipeline under pipefail, and so it is not re-run per floor). readelf must have produced
# version data — otherwise an absent tool or an unreadable/non-ELF file would read as 'needs nothing'
# for every floor and pass vacuously.
syms="$(readelf -V "$@" 2>/dev/null || true)"
printf '%s' "$syms" | grep -qi "version" || { echo "::error::readelf produced no version data for $*: not validated"; exit 2; }

newest() {  # newest "<prefix>_<version>" the files need, empty when none
  # grep finds nothing when no such symbol is needed: that is an answer, not a failure.
  { printf '%s\n' "$syms" | grep -o "$1_[0-9][0-9.]*" || true; } | sort -uV | tail -1
}

bad=0
for pair in "GLIBC:$GLIBC_FLOOR" "GLIBCXX:$GLIBCXX_FLOOR" "CXXABI:$CXXABI_FLOOR" "GCC:$GCC_FLOOR"; do
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
