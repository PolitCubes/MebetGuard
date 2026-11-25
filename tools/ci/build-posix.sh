#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
# Build and package one Linux/macOS guard variant. One call per build step so every instance is
# a separate, visible step in the single "linux" / "macos" job.
#   build-posix.sh <kind> <dir> [extra cmake args...]
set -euo pipefail

KIND="$1"
DIR="$2"
shift 2

: "${JAVA_HOME:=$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
export JAVA_HOME

B="build/$DIR-$KIND"
cmake -S . -B "$B" -DCMAKE_BUILD_TYPE=Release -DMEBET_BUILD_KIND="$KIND" -DMEBET_JAVA_HOME="$JAVA_HOME" "$@"
cmake --build "$B" --parallel

OUT="dist/$KIND/$DIR"
mkdir -p "$OUT"
cp "$B/src/posix/MebetGuard" "$OUT/"
for lib in libMebetGuard.so libMebetGuard.dylib; do
  [ -f "$B/src/posix/$lib" ] && cp "$B/src/posix/$lib" "$OUT/"
done
echo "built $DIR ($KIND):"
( sha256sum "$OUT"/* 2>/dev/null || shasum -a 256 "$OUT"/* )
