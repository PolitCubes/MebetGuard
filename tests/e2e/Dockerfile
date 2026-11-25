# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
#
# A self-contained end-to-end test container. Inside it the guard is built (test/novm build,
# no VM/WSL detection, so it runs inside this container), then tests/e2e/run.py launches the
# target JVM with and without the guard and attacks each layer. "docker run" exits non-zero if
# any layer regressed.
#
#   docker build -f tests/e2e/Dockerfile -t mebet-e2e .
#   docker run --rm mebet-e2e                      # all applicable layers
#   docker run --rm mebet-e2e --only jvm_agents_javaagent
#
# The game Java vendor does not matter for these start-time layers, so the container's own JDK
# is used as JAVA_HOME.
FROM eclipse-temurin:25-jdk

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake python3 python3-pytest git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /mebet
COPY . .

# Build the guard (test = novm: virtual_machine and linux_wsl off, so no false close here).
RUN git config --global --add safe.directory /mebet \
 && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMEBET_BUILD_KIND=test -DMEBET_JAVA_HOME="$JAVA_HOME" \
 && cmake --build build --parallel \
 && test -x build/src/posix/MebetGuard

# One pytest test per layer scenario (pass extra args to docker run, e.g. -k jvm_agents).
ENTRYPOINT ["python3", "-m", "pytest", "tests/e2e", "-v", "--no-header", \
            "--guard", "/mebet/build/src/posix/MebetGuard", \
            "--java", "/opt/java/openjdk", \
            "--work", "/tmp/e2e"]
