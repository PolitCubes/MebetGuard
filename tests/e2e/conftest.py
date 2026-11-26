# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
import pytest

import harness


def pytest_addoption(parser):
    g = parser.getgroup("mebet e2e")
    g.addoption("--guard", default=None, help="MebetGuard wrapper executable")
    g.addoption("--java", default=None, help="JAVA_HOME of the game Java")
    g.addoption("--work", default=None, help="work directory for built fixtures")
    g.addoption("--untrusted-native", default=None, help="prebuilt unsigned native (no compiler)")
    g.addoption("--no-skip", action="store_true",
                help="fail instead of skipping a scenario that cannot run here (CI)")
    g.addoption("--expect-dev-mode", action="store_true",
                help="the guard is a release build and this machine is in dev mode: run the dev_mode scenario")


@pytest.fixture(scope="session")
def ctx(request):
    guard = request.config.getoption("--guard")
    java = request.config.getoption("--java")
    if not guard or not java:
        pytest.fail("нужны --guard <MebetGuard> и --java <JAVA_HOME>")
    c = harness.Ctx(guard, java, request.config.getoption("--work"),
                    request.config.getoption("--untrusted-native"))
    if not c.guard.exists():
        pytest.fail("нет стража: %s" % c.guard)
    if not c.java.exists():
        pytest.fail("нет java: %s" % c.java)
    c.no_skip = request.config.getoption("--no-skip")
    c.expect_dev_mode = request.config.getoption("--expect-dev-mode")
    harness.build_fixtures(c)
    return c
