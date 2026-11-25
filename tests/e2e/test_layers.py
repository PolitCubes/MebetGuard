# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""One test per protection layer scenario (harness.SCENARIOS).

Each test runs the scenario's attack twice: without the guard it must work, through the guard
it must be blocked. `pytest -v` prints a line per scenario, e.g.

    test_layers.py::test_layer[jvm_agents_javaagent] PASSED

Run it with the built guard and the game Java:

    pytest tests/e2e -v --guard <MebetGuard> --java <JAVA_HOME> [--untrusted-native <lib>]
"""
import pytest

import harness


@pytest.mark.parametrize("sc", harness.SCENARIOS, ids=[s["id"] for s in harness.SCENARIOS])
def test_layer(ctx, sc):
    skip = harness.applies(sc, ctx)
    if skip:
        pytest.skip(skip)

    # 1. Without the guard the attack must work.
    base = harness.run_scenario(ctx, sc, "baseline")
    ok, msg = harness.baseline_ok(sc, base)
    assert ok, "[%s] без гварда: %s\n%s" % (sc["id"], msg, base["out"])

    # 2. Through the guard it must be blocked.
    guarded = harness.run_scenario(ctx, sc, "guarded")
    ok, msg = harness.guard_ok(ctx, sc, guarded)
    assert ok, "[%s] через гвард: %s\n%s" % (sc["id"], msg, guarded["out"])
