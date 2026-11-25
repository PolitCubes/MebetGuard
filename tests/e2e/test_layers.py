# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Two tests per scenario (harness.SCENARIOS): the same action without the guard and through it.

    test_layers.py::test_layer[module_trust_load-baseline] PASSED   без гварда: атака сработала
    test_layers.py::test_layer[module_trust_load-guarded]  PASSED   через гвард: закрыт, код 210

For an attack the baseline proves it works and the guarded run proves the guard stops it; for a
legit action both runs prove it works. Run with the built guard and the game Java:

    pytest tests/e2e -v --guard <MebetGuard> --java <JAVA_HOME> [--untrusted-native <lib>]
"""
import pytest

import harness

SIDES = {"baseline": "без гварда", "guarded": "через гвард"}
CASES = [(sc, side) for sc in harness.SCENARIOS for side in SIDES]


@pytest.mark.parametrize("sc,side", CASES, ids=["%s-%s" % (sc["id"], side) for sc, side in CASES])
def test_layer(ctx, sc, side):
    skip = harness.applies(sc, ctx)
    if skip:
        # In CI every selected scenario must really run: a skip there would show green.
        if ctx.no_skip:
            pytest.fail("[%s] не может выполниться здесь: %s" % (sc["id"], skip))
        pytest.skip(skip)

    run = harness.run_scenario(ctx, sc, side)
    if side == "baseline":
        ok, msg = harness.baseline_ok(sc, run)
    else:
        ok, msg = harness.guard_ok(ctx, sc, run)
    assert ok, "[%s] %s: %s\n%s" % (sc["id"], SIDES[side], msg, run["out"])
