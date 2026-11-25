# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Two tests per scenario and privilege variant (harness.SCENARIOS): the same action without the
guard and through it.

    test_layer[module_trust_load-baseline-game_user]    PASSED   без гварда: атака сработала
    test_layer[module_trust_load-guarded-game_user]     PASSED   через гвард: закрыт, код 210
    test_layer[tamper_freeze_guard-guarded-game_admin]  PASSED   через гвард: закрыт, код 225
    test_layer[process_dacl_open-guarded-game_user-other_admin]  XFAIL  известное ограничение Windows

For an attack the baseline proves it works and the guarded run proves the guard stops it; for a
legit action both runs prove it works. On Windows every scenario runs with the game as a standard
user and as an admin (and, for an attack from another program, that program as either too).

    pytest tests/e2e -v -rP --guard <MebetGuard> --java <JAVA_HOME> [--untrusted-native <lib>]
"""
import re

import pytest

import harness

SIDES = {"baseline": "без гварда", "guarded": "через гвард"}
LEVEL = {"user": "пользователь", "admin": "админ"}
CASES = [(sc, v, side) for sc in harness.SCENARIOS for v in harness.variants(sc) for side in SIDES]
IDS = ["-".join(x for x in (sc["id"], side, harness.variant_id(v)) if x) for sc, v, side in CASES]
EVIDENCE = re.compile(r"TARGET (did|froze|killed|called|foreign|action-failed)|\[Mebet\] closed|PROBE ")


def _label(side, variant):
    game, other = variant
    parts = []
    if game:
        parts.append("игра: " + LEVEL[game])
    if other:
        parts.append("другая программа: " + LEVEL[other])
    return SIDES[side] + (" [" + ", ".join(parts) + "]" if parts else "")


@pytest.mark.parametrize("sc,variant,side", CASES, ids=IDS)
def test_layer(ctx, sc, variant, side):
    skip = harness.applies(sc, ctx, variant)
    if skip:
        # In CI every selected scenario must really run: a skip there would show green.
        if ctx.no_skip:
            pytest.fail("[%s] не может выполниться здесь: %s" % (sc["id"], skip))
        pytest.skip(skip)

    exp = harness.expectations(sc, variant)
    run = harness.run_scenario(ctx, sc, side, variant)
    if side == "baseline":
        ok, msg = harness.baseline_ok(sc, run, exp)
    else:
        ok, msg = harness.guard_ok(ctx, sc, run, exp)
    label = _label(side, variant)
    assert ok, "[%s] %s: %s\n%s" % (sc["id"], label, msg, run["out"])

    # The verdict and its evidence, shown for passed tests too (pytest -rP): what the attack did
    # and how the guard answered, not just PASSED.
    print("[%s] %s: %s" % (sc["id"], label, msg))
    for line in run["out"].splitlines():
        if EVIDENCE.search(line):
            print("    " + line.strip())
    if ok == "xfail":
        pytest.xfail(msg)
