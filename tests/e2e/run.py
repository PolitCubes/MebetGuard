#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Quick table view of the layer e2e — one row per scenario.

This is a convenience wrapper over the same harness the pytest tests use. For one test per
scenario with per-test pass/fail, prefer:

    pytest tests/e2e -v --guard <MebetGuard> --java <JAVA_HOME> [--untrusted-native <lib>]

Table form:

    python tests/e2e/run.py --guard <MebetGuard> --java <JAVA_HOME> [--only id,id]
                            [--untrusted-native <lib>] [--work <dir>] [--json <out>]
"""
import argparse
import json
import sys
from pathlib import Path

import harness


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard", required=True)
    ap.add_argument("--java", required=True)
    ap.add_argument("--work", default=None)
    ap.add_argument("--only", default="", help="comma-separated scenario ids")
    ap.add_argument("--untrusted-native", default=None)
    ap.add_argument("--json", default="")
    a = ap.parse_args()

    ctx = harness.Ctx(a.guard, a.java, a.work, a.untrusted_native)
    if not ctx.guard.exists():
        sys.exit("guard not found: " + str(ctx.guard))
    if not ctx.java.exists():
        sys.exit("java not found: " + str(ctx.java))
    harness.build_fixtures(ctx)

    only = {x for x in a.only.split(",") if x}
    rows, failed = [], 0
    for sc in harness.SCENARIOS:
        if only and sc["id"] not in only:
            continue
        skip = harness.applies(sc, ctx)
        if skip:
            rows.append(dict(id=sc["id"], state="skip", baseline="—", guard=skip))
            continue
        base = harness.run_scenario(ctx, sc, "baseline")
        guarded = harness.run_scenario(ctx, sc, "guarded")
        ok_b, bv = harness.baseline_ok(sc, base)
        ok_g, gv = harness.guard_ok(ctx, sc, guarded)
        passed = ok_b and ok_g
        failed += 0 if passed else 1
        rows.append(dict(id=sc["id"], state="OK" if passed else "FAIL", baseline=bv, guard=gv,
                         base_exit=base["exit"], guard_exit=guarded["exit"]))

    w = max((len(r["id"]) for r in rows), default=4)
    print("\n%-4s %-*s  %-30s  %s" % ("", w, "scenario", "без гварда", "через гвард"))
    for r in rows:
        print("%-4s %-*s  %-30s  %s" % (r["state"], w, r["id"], r["baseline"], r["guard"]))
    ran = [r for r in rows if r["state"] != "skip"]
    print("\n%d/%d scenarios passed (%d skipped)" %
          (len(ran) - failed, len(ran), len(rows) - len(ran)))

    if a.json:
        Path(a.json).write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
