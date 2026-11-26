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
import paths


def main():
    # The verdicts are Russian: printed into a pipe or a file with a legacy code page they ended the
    # run with UnicodeEncodeError after every scenario had run, and the --json file was lost.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard", required=True)
    ap.add_argument("--java", required=True)
    ap.add_argument("--work", default=None)
    ap.add_argument("--only", default="", help="comma-separated scenario ids")
    ap.add_argument("--untrusted-native", default=None)
    ap.add_argument("--json", default="")
    ap.add_argument("--expect-dev-mode", action="store_true",
                    help="the guard is a release build and this machine is in dev mode: run the dev_mode scenario")
    ap.add_argument("--paths", default=None, choices=paths.VARIANTS,
                    help="run from awkward folders — copies of the guard and the JDK, the work dir (paths.py)")
    a = ap.parse_args()

    guard, java, work, native = a.guard, a.java, a.work, a.untrusted_native
    if a.paths:
        root = Path(work).resolve() / "paths" if work else harness.HERE / "_work" / "paths"
        layout = paths.relocate(a.paths, harness.host_os(), guard, java, root, native)
        print("--paths %s:\n%s" % (a.paths, layout.describe()))
        guard, java, work, native = layout.guard, layout.java, layout.work, layout.native
    ctx = harness.Ctx(guard, java, work, native)
    ctx.expect_dev_mode = a.expect_dev_mode
    ctx.java_env = layout.java_env if a.paths else None
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
        for variant in harness.variants(sc):
            rid = "-".join(x for x in (sc["id"], harness.variant_id(variant)) if x)
            skip = harness.applies(sc, ctx, variant)
            if skip:
                rows.append(dict(id=rid, state="skip", baseline="—", guard=skip))
                continue
            exp = harness.expectations(sc, variant)
            base = harness.run_scenario(ctx, sc, "baseline", variant)
            guarded = harness.run_scenario(ctx, sc, "guarded", variant)
            ok_b, bv = harness.baseline_ok(sc, base, exp)
            ok_g, gv = harness.guard_ok(ctx, sc, guarded, exp)
            passed = bool(ok_b) and bool(ok_g)
            failed += 0 if passed else 1
            state = "FAIL" if not passed else ("LIMIT" if ok_g == "xfail" else "OK")
            rows.append(dict(id=rid, state=state, baseline=bv, guard=gv,
                             base_exit=base["exit"], guard_exit=guarded["exit"]))

    if a.json:  # first: the table below must not be able to cost it
        Path(a.json).write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    w = max((len(r["id"]) for r in rows), default=4)
    print("\n%-5s %-*s  %-30s  %s" % ("", w, "scenario", "без гварда", "через гвард"))
    for r in rows:
        print("%-5s %-*s  %-30s  %s" % (r["state"], w, r["id"], r["baseline"], r["guard"]))
    ran = [r for r in rows if r["state"] != "skip"]
    print("\n%d/%d scenarios passed (%d skipped)" %
          (len(ran) - failed, len(ran), len(rows) - len(ran)))

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
