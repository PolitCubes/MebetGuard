#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""The real client, without the guard and through it: FPS, frame times, load times.

    python tests/perf/minecraft/run.py --client <updates/modern> --java <updates/java25-windows-amd64>
        --guard <MebetGuard.exe> --profile <modern.json> [--assets <updates/assets>]
        [--reps 3] [--world "New World"] [--warmup 20] [--measure 60] [--xmx 4G] [--work <dir>]

Works on a copy of the client folder (your saves and options stay as they are): the bench mod
(MebetBenchMod.java) goes into its mods, the world is restored before every run, the options say
"do not pause when the window loses focus". The client is started the way the launcher starts
it — the profile's JVM arguments, its main class and client arguments, the classpath in the order
the client's own log recorded — once with plain java, once with the guard in its place, in turn.
The mod opens the world by itself (no synthetic input: the guard drops it), warms up, turns the
camera a full circle every 6 s while every frame is timed, writes its result and closes the game.
"""
import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


def classpath(client, copy):
    """The classpath in the launcher's order: from the client's own log when it has it, else the
    libraries folder as Windows lists it, then minecraft.jar."""
    log = client / "logs" / "fml-client-latest.log"
    if log.exists():
        m = re.search(r"Java classpath at launch is (.*)", log.read_text(encoding="utf-8", errors="replace"))
        if m:
            out = []
            for p in m.group(1).strip().split(os.pathsep):
                rel = os.path.relpath(p, client)
                if not rel.startswith(".."):
                    out.append(str(copy / rel))
            if out:
                return out
    jars = []
    for root, _, files in os.walk(copy / "libraries"):
        jars += [str(Path(root) / f) for f in files if f.endswith(".jar")]
    return jars + [str(copy / "minecraft.jar")]


def prepare(a, work):
    client = Path(a.client).resolve()
    copy = work / "client"
    if not copy.exists():
        print("copying the client to", copy, flush=True)
        shutil.copytree(client, copy, ignore=shutil.ignore_patterns("logs", "crash-reports", "screenshots"))
    pristine = work / "world-pristine"
    if not pristine.exists():
        shutil.copytree(client / "saves" / a.world, pristine)
    # Options: never pause on focus loss (the pause menu would change what is drawn).
    opts = copy / "options.txt"
    lines = [l for l in opts.read_text(encoding="utf-8", errors="replace").splitlines()
             if not l.startswith(("pauseOnLostFocus:", "enableVsync:", "maxFps:"))]
    lines += ["pauseOnLostFocus:false", "enableVsync:false", "maxFps:260"]
    opts.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # The bench mod, built against the client's own Forge.
    forge = next((copy / "libraries").rglob("forge-*-universal.jar"))
    classes = work / "mod-classes"
    shutil.rmtree(classes, ignore_errors=True)
    classes.mkdir(parents=True)
    javac = Path(a.java) / "bin" / "javac.exe"
    if not javac.exists():
        javac = shutil.which("javac") or "javac"
    r = run([javac, "--release", "8", "-nowarn", "-cp", forge, "-d", classes, HERE / "MebetBenchMod.java"])
    if r.returncode != 0:
        sys.exit("javac (bench mod) failed:\n" + r.stdout.decode("utf-8", "replace"))
    jar_tool = Path(a.java) / "bin" / "jar.exe"
    if not jar_tool.exists():
        jar_tool = shutil.which("jar") or "jar"
    r = run([jar_tool, "cf", copy / "mods" / "zz-mebetbench.jar", "-C", classes, "."])
    if r.returncode != 0:
        sys.exit("jar (bench mod) failed:\n" + r.stdout.decode("utf-8", "replace"))
    return client, copy, pristine


def one(a, mode, client, copy, pristine, profile, cp, run_no):
    world = copy / "saves" / a.world
    shutil.rmtree(world, ignore_errors=True)
    shutil.copytree(pristine, world)
    result = copy / "mebet-bench-result.json"
    if result.exists():
        result.unlink()
    java_home = Path(a.java).resolve()
    head = Path(a.guard).resolve() if mode == "guarded" else java_home / "bin" / "java.exe"
    cmd = [head, "-Xmx" + a.xmx] + profile["jvmArgs"] + [
        "-Dfile.encoding=UTF-8",
        "-Djava.library.path=" + str(copy / "natives" / a.natives),
        "-Dmcbench.world=" + a.world, "-Dmcbench.warmup=%g" % a.warmup,
        "-Dmcbench.measure=%g" % a.measure, "-Dmcbench.out=" + str(result),
        "-cp", os.pathsep.join(cp), profile["mainClass"],
        "--username", "MebetBench", "--version", profile.get("version", "1.7.10"),
        "--gameDir", str(copy), "--assetsDir", str(Path(a.assets).resolve()),
        "--assetIndex", profile.get("assetIndex", "1.7.10"),
        "--uuid", "4d656265742062656e63680000000001", "--accessToken", "0",
        "--userProperties", "{}", "--userType", "legacy", "--width", "1280", "--height", "720",
    ] + profile.get("clientArgs", [])
    env = os.environ.copy()
    env["JAVA_HOME"] = str(java_home)
    env["MEBET_TEST_NO_UI"] = "1"
    t0 = time.perf_counter()
    p = subprocess.run([str(c) for c in cmd], cwd=str(copy), env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=900)
    secs = time.perf_counter() - t0
    out = p.stdout.decode("utf-8", "replace")
    (copy.parent / ("run%02d-%s.log" % (run_no, mode))).write_text(out, encoding="utf-8")
    guard_lines = [l for l in out.splitlines() if l.startswith("[Mebet]")]
    rec = json.loads(result.read_text(encoding="utf-8")) if result.exists() else {"error": "no result"}
    rec.update(exit=p.returncode, wall_s=round(secs, 1), guard=guard_lines[-6:])
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", required=True)
    ap.add_argument("--java", required=True)
    ap.add_argument("--guard", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--assets", default="")
    ap.add_argument("--natives", default="mustdie/x86-64")
    ap.add_argument("--world", default="New World")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--warmup", type=float, default=20)
    ap.add_argument("--measure", type=float, default=60)
    ap.add_argument("--xmx", default="4G")
    ap.add_argument("--work", default=str(HERE / "_work"))
    ap.add_argument("--json", default="")
    ap.add_argument("--markdown", default="")
    a = ap.parse_args()
    if not a.assets:
        a.assets = str(Path(a.client).resolve().parent / "assets")
    work = Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    profile = json.loads(Path(a.profile).read_text(encoding="utf-8"))
    client, copy, pristine = prepare(a, work)
    cp = classpath(client, copy)

    runs = {"baseline": [], "guarded": []}
    k = 0
    for rep in range(a.reps):
        for mode in (("baseline", "guarded") if rep % 2 == 0 else ("guarded", "baseline")):
            k += 1
            rec = one(a, mode, client, copy, pristine, profile, cp, k)
            runs[mode].append(rec)
            print("run %d (%s): %s" % (k, mode, json.dumps(rec, ensure_ascii=False)), flush=True)

    md = render(runs, a)
    print(md)
    if a.markdown:
        Path(a.markdown).write_text(md, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(runs, ensure_ascii=False, indent=2), encoding="utf-8")


ROWS = [("avg_fps", "средний FPS", True), ("low1_fps", "1 % low FPS", True),
        ("p50_ms", "кадр p50, мс", False), ("p99_ms", "кадр p99, мс", False),
        ("p999_ms", "кадр p99.9, мс", False), ("max_ms", "кадр максимум, мс", False),
        ("menu_ms", "до главного меню, мс", False), ("world_ms", "до входа в мир, мс", False)]


def render(runs, a):
    ok = {m: [r for r in rs if "error" not in r] for m, rs in runs.items()}
    lines = ["### Настоящий клиент: без гварда и с гвардом", "",
             "Мир «%s», прогрев %g с, замер %g с (камера — полный круг за 6 с), окно 1280×720, VSync выкл., "
             "FPS без ограничения. Медиана по удачным прогонам: без гварда %d, с гвардом %d." % (
                 a.world, a.warmup, a.measure, len(ok["baseline"]), len(ok["guarded"])), "",
             "| | без гварда | с гвардом | разница |", "|---|---:|---:|---:|"]
    for key, label, higher_better in ROWS:
        b = [r[key] for r in ok["baseline"] if key in r]
        g = [r[key] for r in ok["guarded"] if key in r]
        if not b or not g:
            continue
        mb, mg = statistics.median(b), statistics.median(g)
        diff = (mg - mb) / mb * 100 if mb else 0.0
        lines.append("| %s | %.1f | %.1f | %+.1f %% |" % (label, mb, mg, diff))
    failed = [(m, r) for m, rs in runs.items() for r in rs if "error" in r]
    if failed:
        lines += ["", "Неудачные прогоны:"]
        for m, r in failed:
            lines.append("- %s: %s (exit %s) %s" % (m, r["error"], r.get("exit"), " | ".join(r.get("guard", []))))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
