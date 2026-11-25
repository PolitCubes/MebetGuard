#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""MebetGuard end-to-end layer tests.

For every protection layer the guard has (config/modules.json), run the SAME attack against
the target JVM twice:

  * baseline  — the target is launched by plain `java`, with no guard in the process. The
                attack must WORK: its marker shows up and the app keeps running.
  * guarded   — the target is launched through the guard wrapper (MebetGuard.exe / MebetGuard),
                exactly as the real client is. The attack must be BLOCKED: the guard closes
                the process with the layer's exit code, or silently neutralizes the attack
                while the app keeps running.

A layer PASSES only when the baseline proves the attack used to work AND the guarded run
proves it no longer does. The script prints a before/after table and exits non-zero if any
layer regressed.

Usage:
  python tests/e2e/run.py --guard <MebetGuard exe> --java <JAVA_HOME> [--only id,id]
                          [--untrusted-native <lib>] [--work <dir>] [--json <out>]
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EXE = ".exe" if os.name == "nt" else ""


def host_os():
    s = platform.system().lower()
    return {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(s, s)


def load_codes():
    data = json.loads((REPO / "config" / "exit_codes.json").read_text(encoding="utf-8"))
    return {r["id"]: r["code"] for r in data["codes"]}


class Ctx:
    def __init__(self, a):
        self.os = host_os()
        self.guard = Path(a.guard).resolve()
        self.java_home = Path(a.java).resolve()
        self.java = self.java_home / "bin" / ("java" + EXE)
        self.work = Path(a.work).resolve() if a.work else (HERE / "_work")
        self.codes = load_codes()
        self.untrusted_native = Path(a.untrusted_native).resolve() if a.untrusted_native else None
        self.classes = self.work / "classes"
        self.marker_jar = self.work / "mebet-marker.jar"

    def java_tool(self, name):
        return self.java_home / "bin" / (name + EXE)


def run_cmd(cmd, env, timeout, cwd=None):
    """Run cmd, merging stderr into stdout. Returns (exit_code, output, timed_out)."""
    p = subprocess.Popen(cmd, env=env, cwd=cwd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out, False
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        return p.returncode, out, True


# --- building the fixtures -----------------------------------------------------------------

def build_target(ctx):
    ctx.classes.mkdir(parents=True, exist_ok=True)
    src = HERE / "target" / "MebetTarget.java"
    r, out, _ = run_cmd([str(ctx.java_tool("javac")), "-d", str(ctx.classes), str(src)], os.environ.copy(), 120)
    if r != 0:
        sys.exit("javac MebetTarget failed:\n" + out)


def build_marker_jar(ctx):
    tmp = ctx.work / "marker"
    tmp.mkdir(parents=True, exist_ok=True)
    src = HERE / "attacks" / "MebetMarkerAgent.java"
    r, out, _ = run_cmd([str(ctx.java_tool("javac")), "-d", str(tmp), str(src)], os.environ.copy(), 120)
    if r != 0:
        sys.exit("javac MebetMarkerAgent failed:\n" + out)
    manifest = tmp / "manifest.txt"
    manifest.write_text("Premain-Class: MebetMarkerAgent\nAgent-Class: MebetMarkerAgent\n"
                        "Can-Retransform-Classes: true\n", encoding="utf-8")
    r, out, _ = run_cmd([str(ctx.java_tool("jar")), "cfm", str(ctx.marker_jar), str(manifest),
                         "-C", str(tmp), "MebetMarkerAgent.class"], os.environ.copy(), 120)
    if r != 0:
        sys.exit("jar (marker) failed:\n" + out)


def build_untrusted_native(ctx):
    """Compile the fake-cheat native library with whatever toolchain is present, or return the
    --untrusted-native override. None means module-trust-by-load scenarios are skipped."""
    if ctx.untrusted_native and ctx.untrusted_native.exists():
        return ctx.untrusted_native
    src = HERE / "attacks" / "native" / "mebet_fake_cheat.c"
    out_dir = ctx.work / "native"
    out_dir.mkdir(parents=True, exist_ok=True)
    if ctx.os == "windows":
        lib = out_dir / "mebet_fake_cheat.dll"
        for cc in ("clang", "gcc"):
            if shutil.which(cc):
                r, o, _ = run_cmd([cc, "-shared", "-o", str(lib), str(src)], os.environ.copy(), 120)
                if r == 0 and lib.exists():
                    return lib
        if shutil.which("cl"):
            r, o, _ = run_cmd(["cl", "/LD", "/nologo", str(src), "/Fe:" + str(lib)], os.environ.copy(), 120, cwd=out_dir)
            if r == 0 and lib.exists():
                return lib
        return None
    lib = out_dir / ("libmebet_fake_cheat." + ("dylib" if ctx.os == "macos" else "so"))
    for cc in ("cc", "clang", "gcc"):
        if shutil.which(cc):
            r, o, _ = run_cmd([cc, "-shared", "-fPIC", "-o", str(lib), str(src)], os.environ.copy(), 120)
            if r == 0 and lib.exists():
                return lib
    return None


# --- launching the target ------------------------------------------------------------------

def launch(ctx, mode, jvm_args=(), extra_env=None, action=None, iters=8):
    """mode 'baseline' uses plain java; 'guarded' uses the guard wrapper. Returns the run dict."""
    env = os.environ.copy()
    env["JAVA_HOME"] = str(ctx.java_home)
    env["MEBET_TEST_NO_UI"] = "1"           # the guard shows no message box on the stand
    if extra_env:
        env.update(extra_env)
    pre = ["-Dmebet.iters=%d" % iters]
    if action is not None:
        cmd_file = ctx.work / ("action_%s.txt" % mode)
        cmd_file.write_text(action + "\n", encoding="utf-8")
        pre.append("-Dmebet.cmd=" + str(cmd_file))
    head = str(ctx.guard) if mode == "guarded" else str(ctx.java)
    cmd = [head] + pre + list(jvm_args) + ["-cp", str(ctx.classes), "MebetTarget"]
    code, out, timed_out = run_cmd(cmd, env, timeout=10 + iters, cwd=str(ctx.work))
    return {"exit": code, "out": out, "timed_out": timed_out, "cmd": cmd}


def has(run, text):
    return text in run["out"]


# --- scenarios -----------------------------------------------------------------------------
# Each scenario: id, title, module (config/modules.json), os set, the attack set-up, the text
# that proves the attack worked, and what the guard must do: close:<reason> | neutralize.

ALL = {"windows", "linux", "macos"}


def scenarios(ctx, marker_jar, native):
    agent = "-javaagent:" + str(marker_jar)
    AGENT_MARK = "ATTACK agent premain ran"
    s = []

    # env_hardening (level on): the wrapper clears the Java env vars, so a cheat agent smuggled
    # through them never loads. The guard does not close — the app runs without the agent.
    s.append(dict(
        id="env_hardening_jto", module="env_hardening", os=ALL,
        title="Чужой агент через JAVA_TOOL_OPTIONS",
        setup=dict(extra_env={"JAVA_TOOL_OPTIONS": agent}),
        attack_marker=AGENT_MARK, guard="neutralize"))
    s.append(dict(
        id="env_hardening_jdk", module="env_hardening", os=ALL,
        title="Чужой агент через JDK_JAVA_OPTIONS",
        setup=dict(extra_env={"JDK_JAVA_OPTIONS": agent}),
        attack_marker=AGENT_MARK, guard="neutralize"))

    # jvm_agents (level close): a foreign agent passed on the command line closes the client.
    s.append(dict(
        id="jvm_agents_javaagent", module="jvm_agents", os=ALL,
        title="Чужой -javaagent (Java-агент)",
        setup=dict(jvm_args=[agent]),
        attack_marker=AGENT_MARK, guard="close:foreign_agent_arg"))

    if native is not None:
        s.append(dict(
            id="jvm_agents_agentpath", module="jvm_agents", os=ALL,
            title="Чужой -agentpath (нативный JVMTI-агент)",
            setup=dict(jvm_args=["-agentpath:" + str(native)]),
            attack_marker="ATTACK native Agent_OnLoad", guard="close:foreign_agent_arg"))

        # module_trust (level close): a mod loads an unsigned native with System.load. On
        # Windows the NtCreateSection gate refuses it (210); the Linux/macOS in-process gate
        # is not wired yet (see README), so this layer is Windows-only for now.
        s.append(dict(
            id="module_trust_load", module="module_trust", os={"windows"},
            title="System.load неподписанной нативной библиотеки",
            setup=dict(action="load-native " + str(native)),
            attack_marker="TARGET did load-native", guard="close:untrusted_module"))

    return s


def oracle(ctx, sc, base, guarded):
    """Returns (passed, baseline_verdict, guard_verdict)."""
    mark = sc["attack_marker"]
    base_worked = (base["exit"] == 0 and has(base, mark) and has(base, "TARGET exit"))
    base_verdict = "атака сработала" if base_worked else (
        "НЕ воспроизвелась (exit %s, marker=%s)" % (base["exit"], has(base, mark)))

    g = sc["guard"]
    if g.startswith("close:"):
        reason = g.split(":", 1)[1]
        want = ctx.codes[reason]
        blocked = (guarded["exit"] == want and not has(guarded, mark))
        gv = ("закрыт, код %d (%s)" % (want, reason)) if blocked else (
            "НЕ закрыт как ждали (exit %s, marker=%s)" % (guarded["exit"], has(guarded, mark)))
    else:  # neutralize
        blocked = (guarded["exit"] == 0 and has(guarded, "TARGET exit") and not has(guarded, mark))
        gv = "нейтрализован, приложение живо" if blocked else (
            "НЕ нейтрализован (exit %s, marker=%s)" % (guarded["exit"], has(guarded, mark)))

    return (base_worked and blocked), base_verdict, gv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard", required=True, help="MebetGuard wrapper executable")
    ap.add_argument("--java", required=True, help="JAVA_HOME of the game Java")
    ap.add_argument("--work", default="")
    ap.add_argument("--only", default="", help="comma-separated scenario ids")
    ap.add_argument("--untrusted-native", default="")
    ap.add_argument("--json", default="")
    a = ap.parse_args()

    ctx = Ctx(a)
    ctx.work.mkdir(parents=True, exist_ok=True)
    if not ctx.guard.exists():
        sys.exit("guard not found: " + str(ctx.guard))
    if not ctx.java.exists():
        sys.exit("java not found: " + str(ctx.java))

    build_target(ctx)
    build_marker_jar(ctx)
    native = build_untrusted_native(ctx)
    if native is None:
        print("note: no toolchain for the unsigned native — module-trust-by-load scenarios skipped")

    only = {x for x in a.only.split(",") if x}
    rows, failed = [], 0
    for sc in scenarios(ctx, ctx.marker_jar, native):
        if ctx.os not in sc["os"]:
            continue
        if only and sc["id"] not in only:
            continue
        setup = sc["setup"]
        base = launch(ctx, "baseline", setup.get("jvm_args", ()), setup.get("extra_env"), setup.get("action"))
        guarded = launch(ctx, "guarded", setup.get("jvm_args", ()), setup.get("extra_env"), setup.get("action"))
        passed, bv, gv = oracle(ctx, sc, base, guarded)
        failed += 0 if passed else 1
        rows.append(dict(id=sc["id"], module=sc["module"], title=sc["title"], passed=passed,
                         baseline=bv, guard=gv, base_exit=base["exit"], guard_exit=guarded["exit"]))

    w = max((len(r["id"]) for r in rows), default=4)
    print("\n%-4s %-*s  %-28s  %s" % ("", w, "layer", "без гварда", "через гвард"))
    for r in rows:
        print("%-4s %-*s  %-28s  %s" % ("OK " if r["passed"] else "FAIL", w, r["id"], r["baseline"], r["guard"]))
    print("\n%d/%d layers passed" % (len(rows) - failed, len(rows)))

    if a.json:
        Path(a.json).write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
