# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Shared machinery for the MebetGuard layer e2e tests.

One SCENARIO per attack: it is run twice — baseline (plain `java`, the attack must work) and
guarded (through the guard wrapper, the attack must be blocked). test_layers.py turns each
scenario into its own pytest test; run.py prints them as a table. The oracle is split into
baseline_ok() and guard_ok() so a failing test says exactly which half broke.
"""
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EXE = ".exe" if os.name == "nt" else ""
ALL = {"windows", "linux", "macos"}


def host_os():
    s = platform.system().lower()
    return {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(s, s)


def load_codes():
    data = json.loads((REPO / "config" / "exit_codes.json").read_text(encoding="utf-8"))
    return {r["id"]: r["code"] for r in data["codes"]}


class Ctx:
    def __init__(self, guard, java, work=None, untrusted_native=None):
        self.os = host_os()
        self.guard = Path(guard).resolve()
        self.java_home = Path(java).resolve()
        self.java = self.java_home / "bin" / ("java" + EXE)
        self.work = Path(work).resolve() if work else (HERE / "_work")
        self.codes = load_codes()
        self.untrusted_native = Path(untrusted_native).resolve() if untrusted_native else None
        self.classes = self.work / "classes"
        self.marker_jar = self.work / "mebet-marker.jar"
        self.native = None  # filled by build_fixtures()

    def tool(self, name):
        return self.java_home / "bin" / (name + EXE)


def run_cmd(cmd, env, timeout, cwd=None):
    """Run cmd, merging stderr into stdout. Returns (exit_code, output, timed_out)."""
    p = subprocess.Popen([str(c) for c in cmd], env=env, cwd=cwd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out, False
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        return p.returncode, out, True


# --- fixtures ------------------------------------------------------------------------------

def build_fixtures(ctx):
    """Build the target class, the marker agent jar and the unsigned native once."""
    ctx.work.mkdir(parents=True, exist_ok=True)
    ctx.classes.mkdir(parents=True, exist_ok=True)
    _javac(ctx, HERE / "target" / "MebetTarget.java", ctx.classes)

    tmp = ctx.work / "marker"
    tmp.mkdir(parents=True, exist_ok=True)
    _javac(ctx, HERE / "attacks" / "MebetMarkerAgent.java", tmp)
    (tmp / "manifest.txt").write_text(
        "Premain-Class: MebetMarkerAgent\nAgent-Class: MebetMarkerAgent\nCan-Retransform-Classes: true\n",
        encoding="utf-8")
    r, out, _ = run_cmd([ctx.tool("jar"), "cfm", ctx.marker_jar, tmp / "manifest.txt",
                         "-C", tmp, "MebetMarkerAgent.class"], os.environ.copy(), 120)
    if r != 0:
        raise RuntimeError("jar (marker) failed:\n" + out)

    ctx.native = _build_native(ctx)
    return ctx


def _javac(ctx, src, out_dir):
    r, out, _ = run_cmd([ctx.tool("javac"), "-d", out_dir, src], os.environ.copy(), 120)
    if r != 0:
        raise RuntimeError("javac %s failed:\n%s" % (src.name, out))


def _build_native(ctx):
    """The unsigned marker native (module_trust / -agentpath). Returns a path, or None when no
    toolchain is present and no override was given."""
    if ctx.untrusted_native and ctx.untrusted_native.exists():
        return ctx.untrusted_native
    src = HERE / "attacks" / "native" / "mebet_fake_cheat.c"
    out_dir = ctx.work / "native"
    out_dir.mkdir(parents=True, exist_ok=True)
    if ctx.os == "windows":
        lib = out_dir / "mebet_fake_cheat.dll"
        for cc in ("clang", "gcc"):
            if shutil.which(cc) and run_cmd([cc, "-shared", "-o", lib, src], os.environ.copy(), 120)[0] == 0:
                return lib
        if shutil.which("cl") and run_cmd(["cl", "/LD", "/nologo", src, "/Fe:" + str(lib)],
                                          os.environ.copy(), 120, cwd=out_dir)[0] == 0 and lib.exists():
            return lib
        return None
    lib = out_dir / ("libmebet_fake_cheat." + ("dylib" if ctx.os == "macos" else "so"))
    for cc in ("cc", "clang", "gcc"):
        if shutil.which(cc) and run_cmd([cc, "-shared", "-fPIC", "-o", lib, src], os.environ.copy(), 120)[0] == 0:
            return lib
    return None


# --- launching -----------------------------------------------------------------------------

def launch(ctx, mode, jvm_args=(), extra_env=None, action=None, iters=8):
    """mode 'baseline' uses plain java; 'guarded' uses the guard wrapper. Returns the run dict."""
    env = os.environ.copy()
    env["JAVA_HOME"] = str(ctx.java_home)
    env["MEBET_TEST_NO_UI"] = "1"
    if extra_env:
        env.update(extra_env)
    pre = ["-Dmebet.iters=%d" % iters]
    if action is not None:
        cmd_file = ctx.work / ("action_%s.txt" % mode)
        cmd_file.write_text(action + "\n", encoding="utf-8")
        pre.append("-Dmebet.cmd=" + str(cmd_file))
    head = ctx.guard if mode == "guarded" else ctx.java
    cmd = [head] + pre + list(jvm_args) + ["-cp", ctx.classes, "MebetTarget"]
    code, out, timed_out = run_cmd(cmd, env, timeout=10 + iters, cwd=str(ctx.work))
    return {"exit": code, "out": out, "timed_out": timed_out, "cmd": [str(c) for c in cmd]}


def has(run, text):
    return text in run["out"]


def run_scenario(ctx, sc, mode):
    """Run one side (baseline|guarded) of a scenario."""
    setup = sc["build"](ctx, ctx.native, ctx.marker_jar)
    return launch(ctx, mode, setup.get("jvm_args", ()), setup.get("extra_env"), setup.get("action"))


# --- scenarios -----------------------------------------------------------------------------
# build(ctx, native, marker_jar) -> {jvm_args?, extra_env?, action?}. os = where it applies.
# guard: "neutralize" (exit 0, no marker) or "close:<reason>" (exit = that code, no marker).

def _agent(jar):
    return "-javaagent:" + str(jar)


SCENARIOS = [
    dict(id="env_hardening_jto", module="env_hardening", os=ALL, needs_native=False,
         title="Чужой агент через JAVA_TOOL_OPTIONS", guard="neutralize",
         attack_marker="ATTACK agent premain ran",
         build=lambda ctx, native, jar: dict(extra_env={"JAVA_TOOL_OPTIONS": _agent(jar)})),
    dict(id="env_hardening_jdk", module="env_hardening", os=ALL, needs_native=False,
         title="Чужой агент через JDK_JAVA_OPTIONS", guard="neutralize",
         attack_marker="ATTACK agent premain ran",
         build=lambda ctx, native, jar: dict(extra_env={"JDK_JAVA_OPTIONS": _agent(jar)})),
    dict(id="jvm_agents_javaagent", module="jvm_agents", os=ALL, needs_native=False,
         title="Чужой -javaagent (Java-агент)", guard="close:foreign_agent_arg",
         attack_marker="ATTACK agent premain ran",
         build=lambda ctx, native, jar: dict(jvm_args=[_agent(jar)])),
    dict(id="jvm_agents_agentpath", module="jvm_agents", os=ALL, needs_native=True,
         title="Чужой -agentpath (нативный JVMTI-агент)", guard="close:foreign_agent_arg",
         attack_marker="ATTACK native Agent_OnLoad",
         build=lambda ctx, native, jar: dict(jvm_args=["-agentpath:" + str(native)])),
    dict(id="module_trust_load", module="module_trust", os={"windows"}, needs_native=True,
         title="System.load неподписанной нативной библиотеки", guard="close:untrusted_module",
         attack_marker="TARGET did load-native",
         build=lambda ctx, native, jar: dict(action="load-native " + str(native))),
    # The locked dev-mode check: on a dev-mode / test-signing machine the prod build must close
    # before the JVM even starts. Only passes where the machine really is in dev mode (the CI
    # Windows runner); the e2e-windows job runs it against the prod (release) build.
    dict(id="dev_mode", module="dev_mode", os={"windows"}, needs_native=False,
         title="Запуск prod-сборки в dev-режиме → закрытие", guard="close:dev_mode",
         attack_marker="TARGET up pid=",
         build=lambda ctx, native, jar: dict()),
]


def applies(sc, ctx):
    """None if the scenario runs here, else a reason to skip it."""
    if ctx.os not in sc["os"]:
        return "не для %s" % ctx.os
    if sc["needs_native"] and ctx.native is None:
        return "нет компилятора для неподписанного натива (передайте --untrusted-native)"
    return None


def baseline_ok(sc, base):
    """Without the guard the attack must work: its marker shows and the app finishes."""
    if base["exit"] != 0:
        return False, "приложение не завершилось чисто (exit %s)" % base["exit"]
    if not has(base, sc["attack_marker"]):
        return False, "атака не воспроизвелась: нет маркера %r" % sc["attack_marker"]
    if not has(base, "TARGET exit"):
        return False, "приложение не доработало до конца"
    return True, "атака сработала, приложение живо"


def guard_ok(ctx, sc, guarded):
    """Through the guard the attack must be blocked."""
    mark = sc["attack_marker"]
    if has(guarded, mark):
        return False, "маркер атаки всё же появился: %r" % mark
    g = sc["guard"]
    if g.startswith("close:"):
        reason = g.split(":", 1)[1]
        want = ctx.codes[reason]
        # The guard prints "[Mebet] closed: <reason> (code N)" before any reason window; the
        # prod build shows that window (ignores MEBET_TEST_NO_UI) and can block on a headless
        # runner, so accept the stderr line as proof of the close too, not only the exit code.
        closed = guarded["exit"] == want or ("closed: %s (code %d)" % (reason, want)) in guarded["out"]
        if not closed:
            return False, "ждали закрытие с кодом %d (%s), получили exit %s" % (want, reason, guarded["exit"])
        return True, "закрыт, код %d (%s)" % (want, reason)
    # neutralize
    if guarded["exit"] != 0 or not has(guarded, "TARGET exit"):
        return False, "ждали нейтрализацию (exit 0, приложение живо), получили exit %s" % guarded["exit"]
    return True, "нейтрализован, приложение живо"
