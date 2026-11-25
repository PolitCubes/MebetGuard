# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Shared machinery for the MebetGuard layer e2e tests.

Every SCENARIO runs twice: baseline (plain `java`) and guarded (through the guard wrapper).

- attack  — what a cheat does. Baseline: the attack must work (its marker shows, the app lives).
            Guarded: it must be blocked — the guard closes the process with the layer's exit
            code, or neutralizes the attack while the app keeps running.
- legit   — what the game itself does (threads, JIT, a JDK library, a plain native call).
            It must work in both runs: the guard must not get in the way.

On Windows each scenario also runs at every privilege level that changes its outcome (winpriv):
the game as a standard user or as an elevated admin, and — for an attack from another program —
that program as a standard user or as an admin with SeDebugPrivilege. A variant may expect a
different answer (an admin cheat can freeze guard threads, a standard one cannot even open them).

test_layers.py turns every scenario × variant into two pytest tests (baseline / guarded); run.py
prints them as a table. The oracle is split into baseline_ok() and guard_ok() so a failure says
exactly which half broke.
"""
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EXE = ".exe" if os.name == "nt" else ""
ALL = {"windows", "linux", "macos"}
WIN = {"windows"}


def host_os():
    s = platform.system().lower()
    return {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(s, s)


if host_os() == "windows":
    import winpriv  # noqa: E402  (Windows only: privilege levels)
else:
    winpriv = None


def load_codes():
    data = json.loads((REPO / "config" / "exit_codes.json").read_text(encoding="utf-8"))
    return {r["id"]: r["code"] for r in data["codes"]}


def java_feature(java_home):
    """Feature release of a JDK from its `release` file: 25, 21, 8 (1.8.0_x)."""
    try:
        text = (Path(java_home) / "release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    m = re.search(r'JAVA_VERSION="(\d+)(?:\.(\d+))?', text)
    if not m:
        return 0
    major = int(m.group(1))
    return int(m.group(2) or 0) if major == 1 else major


class Ctx:
    def __init__(self, guard, java, work=None, untrusted_native=None):
        self.os = host_os()
        self.guard = Path(guard).resolve()
        self.java_home = Path(java).resolve()
        self.java = self.java_home / "bin" / ("java" + EXE)
        self.java_feature = java_feature(self.java_home)
        self.work = Path(work).resolve() if work else (HERE / "_work")
        self.codes = load_codes()
        self.untrusted_native = Path(untrusted_native).resolve() if untrusted_native else None
        self.classes = self.work / "classes"
        self.marker_jar = self.work / "mebet-marker.jar"
        self.native = None  # filled by build_fixtures()
        self.ffm = False    # Foreign Function & Memory API in the target (Java 22+)
        self.admin = bool(winpriv and winpriv.is_admin())
        self.no_skip = False

    def tool(self, name):
        return self.java_home / "bin" / (name + EXE)


def run_cmd(cmd, env, timeout, cwd=None):
    """Run a build tool, merging stderr into stdout. Returns (exit_code, output, timed_out)."""
    p = subprocess.Popen([str(c) for c in cmd], env=env, cwd=cwd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out, False
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        return p.returncode, out, True


class Proc:
    """A target started with the test's own token: output lines as they come, wait / kill /
    finish (winpriv.UserProc has the same shape for the standard-user token)."""

    def __init__(self, cmd, env, cwd):
        self.lines = []
        self._p = subprocess.Popen([str(c) for c in cmd], env=env, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        self.pid = self._p.pid
        self._t = threading.Thread(target=self._read, daemon=True)
        self._t.start()

    def _read(self):
        for raw in self._p.stdout:
            self.lines.append(raw.decode("utf-8", "replace"))

    def wait(self, timeout):
        try:
            self._p.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def kill(self):
        self._p.kill()
        self._p.wait()

    def finish(self):
        self._t.join(5)
        return self._p.returncode


# --- external probes (another program acting on the target) ------------------------------------

def probe_open_process(pid):
    """Another program asks for the rights an injector needs. Only opens and closes a handle —
    nothing is written into the target. Its privilege level comes from winpriv.as_other()."""
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    access = 0x0008 | 0x0020 | 0x0002  # PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
    h = k32.OpenProcess(access, 0, pid)
    if h:
        k32.CloseHandle(h)
        return "PROBE open-process granted (memory write + thread creation)"
    return "PROBE open-process denied (error %d)" % ctypes.get_last_error()


PROBES = {"open_process": probe_open_process}


# --- fixtures ------------------------------------------------------------------------------------

def build_fixtures(ctx):
    """Build the target classes, the marker agent jar and the unsigned native once."""
    ctx.work.mkdir(parents=True, exist_ok=True)
    ctx.classes.mkdir(parents=True, exist_ok=True)
    _javac(ctx, [HERE / "target" / "MebetTarget.java"], ctx.classes)
    # The FFM attacks need the final Foreign Function & Memory API (Java 22+) and a native
    # linker for the platform; 32-bit Windows JDKs have none.
    if ctx.java_feature >= 22:
        _javac(ctx, [HERE / "target" / "MebetFfm.java"], ctx.classes)
        ctx.ffm = True

    tmp = ctx.work / "marker"
    tmp.mkdir(parents=True, exist_ok=True)
    _javac(ctx, [HERE / "attacks" / "MebetMarkerAgent.java"], tmp)
    (tmp / "manifest.txt").write_text(
        "Premain-Class: MebetMarkerAgent\nAgent-Class: MebetMarkerAgent\nCan-Retransform-Classes: true\n",
        encoding="utf-8")
    r, out, _ = run_cmd([ctx.tool("jar"), "cfm", ctx.marker_jar, tmp / "manifest.txt",
                         "-C", tmp, "MebetMarkerAgent.class"], os.environ.copy(), 120)
    if r != 0:
        raise RuntimeError("jar (marker) failed:\n" + out)

    ctx.native = _build_native(ctx)
    return ctx


def _javac(ctx, sources, out_dir):
    r, out, _ = run_cmd([ctx.tool("javac"), "-d", out_dir] + list(sources), os.environ.copy(), 180)
    if r != 0:
        raise RuntimeError("javac %s failed:\n%s" % (", ".join(s.name for s in sources), out))


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


# --- launching -----------------------------------------------------------------------------------

def launch(ctx, mode, jvm_args=(), extra_env=None, action=None, iters=8, timeout=None, probe=None,
           game=None, other=None):
    """mode 'baseline' uses plain java; 'guarded' uses the guard wrapper. game / other are the
    privilege levels ("user" / "admin", Windows) of the game and of the probing program."""
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
    limit = timeout or (10 + iters)
    start = time.monotonic()
    proc = winpriv.UserProc(cmd, env, str(ctx.work)) if game == "user" else Proc(cmd, env, str(ctx.work))
    if probe:
        pid = 0
        while not pid and time.monotonic() - start < limit:
            for line in list(proc.lines):
                m = re.search(r"TARGET up pid=(\d+)", line)
                if m:
                    pid = int(m.group(1))
                    break
            else:
                if proc.wait(0.05):
                    break
        if pid:
            fn = lambda: PROBES[probe](pid)  # noqa: E731
            proc.lines.append((winpriv.as_other(other, fn) if other else fn()) + "\n")
    timed_out = not proc.wait(max(0.0, limit - (time.monotonic() - start)))
    if timed_out:
        proc.kill()
    code = proc.finish()
    return {"exit": code, "out": "".join(proc.lines), "timed_out": timed_out, "cmd": [str(c) for c in cmd]}


def has(run, text):
    return text in run["out"]


def run_scenario(ctx, sc, mode, variant=(None, None)):
    """Run one side (baseline|guarded) of a scenario at one privilege variant (game, other)."""
    s = sc["build"](ctx, ctx.native, ctx.marker_jar)
    return launch(ctx, mode, s.get("jvm_args", ()), s.get("extra_env"), s.get("action"),
                  s.get("iters", 8), sc.get("timeout"), sc.get("probe"), variant[0], variant[1])


# --- scenarios -----------------------------------------------------------------------------------
# kind:   "attack" or "legit".
# guard:  "allow" (legit: works through the guard), "neutralize" (attack: exit 0, no marker),
#         "close:<reason>[|<reason>]" (attack: the process ends with one of these codes),
#         "known_limit" (the attack gets through and that is Windows by design, e.g. an admin
#         with SeDebugPrivilege opens any process: the test is xfail, it documents the limit).
# marker: the attack worked / the legit action ran.
# proof:  regexes the guarded output must contain — the attack really was attempted there.
# privs:  Windows privilege variants — "game" (game user / admin) or "game_other" (× the other
#         program user / admin, for attacks from another program).
# expect(game, other) -> overrides of {guard, proof, baseline} for one variant; baseline
#         "works" (default) or "denied" (Windows itself stops the attack even without the guard).
# build(ctx, native, marker_jar) -> {jvm_args?, extra_env?, action?, iters?}.

def _agent(jar):
    return "-javaagent:" + str(jar)


def _sc(**kw):
    kw.setdefault("os", ALL)
    kw.setdefault("needs_native", False)
    kw.setdefault("needs_ffm", False)
    kw.setdefault("proof", [])
    kw.setdefault("privs", "game")
    return kw


def _tamper_threads(verb):
    # Admin (SeDebugPrivilege) gets past the guard's thread DACL and freezes / kills its threads:
    # the watchdog must end the game. A standard user cannot even open them: the forbidden load
    # that follows is caught as usual.
    def expect(game, other):
        if game == "admin":
            return dict(guard="close:guard_stalled", proof=[r"TARGET %s [1-9]\d* guard threads" % verb])
        return dict(guard="close:untrusted_module", proof=[r"TARGET %s 0 guard threads" % verb])
    return expect


def _dacl_expect(game, other):
    if other == "admin":
        # Windows lets an admin with SeDebugPrivilege open any process: not the DACL's job, the
        # guard's detections (watchdog, hooks, sweeps) cover what such a program does next.
        return dict(guard="known_limit", proof=[])
    if game == "admin":
        # A standard program cannot open an elevated one at all (integrity level), guard or not.
        return dict(baseline="denied")
    return {}


SCENARIOS = [
    # ---- legit: the guard must not get in the way ----------------------------------------------
    _sc(id="clean_launch", kind="legit", module="—", guard="allow",
        title="Обычный запуск без атаки", marker="TARGET did none",
        build=lambda ctx, native, jar: dict(action="none")),
    _sc(id="thread_churn", kind="legit", module="foreign_threads", guard="allow",
        title="2000 коротких Java-потоков (старт и выход через хуки)", marker="TARGET did thread-churn 2000",
        build=lambda ctx, native, jar: dict(action="thread-churn 2000")),
    _sc(id="jit_hot", kind="legit", module="foreign_exec_memory", guard="allow",
        title="Горячий цикл: JIT пишет исполняемый код JVM", marker="TARGET did jit-hot",
        build=lambda ctx, native, jar: dict(action="jit-hot 1500")),
    _sc(id="trusted_native_load", kind="legit", module="module_trust", os=WIN, guard="allow",
        title="System.load библиотеки самой Java (sunmscapi.dll)", marker="TARGET did load-native",
        build=lambda ctx, native, jar: dict(action="load-native " + str(ctx.java_home / "bin" / "sunmscapi.dll"))),
    _sc(id="ffm_benign", kind="legit", module="foreign_exec_memory", needs_ffm=True, guard="allow",
        title="Обычный нативный вызов через FFM", marker="TARGET did ffm-benign",
        build=lambda ctx, native, jar: dict(action="ffm-benign")),

    # ---- attacks: the start of the JVM -----------------------------------------------------------
    _sc(id="env_hardening_jto", kind="attack", module="env_hardening", guard="neutralize",
        title="Чужой агент через JAVA_TOOL_OPTIONS", marker="ATTACK agent premain ran",
        build=lambda ctx, native, jar: dict(extra_env={"JAVA_TOOL_OPTIONS": _agent(jar)})),
    _sc(id="env_hardening_jdk", kind="attack", module="env_hardening", guard="neutralize",
        title="Чужой агент через JDK_JAVA_OPTIONS", marker="ATTACK agent premain ran",
        build=lambda ctx, native, jar: dict(extra_env={"JDK_JAVA_OPTIONS": _agent(jar)})),
    _sc(id="jvm_agents_javaagent", kind="attack", module="jvm_agents", guard="close:foreign_agent_arg",
        title="Чужой -javaagent (Java-агент)", marker="ATTACK agent premain ran",
        build=lambda ctx, native, jar: dict(jvm_args=[_agent(jar)])),
    _sc(id="jvm_agents_agentpath", kind="attack", module="jvm_agents", needs_native=True,
        guard="close:foreign_agent_arg", title="Чужой -agentpath (нативный JVMTI-агент)",
        marker="ATTACK native Agent_OnLoad",
        build=lambda ctx, native, jar: dict(jvm_args=["-agentpath:" + str(native)])),
    # The locked dev-mode check: on a dev-mode / test-signing machine the prod build must close
    # before the JVM even starts. Only passes where the machine really is in dev mode (the CI
    # Windows runners); the e2e-windows job runs it against the prod (release) build.
    _sc(id="dev_mode", kind="attack", module="dev_mode", os=WIN, guard="close:dev_mode",
        title="Запуск prod-сборки в dev-режиме → закрытие", marker="TARGET up pid=",
        build=lambda ctx, native, jar: dict()),

    # ---- attacks: inside the running game --------------------------------------------------------
    _sc(id="module_trust_load", kind="attack", module="module_trust", os=WIN, needs_native=True,
        guard="close:untrusted_module", title="System.load неподписанной нативной библиотеки",
        marker="TARGET did load-native",
        build=lambda ctx, native, jar: dict(action="load-native " + str(native))),
    _sc(id="jvm_agent_module", kind="attack", module="jvm_agents", os=WIN, guard="close:jvm_agent_module",
        title="Модуль агентов JDK (instrument) в рантайме", marker="TARGET did load-library instrument",
        build=lambda ctx, native, jar: dict(action="load-library instrument")),
    _sc(id="foreign_exec_alloc", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True,
        guard="close:foreign_code", title="FFM: VirtualAlloc(RWX) + шелл-код из Java",
        marker="TARGET did ffm-exec-alloc",
        build=lambda ctx, native, jar: dict(action="ffm-exec-alloc")),
    _sc(id="foreign_exec_protect", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True,
        guard="close:foreign_code", title="FFM: VirtualProtect(RX) + шелл-код из Java",
        marker="TARGET did ffm-exec-protect",
        build=lambda ctx, native, jar: dict(action="ffm-exec-protect")),
    _sc(id="process_dacl_open", kind="attack", module="process_dacl", os=WIN, guard="neutralize",
        title="Чужая программа открывает процесс на запись памяти и потоки",
        marker="PROBE open-process granted", probe="open_process", proof=[r"PROBE open-process denied"],
        privs="game_other", expect=_dacl_expect,
        build=lambda ctx, native, jar: dict(action="none", iters=16)),

    # ---- attacks: on the guard itself ------------------------------------------------------------
    _sc(id="tamper_freeze_guard", kind="attack", module="guard_watchdog", os=WIN, needs_native=True,
        needs_ffm=True, guard="close:guard_stalled", timeout=60, expect=_tamper_threads("froze"),
        title="Заморозить потоки стража, затем загрузить чужой натив", marker="TARGET did ffm-freeze-guard",
        build=lambda ctx, native, jar: dict(action="ffm-freeze-guard " + str(native), iters=2)),
    _sc(id="tamper_kill_guard", kind="attack", module="guard_watchdog", os=WIN, needs_native=True,
        needs_ffm=True, guard="close:guard_stalled", timeout=60, expect=_tamper_threads("killed"),
        title="Убить потоки стража, затем загрузить чужой натив", marker="TARGET did ffm-kill-guard",
        build=lambda ctx, native, jar: dict(action="ffm-kill-guard " + str(native), iters=2)),
    _sc(id="tamper_unload_guard", kind="attack", module="module_trust", os=WIN, needs_native=True,
        needs_ffm=True, guard="close:untrusted_module", timeout=60,
        title="FreeLibrary на страже, затем загрузить чужой натив", marker="TARGET did ffm-unload-guard",
        proof=[r"TARGET called FreeLibrary on the guard [1-9]\d* times"],
        build=lambda ctx, native, jar: dict(action="ffm-unload-guard " + str(native), iters=2)),
    _sc(id="tamper_jam_sweep", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True,
        guard="close:foreign_code", timeout=90,
        title="Убить потоки посреди хука, затем RWX мимо хуков (только обход)",
        marker="TARGET did ffm-jam-sweep", proof=[r"TARGET killed [1-9]\d* threads inside MapViewOfFile"],
        build=lambda ctx, native, jar: dict(action="ffm-jam-sweep", iters=2)),
]


def variants(sc):
    """Privilege variants (game, other) of a scenario on this host. Off Windows: one, as is."""
    if host_os() != "windows":
        return [(None, None)]
    if sc["privs"] == "game_other":
        return [(g, o) for g in ("user", "admin") for o in ("user", "admin")]
    return [("user", None), ("admin", None)]


def variant_id(variant):
    game, other = variant
    if not game:
        return ""
    return "game_%s" % game + ("-other_%s" % other if other else "")


def expectations(sc, variant):
    exp = dict(guard=sc["guard"], proof=sc["proof"], baseline="works")
    if "expect" in sc:
        exp.update(sc["expect"](*variant))
    return exp


def applies(sc, ctx, variant=(None, None)):
    """None if the scenario runs here at this variant, else a reason to skip it."""
    if ctx.os not in sc["os"]:
        return "не для %s" % ctx.os
    if sc["needs_native"] and ctx.native is None:
        return "нет компилятора для неподписанного натива (передайте --untrusted-native)"
    if sc["needs_ffm"] and not ctx.ffm:
        return "нужна Java 22+ с FFM (здесь Java %d)" % ctx.java_feature
    if "admin" in variant and not ctx.admin:
        return "вариант «админ» требует, чтобы тест работал от администратора (на раннерах CI так и есть)"
    return None


def baseline_ok(sc, base, exp=None):
    """Without the guard: an attack must work, a legit action must run; the app finishes.
    exp["baseline"] == "denied": Windows itself stops this attack at this privilege variant."""
    exp = exp or dict(baseline="works")
    if base["exit"] != 0:
        return False, "приложение не завершилось чисто (exit %s)" % base["exit"]
    if not has(base, "TARGET exit"):
        return False, "приложение не доработало до конца"
    if exp["baseline"] == "denied":
        if has(base, sc["marker"]):
            return False, "ждали, что Windows сама не пустит, а атака прошла: %r" % sc["marker"]
        return True, "Windows сама не пускает (уровень целостности), приложение живо"
    what = "атака не воспроизвелась" if sc["kind"] == "attack" else "действие не выполнилось"
    if not has(base, sc["marker"]):
        return False, "%s: нет маркера %r" % (what, sc["marker"])
    return True, ("атака сработала" if sc["kind"] == "attack" else "работает") + ", приложение живо"


def _closed_line(run):
    m = re.search(r"\[Mebet\] closed: (\w+) \(code (\d+)\)", run["out"])
    return (m.group(1), int(m.group(2))) if m else None


def guard_ok(ctx, sc, guarded, exp=None):
    """Through the guard: an attack must be blocked, a legit action must still run.
    Returns (True | False | "xfail", message)."""
    exp = exp or dict(guard=sc["guard"], proof=sc["proof"])
    g = exp["guard"]
    if g == "allow":
        closed = _closed_line(guarded)
        if closed:
            return False, "страж закрыл легитимное действие: %s (code %d)" % closed
        if guarded["exit"] != 0 or not has(guarded, "TARGET exit"):
            return False, "через гвард не доработало (exit %s)" % guarded["exit"]
        if not has(guarded, sc["marker"]):
            return False, "через гвард действие не выполнилось: нет %r" % sc["marker"]
        return True, "работает, страж не мешает"

    if g == "known_limit":
        # The limit only shows when the attack really reached a running game: closed before it
        # (CI once closed the game with 209 before the probe ran), the run proves nothing either way.
        if guarded["exit"] != 0 or not has(guarded, "TARGET exit"):
            return False, "через гвард не доработало (exit %s) — ограничение не проверено" % guarded["exit"]
        if has(guarded, sc["marker"]):
            return "xfail", ("известное ограничение Windows: администратор с SeDebugPrivilege открывает "
                             "любой процесс мимо DACL — дальше его ловят другие слои")
        for rx in sc["proof"]:
            if not re.search(rx, guarded["out"]):
                return False, "атака не была проведена так, как ждали (нет %r) — проверка ничего не доказала" % rx
        return True, "не пустило даже администратора"

    if has(guarded, sc["marker"]):
        return False, "маркер атаки всё же появился: %r" % sc["marker"]
    for rx in exp["proof"]:
        if not re.search(rx, guarded["out"]):
            return False, "атака не была проведена так, как ждали (нет %r) — проверка ничего не доказала" % rx
    if g.startswith("close:"):
        reasons = g.split(":", 1)[1].split("|")
        wants = {ctx.codes[r]: r for r in reasons}
        if guarded["exit"] in wants:
            return True, "закрыт, код %d (%s)" % (guarded["exit"], wants[guarded["exit"]])
        # The prod build shows the reason window (it ignores MEBET_TEST_NO_UI) and can block on a
        # headless runner until the harness kills it: then the "[Mebet] closed" line is the
        # proof — but only if the app really stopped (it never reached its end).
        closed = _closed_line(guarded)
        if closed and closed[1] in wants and not has(guarded, "TARGET exit"):
            return True, "закрыт, код %d (%s)" % (closed[1], closed[0])
        return False, "ждали закрытие с кодом %s, получили exit %s%s" % (
            "/".join("%d (%s)" % (c, r) for c, r in wants.items()), guarded["exit"],
            "" if not closed else ", строка закрытия %s (code %d)" % closed)
    # neutralize
    if guarded["exit"] != 0 or not has(guarded, "TARGET exit"):
        return False, "ждали нейтрализацию (exit 0, приложение живо), получили exit %s" % guarded["exit"]
    return True, "нейтрализован, приложение живо"
