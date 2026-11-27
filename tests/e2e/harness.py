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


def java_arch(java_home):
    """x86 / x64 / arm64 of a JDK from its `release` file (OS_ARCH), "" when unknown."""
    try:
        text = (Path(java_home) / "release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r'OS_ARCH="([^"]+)"', text)
    a = m.group(1).lower() if m else ""
    if a in ("x86_64", "amd64"):
        return "x64"
    if a in ("x86", "i386", "i486", "i586", "i686"):
        return "x86"
    if a in ("aarch64", "arm64"):
        return "arm64"
    return ""


def pe_arch(path):
    """x86 / x64 / arm64 of a PE file by its machine type, "" when it is not one."""
    try:
        data = Path(path).read_bytes()[:4096]
        off = int.from_bytes(data[0x3C:0x40], "little")
        if data[:2] != b"MZ" or data[off:off + 4] != b"PE\0\0":
            return ""
        machine = int.from_bytes(data[off + 4:off + 6], "little")
    except (OSError, ValueError):
        return ""
    return {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, "")


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
        self.expect_dev_mode = False  # --expect-dev-mode: a release build on a dev-mode machine
        self.java_env = None          # JAVA_HOME as handed to the game, when not java_home itself (paths.py)

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
        self.handle = int(getattr(self._p, "_handle", 0))  # Windows: the parent's own process handle
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

def probe_open_process(pid, proc=None):
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


HOLD_SECONDS = 35  # longer than every "guard thread is silent" limit of the watchdog


def probe_hold_process(pid, proc):
    """The whole game is paused and let go again: Suspend / Resume in Process Explorer or Resource
    Monitor, a launcher that pauses the game, a dump tool. Done with the handle the parent got
    when it started the game. Nothing in the game is touched: every thread stops and continues."""
    import ctypes
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
    ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
    status = ntdll.NtSuspendProcess(proc.handle)
    if status != 0:
        return "PROBE hold failed (NtSuspendProcess 0x%08X)" % (status & 0xFFFFFFFF)
    time.sleep(HOLD_SECONDS)
    ntdll.NtResumeProcess(proc.handle)
    return "PROBE process held for %d s and resumed" % HOLD_SECONDS


def probe_remote_code(pid, proc):
    """An administrator's program (SeDebugPrivilege: what no DACL keeps out) writes executable code
    into the game, past every hook in it: only the guard's memory sweep can find it. First waits until
    the game has killed its own threads inside a hooked call (ffm-jam-sweep), which once left the
    sweep waiting for those calls for ever. The code is never run: being there is the attack."""
    import ctypes
    deadline = time.monotonic() + 60
    while not any("TARGET killed" in line for line in list(proc.lines)):
        if time.monotonic() > deadline or proc.wait(0.05):
            return "PROBE remote-code: the game never got to kill its threads"
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    def write():
        h = k32.OpenProcess(0x0008 | 0x0020, 0, pid)  # PROCESS_VM_OPERATION | PROCESS_VM_WRITE
        if not h:
            return "PROBE remote-code: open denied (error %d)" % ctypes.get_last_error()
        try:
            addr = k32.VirtualAllocEx(h, None, 4096, 0x3000, 0x40)  # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            if not addr:
                return "PROBE remote-code: VirtualAllocEx failed (error %d)" % ctypes.get_last_error()
            done = ctypes.c_size_t(0)
            k32.WriteProcessMemory(h, addr, b"\xc3", 1, ctypes.byref(done))  # ret
            return "PROBE remote-code written at 0x%x" % addr
        finally:
            k32.CloseHandle(h)
    return winpriv.as_other("admin", write)


def _k32():
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k32.OpenThread.restype = ctypes.c_void_p
    k32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k32.SuspendThread.restype = ctypes.c_uint32
    k32.SuspendThread.argtypes = [ctypes.c_void_p]
    k32.ResumeThread.restype = ctypes.c_uint32
    k32.ResumeThread.argtypes = [ctypes.c_void_p]
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    k32.Thread32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k32.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    return k32


def _thread_ids(k32, pid):
    import ctypes

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32), ("th32ThreadID", ctypes.c_uint32),
                    ("th32OwnerProcessID", ctypes.c_uint32), ("tpBasePri", ctypes.c_int32),
                    ("tpDeltaPri", ctypes.c_int32), ("dwFlags", ctypes.c_uint32)]
    snap = k32.CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
    out = []
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    ok = k32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            out.append(te.th32ThreadID)
        te.dwSize = ctypes.sizeof(te)
        ok = k32.Thread32Next(snap, ctypes.byref(te))
    k32.CloseHandle(snap)
    return out


def _wait_line(proc, rx, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for line in list(proc.lines):
            m = re.search(rx, line)
            if m:
                return m
        if proc.wait(0.05):
            return None
    return None


def probe_hold_all_but_spinner(pid, proc):
    """Every thread of the game but one is held — the guard's too (an administrator's program, past the
    guard's thread DACL): what NtSuspendProcess leaves when a thread being created slips past it. The
    one left running keeps calling hooked functions (ffm-hook-spinner); let go, the game must go on."""
    m = _wait_line(proc, r"TARGET spinner tid=(\d+)")
    if not m:
        return "PROBE hold-all-but-one: the spinner never started"
    spinner = int(m.group(1))
    k32 = _k32()

    def hold():
        held = []
        for tid in _thread_ids(k32, pid):
            if tid == spinner:
                continue
            h = k32.OpenThread(0x0002, 0, tid)  # THREAD_SUSPEND_RESUME
            if h and k32.SuspendThread(h) != 0xFFFFFFFF:
                held.append(h)
            elif h:
                k32.CloseHandle(h)
        time.sleep(HOLD_SECONDS)
        for h in held:
            k32.ResumeThread(h)
            k32.CloseHandle(h)
        return "PROBE held %d threads but the spinner for %d s and let them go" % (len(held), HOLD_SECONDS)
    return winpriv.as_other("admin", hold)


def probe_remote_code_moving(pid, proc):
    """An administrator's program writes a region of executable memory into the game past every hook, and
    keeps it moving: a new region every 40 ms, the previous one freed — each gone before the sweep can
    look at it a second time. Being found once must be enough to close."""
    k32 = _k32()

    def move():
        import ctypes
        h = k32.OpenProcess(0x0008 | 0x0020, 0, pid)  # PROCESS_VM_OPERATION | PROCESS_VM_WRITE
        if not h:
            return "PROBE remote-code-moving: open denied (error %d)" % ctypes.get_last_error()
        moves, prev = 0, None
        try:
            end = time.monotonic() + 20
            while time.monotonic() < end:
                addr = k32.VirtualAllocEx(h, None, 4096, 0x3000, 0x40)  # MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
                if addr:
                    done = ctypes.c_size_t(0)
                    k32.WriteProcessMemory(h, addr, b"\xc3", 1, ctypes.byref(done))
                    if prev:
                        k32.VirtualFreeEx(h, prev, 0, 0x8000)  # MEM_RELEASE
                    prev = addr
                    moves += 1
                if proc.wait(0.04):
                    break
        finally:
            k32.CloseHandle(h)
        return "PROBE remote-code moved %d times" % moves
    return winpriv.as_other("admin", move)


PROBES = {"open_process": probe_open_process, "hold_process": probe_hold_process, "remote_code": probe_remote_code,
          "hold_all_but_spinner": probe_hold_all_but_spinner, "remote_code_moving": probe_remote_code_moving}


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
        # Built for the game's Java, not for this machine: a 32-bit JVM cannot load an x64 DLL, and
        # every "the attack works" baseline then failed. Whatever a compiler made is checked by its
        # PE machine type; one that does not fit is not used.
        lib = out_dir / "mebet_fake_cheat.dll"
        arch = java_arch(ctx.java_home)
        targets = {"x86": "i686-pc-windows-msvc", "x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}
        tries = []
        if arch in targets:
            tries.append(["clang", "--target=" + targets[arch], "-shared", "-o", lib, src])
        tries.append(["gcc"] + (["-m32"] if arch == "x86" else []) + ["-shared", "-o", lib, src])
        for cmd in tries:
            if lib.exists():
                lib.unlink()
            if shutil.which(cmd[0]) and run_cmd(cmd, os.environ.copy(), 120)[0] == 0 and pe_arch(lib) == arch:
                return lib
        if shutil.which("cl") and run_cmd(["cl", "/LD", "/nologo", src, "/Fe:" + str(lib)],
                                          os.environ.copy(), 120, cwd=out_dir)[0] == 0 and pe_arch(lib) == arch:
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
    env["JAVA_HOME"] = str(ctx.java_env or ctx.java_home)
    env["MEBET_TEST_NO_UI"] = "1"
    if extra_env:
        env.update(extra_env)
    # Reports and error reports off: a test run must never send anything, whatever DSN the build has.
    pre = ["-Dmebet.reports=false", "-Dmebet.errors=false", "-Dmebet.iters=%d" % iters]
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
            fn = lambda: PROBES[probe](pid, proc)  # noqa: E731
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


def _agent_env(jar):
    """The same option for JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS: both are split on spaces, so a
    path with a space (a checkout under "Program Files", a user name with one) must be quoted —
    with forward slashes, because inside quotes JDK_JAVA_OPTIONS reads a backslash as an escape."""
    path = str(jar)
    return _agent(jar) if " " not in path else '-javaagent:"%s"' % path.replace("\\", "/")


def _sc(**kw):
    kw.setdefault("os", ALL)
    kw.setdefault("needs_native", False)
    kw.setdefault("needs_ffm", False)
    kw.setdefault("proof", [])
    kw.setdefault("privs", "game")
    kw.setdefault("ingame", False)         # the attack runs inside the started game (an action)
    kw.setdefault("needs_dev_mode", False)
    kw.setdefault("needs_admin", False)    # the test itself must run as an administrator (its probe)
    kw.setdefault("corrupts_jvm", False)   # the attack breaks the JVM (TerminateThread): no clean exit
    return kw


def _tamper_threads(verb):
    # Admin (SeDebugPrivilege) gets past the guard's thread DACL and freezes / kills its threads:
    # the watchdog must end the game. A standard user cannot even open them: the forbidden load
    # that follows is caught as usual.
    def expect(game, other):
        if game == "admin":
            # The close line too: the thread that would print it starts in the guard module and is
            # frozen or killed with the rest, and the launcher log must still say why.
            return dict(guard="close:guard_stalled", proof=[r"TARGET %s [1-9]\d* guard threads" % verb,
                                                            r"\[Mebet\] closed: guard_stalled \(code 225\)"])
        return dict(guard="close:untrusted_module", proof=[r"TARGET %s 0 guard threads" % verb])
    return expect


def _dacl_expect(game, other):
    if other == "admin":
        # Windows lets an admin with SeDebugPrivilege open any process: not the DACL's job, the
        # guard's detections (watchdog, hooks, sweeps) cover what such a program does next.
        return dict(guard="known_limit", proof=[])
    # The other program as the same user (or as an elevated admin without SeDebugPrivilege):
    # without the guard Windows lets it in, with the guard only the DACL can keep it out.
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
    # The whole process paused for longer than the watchdog's limits and resumed: nobody stopped
    # the guard's threads on their own, so the game must go on.
    _sc(id="process_hold", kind="legit", module="guard_watchdog", os=WIN, guard="allow", timeout=90,
        title="Пауза всего процесса на %d с и продолжение" % HOLD_SECONDS, marker="PROBE process held",
        probe="hold_process", build=lambda ctx, native, jar: dict(action="none", iters=40)),
    # Libraries of the game's own Java loaded and unloaded all the time while the memory sweep
    # runs: an image the load hook is still registering is not a hidden one.
    _sc(id="native_load_churn", kind="legit", module="hidden_images", os=WIN, needs_ffm=True, guard="allow",
        timeout=120, title="Библиотеки самой Java грузятся и выгружаются без остановки (45 с)",
        marker="TARGET did ffm-load-churn",
        build=lambda ctx, native, jar: dict(action="ffm-load-churn 45", iters=2)),
    # A thread that slipped past the hold keeps calling hooks while every other thread, the guard's too,
    # stands: the whole game is held, nobody stopped the guard on its own.
    _sc(id="whole_game_held", kind="legit", module="guard_watchdog", os=WIN, needs_ffm=True, needs_admin=True,
        guard="allow", timeout=120, probe="hold_all_but_spinner", marker="PROBE held",
        title="Пауза всей игры, кроме одного потока, зовущего хуки (%d с), и продолжение" % HOLD_SECONDS,
        build=lambda ctx, native, jar: dict(action="ffm-hook-spinner 50", iters=2)),
    # A library loaded fine whose file can no longer be opened (permissions changed, a share dropped):
    # it was judged when it loaded.
    _sc(id="module_file_unreadable", kind="legit", module="module_trust", os=WIN, guard="allow", timeout=60,
        title="Файл загруженной библиотеки стал нечитаемым (права сменились)", marker="TARGET did unreadable-module",
        build=lambda ctx, native, jar: dict(action="unreadable-module " + str(ctx.java_home / "bin" / "sunmscapi.dll"))),
    # The icon or the version of an unsigned file, read as a file dialog does: the file is mapped as an
    # image that can run no code (LoadLibraryEx AS_IMAGE_RESOURCE) — no module to judge.
    _sc(id="resource_read_unsigned", kind="legit", module="module_trust", os=WIN, needs_ffm=True, needs_native=True,
        guard="allow", title="Ресурсы неподписанного файла (иконка, версия): LoadLibraryEx AS_IMAGE_RESOURCE",
        marker="TARGET did ffm-resource-read",
        build=lambda ctx, native, jar: dict(action="ffm-resource-read " + str(native))),

    # ---- attacks: the start of the JVM -----------------------------------------------------------
    # The proof is the variable gone from the game: the Linux/macOS guard starts the JVM through
    # JLI_Launch, which never reads JDK_JAVA_OPTIONS, so "no agent ran" alone proves nothing there.
    _sc(id="env_hardening_jto", kind="attack", module="env_hardening", guard="neutralize",
        proof=[r"TARGET env JAVA_TOOL_OPTIONS unset"],
        title="Чужой агент через JAVA_TOOL_OPTIONS", marker="ATTACK agent premain ran",
        build=lambda ctx, native, jar: dict(extra_env={"JAVA_TOOL_OPTIONS": _agent_env(jar)})),
    _sc(id="env_hardening_jdk", kind="attack", module="env_hardening", guard="neutralize",
        proof=[r"TARGET env JDK_JAVA_OPTIONS unset"],
        title="Чужой агент через JDK_JAVA_OPTIONS", marker="ATTACK agent premain ran",
        build=lambda ctx, native, jar: dict(extra_env={"JDK_JAVA_OPTIONS": _agent_env(jar)})),
    _sc(id="jvm_agents_javaagent", kind="attack", module="jvm_agents", guard="close:foreign_agent_arg",
        title="Чужой -javaagent (Java-агент)", marker="ATTACK agent premain ran",
        build=lambda ctx, native, jar: dict(jvm_args=[_agent(jar)])),
    _sc(id="jvm_agents_agentpath", kind="attack", module="jvm_agents", needs_native=True,
        guard="close:foreign_agent_arg", title="Чужой -agentpath (нативный JVMTI-агент)",
        marker="ATTACK native Agent_OnLoad",
        build=lambda ctx, native, jar: dict(jvm_args=["-agentpath:" + str(native)])),
    # The locked dev-mode check: on a dev-mode / test-signing machine the prod build must close
    # before the JVM even starts. Only passes where the machine really is in dev mode (the CI
    # Windows runners); the e2e-windows job runs it against the prod (release) build. With any
    # other build or machine it cannot pass, so it runs only when asked for (--expect-dev-mode):
    # a full local run would otherwise never be green.
    # The prod build ignores MEBET_TEST_NO_UI and shows its reason window: nobody on the runner
    # dismisses it, so this also proves that a close before the worker exists ends the process by
    # itself (close_window_max_ms) instead of waiting for ever.
    _sc(id="dev_mode", kind="attack", module="dev_mode", os=WIN, guard="close:dev_mode", needs_dev_mode=True,
        timeout=100, title="Запуск prod-сборки в dev-режиме → закрытие", marker="TARGET up pid=",
        proof=[r"\[Mebet\] the reason window was not closed in \d+ s"],
        build=lambda ctx, native, jar: dict()),

    # ---- attacks: inside the running game --------------------------------------------------------
    _sc(id="module_trust_load", kind="attack", module="module_trust", os=WIN, needs_native=True, ingame=True,
        guard="close:untrusted_module", title="System.load неподписанной нативной библиотеки",
        marker="TARGET did load-native",
        build=lambda ctx, native, jar: dict(action="load-native " + str(native))),
    # The close with the reason window left open (no MEBET_TEST_NO_UI) and nobody to dismiss it:
    # the game keeps running behind the window for 75 s, and the guard must end the process
    # itself, with the code of the reason, when the time for a close is up.
    _sc(id="close_window_timeout", kind="attack", module="guard_watchdog", os=WIN, needs_native=True, ingame=True,
        guard="close:untrusted_module", timeout=120,
        title="Окно причины никто не закрыл: процесс завершается сам, с кодом причины",
        marker="TARGET did load-native", proof=[r"\[Mebet\] the reason window was not closed in \d+ s"],
        build=lambda ctx, native, jar: dict(action="load-native " + str(native), iters=300,
                                            extra_env={"MEBET_TEST_NO_UI": ""})),
    _sc(id="jvm_agent_module", kind="attack", module="jvm_agents", os=WIN, guard="close:jvm_agent_module", ingame=True,
        title="Модуль агентов JDK (instrument) в рантайме", marker="TARGET did load-library instrument",
        build=lambda ctx, native, jar: dict(action="load-library instrument")),
    _sc(id="foreign_exec_alloc", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True, ingame=True,
        guard="close:foreign_code", title="FFM: VirtualAlloc(RWX) + шелл-код из Java",
        marker="TARGET did ffm-exec-alloc",
        build=lambda ctx, native, jar: dict(action="ffm-exec-alloc")),
    _sc(id="foreign_exec_protect", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True, ingame=True,
        guard="close:foreign_code", title="FFM: VirtualProtect(RX) + шелл-код из Java",
        marker="TARGET did ffm-exec-protect",
        build=lambda ctx, native, jar: dict(action="ffm-exec-protect")),
    # Doors past the six hooks of the ТЗ — their Ex variants, an unmap they did not see, a handle that
    # does not say whose process it is — each walked through before the next periodic sweep (every
    # 5 s): the game exits right after the marker ("ffm-quick-" actions), so only a hook that refuses
    # at the call itself stops them.
    _sc(id="ex_exec_alloc", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True, ingame=True,
        guard="close:foreign_code", marker="TARGET did ffm-quick-alloc2",
        title="FFM: VirtualAlloc2(RWX) (NtAllocateVirtualMemoryEx) + шелл-код, выход до обхода",
        build=lambda ctx, native, jar: dict(action="ffm-quick-alloc2")),
    _sc(id="ex_image_map", kind="attack", module="module_trust", os=WIN, needs_ffm=True, needs_native=True,
        ingame=True, guard="close:untrusted_module", marker="TARGET did ffm-quick-map-image",
        title="FFM: образ неподписанной DLL через CreateFileMapping2 + MapViewOfFile3 (Ex), выход до обхода",
        build=lambda ctx, native, jar: dict(action="ffm-quick-map-image " + str(native))),
    _sc(id="stale_unmap_exec", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True, ingame=True,
        guard="close:foreign_code", marker="TARGET did ffm-quick-stale-unmap",
        title="FFM: образ доверенной DLL снят UnmapViewOfFile, на его адресе шелл-код, выход до обхода",
        build=lambda ctx, native, jar: dict(action="ffm-quick-stale-unmap")),
    _sc(id="limited_handle_exec", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True, ingame=True,
        guard="close:foreign_code", marker="TARGET did ffm-quick-limited-handle",
        title="FFM: VirtualAllocEx(RWX) через хэндл своего процесса без права запроса, выход до обхода",
        build=lambda ctx, native, jar: dict(action="ffm-quick-limited-handle")),
    _sc(id="image_page_protect", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True, ingame=True,
        guard="close:foreign_code", marker="TARGET did ffm-quick-image-cave",
        title="FFM: страница кода jvm.dll сделана RWX, свой код в её хвосте, выход до обхода",
        build=lambda ctx, native, jar: dict(action="ffm-quick-image-cave")),
    _sc(id="overwrite_cached_dll", kind="attack", module="module_trust", os=WIN, needs_ffm=True, needs_native=True,
        ingame=True, guard="close:untrusted_module", marker="TARGET did ffm-quick-overwrite",
        proof=[r"TARGET first load allowed"],
        title="FFM: DLL Microsoft выгружена и перезаписана на месте неподписанной того же размера",
        build=lambda ctx, native, jar: dict(action="ffm-quick-overwrite " + str(native))),
    # Code written from outside and kept moving (probe remote_code_moving): found once, closed.
    _sc(id="foreign_exec_moving", kind="attack", module="foreign_exec_memory", os=WIN, ingame=True, needs_admin=True,
        guard="close:foreign_code", timeout=60, probe="remote_code_moving", marker="TARGET exit",
        proof=[r"PROBE remote-code moved [1-9]\d* times"],
        title="Чужая программа пишет исполняемую память в игру и двигает её — поймать за один обход",
        build=lambda ctx, native, jar: dict(action="none", iters=160)),
    _sc(id="process_dacl_open", kind="attack", module="process_dacl", os=WIN, guard="neutralize",
        title="Чужая программа открывает процесс на запись памяти и потоки",
        marker="PROBE open-process granted", probe="open_process", proof=[r"PROBE open-process denied"],
        privs="game_other", expect=_dacl_expect,
        build=lambda ctx, native, jar: dict(action="none", iters=16)),

    # ---- attacks: on the guard itself ------------------------------------------------------------
    _sc(id="tamper_freeze_guard", kind="attack", module="guard_watchdog", os=WIN, needs_native=True, ingame=True,
        needs_ffm=True, guard="close:guard_stalled", timeout=60, expect=_tamper_threads("froze"),
        title="Заморозить потоки стража, затем загрузить чужой натив", marker="TARGET did ffm-freeze-guard",
        build=lambda ctx, native, jar: dict(action="ffm-freeze-guard " + str(native), iters=2)),
    _sc(id="tamper_kill_guard", kind="attack", module="guard_watchdog", os=WIN, needs_native=True, ingame=True,
        needs_ffm=True, guard="close:guard_stalled", timeout=60, expect=_tamper_threads("killed"),
        title="Убить потоки стража, затем загрузить чужой натив", marker="TARGET did ffm-kill-guard",
        build=lambda ctx, native, jar: dict(action="ffm-kill-guard " + str(native), iters=2)),
    _sc(id="tamper_unload_guard", kind="attack", module="module_trust", os=WIN, needs_native=True, ingame=True,
        needs_ffm=True, guard="close:untrusted_module", timeout=60,
        title="FreeLibrary на страже, затем загрузить чужой натив", marker="TARGET did ffm-unload-guard",
        proof=[r"TARGET called FreeLibrary on the guard [1-9]\d* times"],
        build=lambda ctx, native, jar: dict(action="ffm-unload-guard " + str(native), iters=2)),
    # Then the code comes from outside (probe remote_code): past every hook, so only the sweep can see it.
    _sc(id="tamper_jam_sweep", kind="attack", module="foreign_exec_memory", os=WIN, needs_ffm=True, ingame=True,
        needs_admin=True, corrupts_jvm=True, guard="close:foreign_code", timeout=90, probe="remote_code",
        title="Убить потоки посреди хука, затем чужая программа пишет код в игру (только обход)",
        marker="TARGET did ffm-jam-sweep", proof=[r"TARGET killed [1-9]\d* threads inside MapViewOfFile",
                                                  r"PROBE remote-code written at 0x[0-9a-f]+"],
        build=lambda ctx, native, jar: dict(action="ffm-jam-sweep", iters=2)),
]


def variants(sc):
    """Privilege variants (game, other) of a scenario on this host. Off Windows: one, as is."""
    if host_os() != "windows":
        return [(None, None)]
    if sc["privs"] == "game_other":
        # Not (admin game, standard-user program): a medium-integrity program never gets these
        # rights on an elevated process, guard or not, so that variant proved nothing about the
        # guard. An elevated admin without SeDebugPrivilege does get them — but for the guard's DACL.
        return [("user", "user"), ("user", "admin_nodebug"), ("user", "admin"),
                ("admin", "admin_nodebug"), ("admin", "admin")]
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
    if sc["needs_dev_mode"] and not ctx.expect_dev_mode:
        return "только для prod-сборки на машине в dev-режиме (запускается с --expect-dev-mode)"
    if sc["needs_native"] and ctx.native is None:
        return "нет компилятора для неподписанного натива (передайте --untrusted-native)"
    if sc["needs_ffm"] and not ctx.ffm:
        return "нужна Java 22+ с FFM (здесь Java %d)" % ctx.java_feature
    if sc["needs_admin"] and not ctx.admin:
        return "сценарию нужен тест от администратора (на раннерах CI так и есть)"
    if any(v and v.startswith("admin") for v in variant) and not ctx.admin:
        return "вариант «админ» требует, чтобы тест работал от администратора (на раннерах CI так и есть)"
    return None


def baseline_ok(sc, base, exp=None):
    """Without the guard: an attack must work, a legit action must run; the app finishes.
    exp["baseline"] == "denied": Windows itself stops this attack at this privilege variant."""
    exp = exp or dict(baseline="works")
    if sc["corrupts_jvm"] and exp.get("baseline", "works") == "works":
        # TerminateThread leaves the JVM's own bookkeeping broken, so its exit code and whether it
        # reaches "TARGET exit" are the attack's doing, not the app's. The attack is proven to have
        # worked by its marker and its proof; the clean-exit checks do not apply.
        if not has(base, sc["marker"]):
            return False, "атака не воспроизвелась: нет маркера %r" % sc["marker"]
        for rx in exp.get("proof") or sc["proof"]:
            if not re.search(rx, base["out"]):
                return False, "атака не доказана (нет %r)" % rx
        return True, "атака сработала (JVM повреждена TerminateThread)"
    if base["exit"] != 0:
        return False, "приложение не завершилось чисто (exit %s)" % base["exit"]
    if not has(base, "TARGET exit"):
        return False, "приложение не доработало до конца"
    if exp["baseline"] == "denied":
        if has(base, sc["marker"]):
            return False, "ждали, что Windows сама не пустит, а атака прошла: %r" % sc["marker"]
        for rx in exp.get("proof") or sc["proof"]:
            if not re.search(rx, base["out"]):
                return False, "атака не была проведена (нет %r) — проверка ничего не доказала" % rx
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
    # An attack from inside the game proves something only if the game got as far as starting it:
    # a guard that refuses the JVM's own library exits with the very same code before main().
    if sc["ingame"] and not has(guarded, "TARGET action: "):
        return False, ("игра закрыта раньше, чем атака началась (нет «TARGET action:», exit %s) — "
                       "проверка ничего не доказала" % guarded["exit"])
    for rx in exp["proof"]:
        if not re.search(rx, guarded["out"]):
            return False, "атака не была проведена так, как ждали (нет %r) — проверка ничего не доказала" % rx
    if g.startswith("close:"):
        reasons = g.split(":", 1)[1].split("|")
        wants = {ctx.codes[r]: r for r in reasons}
        # By the exit code of a process that ended by itself — never by the close line alone: a
        # guard that printed it and then hung (a reason window nobody dismissed, say) is broken,
        # and the harness's own kill must not count as a close.
        if guarded["exit"] in wants and not guarded["timed_out"]:
            return True, "закрыт, код %d (%s)" % (guarded["exit"], wants[guarded["exit"]])
        closed = _closed_line(guarded)
        return False, "ждали закрытие с кодом %s, получили exit %s%s%s" % (
            "/".join("%d (%s)" % (c, r) for c, r in wants.items()), guarded["exit"],
            " (не завершился сам, остановлен по таймауту)" if guarded["timed_out"] else "",
            "" if not closed else ", строка закрытия %s (code %d)" % closed)
    # neutralize
    if guarded["exit"] != 0 or not has(guarded, "TARGET exit"):
        return False, "ждали нейтрализацию (exit 0, приложение живо), получили exit %s" % guarded["exit"]
    return True, "нейтрализован, приложение живо"
