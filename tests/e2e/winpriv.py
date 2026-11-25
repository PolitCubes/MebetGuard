# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Windows privilege levels for the e2e tests.

admin — the test process's own token. On GitHub runners it is an elevated administrator with
        SeDebugPrivilege on: with it Windows opens any process or thread past its DACL.
user  — a standard-user version of that token (CreateRestrictedToken with LUA_TOKEN):
        Administrators deny-only, every privilege but SeChangeNotify dropped, medium integrity.
        What a player's game, and an ordinary program next to it, run with.

The game is started at one of the levels (UserProc for "user"); a probe from "another program"
runs at one of them too (as_other) — so a scenario is checked for game admin / user × other side
admin / user. Imported on Windows only.
"""
import ctypes
import subprocess
import threading
from ctypes import wintypes as wt

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)

TOKEN_ALL_ACCESS = 0xF01FF
DISABLE_MAX_PRIVILEGE, LUA_TOKEN = 0x1, 0x4
WIN_BUILTIN_ADMINISTRATORS_SID, WIN_MEDIUM_LABEL_SID = 26, 67
TOKEN_INTEGRITY_LEVEL, SE_GROUP_INTEGRITY = 25, 0x20
STARTF_USESTDHANDLES = 0x100
CREATE_UNICODE_ENVIRONMENT, CREATE_NO_WINDOW = 0x400, 0x08000000
WAIT_OBJECT_0 = 0
NUL_CHAR = chr(0)
NEWLINE = b"\x0a"


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


class LUID(ctypes.Structure):
    _fields_ = [("Low", wt.DWORD), ("High", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wt.BOOL)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD),
                ("dwThreadId", wt.DWORD)]


def _proto(fn, res, *args):
    fn.restype, fn.argtypes = res, list(args)
    return fn


_GetCurrentProcess = _proto(_k32.GetCurrentProcess, wt.HANDLE)
_CloseHandle = _proto(_k32.CloseHandle, wt.BOOL, wt.HANDLE)
_CreatePipe = _proto(_k32.CreatePipe, wt.BOOL, ctypes.POINTER(wt.HANDLE), ctypes.POINTER(wt.HANDLE),
                     ctypes.POINTER(SECURITY_ATTRIBUTES), wt.DWORD)
_SetHandleInformation = _proto(_k32.SetHandleInformation, wt.BOOL, wt.HANDLE, wt.DWORD, wt.DWORD)
_CreateFileW = _proto(_k32.CreateFileW, wt.HANDLE, wt.LPCWSTR, wt.DWORD, wt.DWORD,
                      ctypes.POINTER(SECURITY_ATTRIBUTES), wt.DWORD, wt.DWORD, wt.HANDLE)
_ReadFile = _proto(_k32.ReadFile, wt.BOOL, wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                   ctypes.c_void_p)
_WaitForSingleObject = _proto(_k32.WaitForSingleObject, wt.DWORD, wt.HANDLE, wt.DWORD)
_TerminateProcess = _proto(_k32.TerminateProcess, wt.BOOL, wt.HANDLE, wt.UINT)
_GetExitCodeProcess = _proto(_k32.GetExitCodeProcess, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.DWORD))
_OpenProcessToken = _proto(_adv.OpenProcessToken, wt.BOOL, wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE))
_CreateWellKnownSid = _proto(_adv.CreateWellKnownSid, wt.BOOL, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                             ctypes.POINTER(wt.DWORD))
_GetLengthSid = _proto(_adv.GetLengthSid, wt.DWORD, ctypes.c_void_p)
_CreateRestrictedToken = _proto(_adv.CreateRestrictedToken, wt.BOOL, wt.HANDLE, wt.DWORD, wt.DWORD,
                                ctypes.POINTER(SID_AND_ATTRIBUTES), wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                ctypes.c_void_p, ctypes.POINTER(wt.HANDLE))
_SetTokenInformation = _proto(_adv.SetTokenInformation, wt.BOOL, wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                              wt.DWORD)
_CreateProcessAsUserW = _proto(_adv.CreateProcessAsUserW, wt.BOOL, wt.HANDLE, wt.LPCWSTR, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD, ctypes.c_void_p, wt.LPCWSTR,
                               ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION))
_ImpersonateLoggedOnUser = _proto(_adv.ImpersonateLoggedOnUser, wt.BOOL, wt.HANDLE)
_RevertToSelf = _proto(_adv.RevertToSelf, wt.BOOL)
_LookupPrivilegeValueW = _proto(_adv.LookupPrivilegeValueW, wt.BOOL, wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID))
_AdjustTokenPrivileges = _proto(_adv.AdjustTokenPrivileges, wt.BOOL, wt.HANDLE, wt.BOOL,
                                ctypes.POINTER(TOKEN_PRIVILEGES), wt.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES),
                                ctypes.POINTER(wt.DWORD))


def _check(ok, what):
    if not ok:
        raise OSError("%s failed: Windows error %d" % (what, ctypes.get_last_error()))


def is_admin():
    """The test process runs as an elevated administrator (CI runners do; a normal desktop
    session does not)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


_user_token = None


def user_token():
    """A standard-user primary token derived from ours (built once)."""
    global _user_token
    if _user_token:
        return _user_token
    own = wt.HANDLE()
    _check(_OpenProcessToken(_GetCurrentProcess(), TOKEN_ALL_ACCESS, ctypes.byref(own)), "OpenProcessToken")
    admins = ctypes.create_string_buffer(68)
    n = wt.DWORD(68)
    _check(_CreateWellKnownSid(WIN_BUILTIN_ADMINISTRATORS_SID, None, admins, ctypes.byref(n)), "CreateWellKnownSid")
    deny = (SID_AND_ATTRIBUTES * 1)(SID_AND_ATTRIBUTES(ctypes.cast(admins, ctypes.c_void_p), 0))
    tok = wt.HANDLE()
    _check(_CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 1, deny, 0, None, 0, None,
                                  ctypes.byref(tok)), "CreateRestrictedToken")
    medium = ctypes.create_string_buffer(68)
    n = wt.DWORD(68)
    _check(_CreateWellKnownSid(WIN_MEDIUM_LABEL_SID, None, medium, ctypes.byref(n)), "CreateWellKnownSid(medium)")
    label = TOKEN_MANDATORY_LABEL(SID_AND_ATTRIBUTES(ctypes.cast(medium, ctypes.c_void_p), SE_GROUP_INTEGRITY))
    _check(_SetTokenInformation(tok, TOKEN_INTEGRITY_LEVEL, ctypes.byref(label),
                                ctypes.sizeof(label) + _GetLengthSid(medium)), "SetTokenInformation(integrity)")
    _CloseHandle(own)
    _user_token = tok
    return tok


def set_debug_privilege(enable):
    """Switch SeDebugPrivilege in this process's token. Returns whether it was on before, or None
    when the token does not hold it (not an administrator)."""
    tok = wt.HANDLE()
    if not _OpenProcessToken(_GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(tok)):
        return None
    try:
        luid = LUID()
        if not _LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return None
        new = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, 0x2 if enable else 0)))
        old, size = TOKEN_PRIVILEGES(), wt.DWORD(0)
        ok = _AdjustTokenPrivileges(tok, False, ctypes.byref(new), ctypes.sizeof(old), ctypes.byref(old),
                                    ctypes.byref(size))
        if not ok or ctypes.get_last_error() == 1300:  # ERROR_NOT_ALL_ASSIGNED: no such privilege
            return None
        return bool(old.PrivilegeCount and old.Privileges[0].Attributes & 0x2)
    finally:
        _CloseHandle(tok)


def as_other(level, fn):
    """Run fn() as another program at the given level: "user" impersonates the standard-user
    token on this thread; "admin" turns SeDebugPrivilege on for the call."""
    if level == "user":
        _check(_ImpersonateLoggedOnUser(user_token()), "ImpersonateLoggedOnUser")
        try:
            return fn()
        finally:
            _RevertToSelf()
    was = set_debug_privilege(True)
    try:
        return fn()
    finally:
        if was is False:
            set_debug_privilege(False)


class UserProc:
    """A target started with the standard-user token: its output lines as they come, wait / kill /
    finish (the same shape as harness.Proc)."""

    def __init__(self, cmd, env, cwd):
        self.lines = []
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
        r, w = wt.HANDLE(), wt.HANDLE()
        _check(_CreatePipe(ctypes.byref(r), ctypes.byref(w), ctypes.byref(sa), 0), "CreatePipe")
        _SetHandleInformation(r, 1, 0)  # the read end stays ours
        nul = _CreateFileW("NUL", 0x80000000, 3, ctypes.byref(sa), 3, 0, None)
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = STARTF_USESTDHANDLES
        si.hStdInput, si.hStdOutput, si.hStdError = nul, w, w
        block = "".join("%s=%s%s" % (k, v, NUL_CHAR) for k, v in sorted(env.items())) + NUL_CHAR
        envbuf = (ctypes.c_wchar * len(block))(*block)
        cmdbuf = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(c) for c in cmd]))
        pi = PROCESS_INFORMATION()
        ok = _CreateProcessAsUserW(user_token(), None, cmdbuf, None, None, True,
                                   CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, envbuf,
                                   str(cwd) if cwd else None, ctypes.byref(si), ctypes.byref(pi))
        err = ctypes.get_last_error()
        _CloseHandle(w)
        _CloseHandle(nul)
        if not ok:
            _CloseHandle(r)
            raise OSError("CreateProcessAsUser failed: Windows error %d" % err)
        _CloseHandle(pi.hThread)
        self._h, self._r, self.pid = pi.hProcess, r, pi.dwProcessId
        self._t = threading.Thread(target=self._read, daemon=True)
        self._t.start()

    def _read(self):
        buf = ctypes.create_string_buffer(65536)
        n = wt.DWORD(0)
        pending = b""
        while _ReadFile(self._r, buf, 65536, ctypes.byref(n), None) and n.value:
            pending += buf.raw[:n.value]
            while NEWLINE in pending:
                line, pending = pending.split(NEWLINE, 1)
                self.lines.append(line.decode("utf-8", "replace") + "\n")
        if pending:
            self.lines.append(pending.decode("utf-8", "replace"))

    def wait(self, timeout):
        """True if the process ended within timeout seconds."""
        return _WaitForSingleObject(self._h, int(max(timeout, 0) * 1000)) == WAIT_OBJECT_0

    def kill(self):
        _TerminateProcess(self._h, 1)
        _WaitForSingleObject(self._h, 5000)

    def finish(self):
        """Exit code (unsigned, as subprocess reports it on Windows) once the output is drained."""
        code = wt.DWORD(0)
        _GetExitCodeProcess(self._h, ctypes.byref(code))
        self._t.join(5)
        _CloseHandle(self._h)
        _CloseHandle(self._r)
        return code.value
