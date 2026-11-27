# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Awkward paths for the layer e2e (--paths <variant>). Players keep the game in folders like
C:\\Users\\Иван\\AppData\\Roaming\\.politcubes or D:\\Игры\\Мой клиент (копия) & моды.

relocate() puts the guard (a copy of its own two files), the game Java (a real copy: a junction
would hide the name from the guard) and the work dir — the client dir: the working directory, -cp,
the marker agent, the unsigned native — into folders named by the variant, and every selected
scenario then runs from there, without the guard and through it, with the usual oracle.

Variants (every OS):
  cyrillic  — "Игра Тест".
  specials  — spaces and & ( ) [ ] ! % ^ ' ; , = # + ~; on Linux and macOS also $ \\ * ?.
              Windows: the guard's folder also so long that MebetGuard.dll is at 254 characters.
  beyond    — characters outside the Windows ANSI code page: an emoji, CJK, Cyrillic, "Ł" (which
              Windows quietly turns into "L").
  ukrainian — "Ґанок Їжак Єнот іграшка": the letters Russian does not have (Ґ Є І Ї). In the
              code page of Ukrainian and Russian Windows (1251), not in the CI runners' (1252).
  latin     — German and Spanish: "Größe Straße Äpfel Übung ñandú Canción ¿Qué tal ¡Sí". In the
              runners' code page: there they must work everywhere — guard, Java and client folder.

On Windows the guard also gets JAVA_HOME with the letters of the variant's folders in the other case
("äPFEL" for "Äpfel"): the same folder to Windows, and the guard compares paths as Windows does,
not only ASCII letters.

Who gets which characters. The guard's folder gets all of them: plain java never sees it, so the
guard must work from it whatever its name (macOS: no "=" — the JVM cuts -agentpath:<path>=<options>
there and there is no other way to hand it the library; the guard closes with unsupported_path).
The Java folder and the client folder get only what plain java itself accepts — otherwise the
baseline fails and the run proves nothing about the guard:
  - Windows: only letters of the ANSI code page. JLI hands every path to Java through it, so on a
    Western-European Windows (the CI runners: 1252) plain java cannot start from a Cyrillic Java
    folder or find classes in a Cyrillic client folder at all. There the variant's letters stay in
    the guard's folder, the Java and client folders get the code page's own letters, and
    test_paths.py checks the rest: a Java folder and a client folder beyond the code page.
  - no ";" in the Java folder on Windows (java.home is split on it), none in the client folder
    either (-cp); no ":" anywhere on Linux/macOS (the same separator there);
  - no "=" in the client folder: plain java cuts -javaagent:<jar>=<options> there;
  - no "\\" in the client folder on Linux/macOS: JDK_JAVA_OPTIONS reads it as an escape;
  - no emoji outside the guard's folder: java on a UTF-8 Windows loses it in -cp.
"""
import codecs
import os
import shutil
from pathlib import Path

VARIANTS = ("cyrillic", "specials", "beyond", "ukrainian", "latin")
CYRILLIC = "Игра Тест"
UKRAINIAN = "Ґанок Їжак Єнот іграшка"
LATIN = "Größe Straße Äpfel Übung ñandú Canción ¿Qué tal ¡Sí"
BEYOND = "Игра 🎮 中文"              # an emoji is beyond every legacy code page
LETTERS = ["Größe", "Türkçe", "Čeština", "Ελληνικά", "日本語", "中文", "Игра"]
AGENT_LIB = {"windows": "MebetGuard.dll", "linux": "libMebetGuard.so", "macos": "libMebetGuard.dylib"}
DLL_PATH_LEN = 254  # MebetGuard.dll with the linker's default manifest stopped loading at 252
JAVA_SKIP = {"jmods", "src.zip", "demo", "sample", "man"}


def ansi_code_page():
    """The process ANSI code page (Windows), None elsewhere."""
    if os.name != "nt":
        return None
    import ctypes
    return ctypes.windll.kernel32.GetACP()


def fits(text, cp=None):
    """The text survives the ANSI code page unchanged — no "?", no look-alike (best fit).
    Always true off Windows: Linux and macOS hand paths over as bytes."""
    cp = ansi_code_page() if cp is None else cp
    if cp is None or cp == 65001:
        return True
    try:
        codecs.code_page_encode(cp, text, "strict")  # WC_NO_BEST_FIT_CHARS underneath
        return True
    except UnicodeEncodeError:
        return False


def u16len(text):
    """Length as Windows counts it (UTF-16 units: an emoji is two)."""
    return len(text.encode("utf-16-le")) // 2


def own_letters():
    """Letters of this machine's code page (Windows): what its players' folders are named in."""
    return " ".join([w for w in LETTERS if fits(w)][:2]) or "Game"


def names(variant, host_os):
    """{guard, java, client} folder names of a variant on this OS (see the module doc)."""
    win, mac = host_os == "windows", host_os == "macos"

    def _or_own(name, rest):  # Windows: the code page's own letters where it cannot express name
        return name + rest if not win or fits(name) else own_letters() + rest

    if variant == "cyrillic":
        return dict(guard=CYRILLIC + " страж", java=_or_own(CYRILLIC, " java"), client=_or_own(CYRILLIC, ""))
    if variant == "specials":
        common = "(1) & [2] !%^',#+~"
        posix = "" if win else " $\\*?"
        return dict(guard="Game " + common + (" ;" if mac else " ;=") + posix,
                    java="Java " + common + " =" + ("" if win else " ;") + posix,
                    client="Client " + common + ("" if win else " ; $*?"))
    if variant == "beyond":
        return dict(guard=BEYOND + " Łódź страж", java=_or_own("Игра 中文", " java"), client=_or_own("Игра 中文", ""))
    if variant == "ukrainian":
        return dict(guard=UKRAINIAN + " охорона", java=_or_own(UKRAINIAN, " java"), client=_or_own(UKRAINIAN, ""))
    if variant == "latin":
        return dict(guard=LATIN + " Wächter", java=_or_own(LATIN, " java"), client=_or_own(LATIN, ""))
    raise ValueError("unknown --paths variant %r (%s)" % (variant, ", ".join(VARIANTS)))


def beyond_name(variant):
    """Windows: a folder name of the variant the ANSI code page cannot express, or None."""
    if ansi_code_page() is None:
        return None
    name = {"cyrillic": CYRILLIC, "beyond": BEYOND, "ukrainian": UKRAINIAN, "latin": LATIN}.get(variant)
    return name if name and not fits(name) else None


def short_name_fits(path):
    """The 8.3 form of path exists and survives the code page (Windows): what the guard falls back to."""
    import ctypes
    buf = ctypes.create_unicode_buffer(32768)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 32768)
    return bool(n) and fits(buf.value)


def copy_java(src, dst):
    """A real copy of the JDK (jmods and sources left out); reused while it matches the source."""
    src, dst = Path(src), Path(dst)
    if (dst / "release").exists() and (dst / "release").read_bytes() == (src / "release").read_bytes():
        return dst
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True, ignore=lambda d, n: [x for x in n if x in JAVA_SKIP])
    return dst


def other_case(text):
    """Every letter in the other case where that is one letter both ways ("Äpfel" → "äPFEL"); "ß", the
    Turkish dotless "ı" and the like stay, so the name stays the same name to the file system."""
    out = []
    for c in text:
        o = c.swapcase()
        out.append(o if len(o) == 1 and o.swapcase() == c else c)
    return "".join(out)


class Layout:
    def __init__(self, variant, guard, java, work, native, root, java_src, java_env=None):
        self.variant, self.guard, self.java, self.work, self.native = variant, guard, java, work, native
        self.root, self.java_src = root, java_src
        self.java_env = java_env  # JAVA_HOME as handed to the game, when it differs from `java`

    def describe(self):
        rows = [("guard", self.guard), ("java", self.java), ("work", self.work), ("native", self.native)]
        if self.java_env:
            rows.append(("JAVA_HOME", self.java_env))
        return "\n".join("  %-9s %s" % (k, v) for k, v in rows)


def relocate(variant, host_os, guard, java, root, native=None):
    """Copies the guard's two files and the JDK into the variant's folders under root/<variant>;
    the work dir (and a copy of the unsigned native, when given) goes into its client folder."""
    guard, java = Path(guard).resolve(), Path(java).resolve()
    root = Path(root).resolve() / variant
    root.mkdir(parents=True, exist_ok=True)
    n = names(variant, host_os)
    gname = n["guard"]
    if host_os == "windows" and variant == "specials":
        # MebetGuard.dll (and MebetGuard.exe) at DLL_PATH_LEN characters: still under MAX_PATH, so
        # any launcher can start it.
        pad = DLL_PATH_LEN - u16len(str(root)) - 1 - u16len(gname) - 1 - len(AGENT_LIB["windows"])
        if pad < 2:
            raise RuntimeError("--paths specials: the work folder is too long for a %d-character guard path: %s"
                               % (DLL_PATH_LEN, root))
        gname += " " + "x" * (pad - 1)
    gdir = root / gname
    if gdir.exists():
        shutil.rmtree(gdir)
    gdir.mkdir(parents=True)
    # Only the guard's own files: anything else next to it closes the game (extra_file, 207).
    for f in (guard.name, AGENT_LIB[host_os]):
        shutil.copy2(guard.parent / f, gdir / f)
    java_copy = copy_java(java, root / n["java"])
    work = root / n["client"]
    work.mkdir(parents=True, exist_ok=True)
    native_copy = None
    if native:
        native = Path(native).resolve()
        (work / "native").mkdir(exist_ok=True)
        native_copy = work / "native" / native.name
        shutil.copy2(native, native_copy)
    # Windows: JAVA_HOME in the other case — the same folder to Windows (and to plain java, which
    # does not read it), and the guard must find it the same.
    java_env = str(root / other_case(n["java"])) if host_os == "windows" else None
    return Layout(variant, gdir / guard.name, java_copy, work, native_copy, root, java, java_env)
