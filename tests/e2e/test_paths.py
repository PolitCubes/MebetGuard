# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Folders the Windows ANSI code page cannot express (--paths cyrillic | beyond, Windows).

JLI hands every path to Java in the ANSI code page. On a Western-European Windows (the CI runners:
1252) "Игра Тест" or an emoji becomes "?": plain java cannot start from such a Java folder at all
(exit 2, "could not find java.dll") and cannot find its classes in such a client folder (exit 1).
The scenarios of test_layers.py run where plain java can (paths.py); these tests check that where
it cannot, the guard does no worse and says why:

- the Java folder: with an 8.3 name the code page can express, the game runs (the guard loads
  jli.dll by it); without one (8.3 names off on the volume, or removed — administrator only), the
  guard closes with unsupported_path (226). Never a hang behind JLI's own message box — what it
  did before.
- the client folder: the guard ends exactly as plain java does, with its exit code, without a close
  of its own and without the game having started.

    pytest tests/e2e -k beyond_code_page --paths cyrillic --guard <MebetGuard.exe> --java <JAVA_HOME>
"""
import copy
import shutil
import subprocess

import pytest

import harness
import paths


def _skip(ctx, why):
    if ctx.no_skip:
        pytest.fail(why)
    pytest.skip(why)


def _beyond(ctx):
    """The variant's folder name the code page cannot express."""
    if ctx.os != "windows":
        _skip(ctx, "только Windows: Linux и macOS отдают пути Java байтами, без кодовой страницы")
    if not ctx.layout:
        _skip(ctx, "только с --paths cyrillic | beyond")
    name = paths.beyond_name(ctx.layout.variant)
    if name is None:
        _skip(ctx, "кодовая страница ANSI (%s) выражает имена варианта %s — путь за её пределами здесь не получить"
              % (paths.ansi_code_page(), ctx.layout.variant))
    return name


def _show(what, base, g):
    print("[%s] без гварда: exit %s; через гвард: exit %s" % (what, base["exit"], g["exit"]))
    for line in g["out"].splitlines():
        if "[Mebet] closed" in line or "TARGET" in line or "Error" in line:
            print("    " + line.strip())


def _plain_java_cannot(base):
    # Or the folder is not beyond the code page after all and the run proves nothing.
    assert base["exit"] != 0 and not harness.has(base, "TARGET up"), \
        "обычная java запустилась из этой папки — проверка ничего не доказывает\n" + base["out"]


def _java_beyond(ctx, suffix=" java"):
    name = _beyond(ctx)
    java = paths.copy_java(ctx.layout.java_src, ctx.layout.root / (name + suffix))
    c = copy.copy(ctx)
    c.java_home, c.java = java, java / "bin" / "java.exe"
    # JAVA_HOME is this folder now — not the layout's own Java folder in the other case (paths.py),
    # which the guard would happily run from.
    c.java_env = None
    return c


def _check_java(c, expect_runs):
    base = harness.launch(c, "baseline", action="none")
    _plain_java_cannot(base)
    g = harness.launch(c, "guarded", action="none")
    _show("java_home_beyond", base, g)
    out = g["out"]
    assert not g["timed_out"], ("страж не завершился сам (окно JLI «could not find java.dll»?), exit %s\n%s"
                                % (g["exit"], out))
    if expect_runs:
        assert g["exit"] == 0 and harness.has(g, "TARGET exit") and "[Mebet] closed" not in out, \
            "у папки есть имя 8.3 — игра должна была запуститься через него (exit %s)\n%s" % (g["exit"], out)
    else:
        code = c.codes["unsupported_path"]
        assert g["exit"] == code and "[Mebet] closed: unsupported_path (code %d)" % code in out, \
            "ждали закрытие unsupported_path (%d), получили exit %s\n%s" % (code, g["exit"], out)


def test_java_home_beyond_code_page(ctx):
    """As the volume makes it: with an 8.3 name the game runs, without one the guard closes (226)."""
    c = _java_beyond(ctx)
    _check_java(c, paths.short_name_fits(c.java_home / "bin"))


def test_java_home_beyond_code_page_no_short_name(ctx):
    """A folder like it with its 8.3 name removed (fsutil, administrator): the guard must close (226).
    A copy of its own: stripped on the shared one, the name stays gone in a reused work folder, and
    the test above would no longer try the 8.3 way at all."""
    c = _java_beyond(ctx, " java nosn")
    if not ctx.admin:
        _skip(ctx, "снять имя 8.3 может только администратор (на раннерах CI так и есть)")
    folder = c.java_home
    if paths.short_name_fits(folder / "bin"):
        r = subprocess.run(["fsutil", "file", "setshortname", str(folder), ""], capture_output=True)  # "" removes it
        if paths.short_name_fits(folder / "bin"):
            pytest.fail("не удалось снять имя 8.3 у %s: %s" % (folder, (r.stdout + r.stderr).decode("mbcs", "replace")))
    _check_java(c, False)


def test_client_dir_beyond_code_page(ctx):
    """The client folder (working directory, -cp) beyond the code page: as plain java, no worse."""
    name = _beyond(ctx)
    c = copy.copy(ctx)
    c.work = ctx.layout.root / (name + " client")
    c.classes = c.work / "classes"
    if c.classes.exists():
        shutil.rmtree(c.classes)
    shutil.copytree(ctx.classes, c.classes)
    base = harness.launch(c, "baseline", action="none")
    _plain_java_cannot(base)
    g = harness.launch(c, "guarded", action="none")
    _show("client_dir_beyond", base, g)
    assert not g["timed_out"], "страж не завершился сам, exit %s\n%s" % (g["exit"], g["out"])
    assert not harness.has(g, "TARGET up"), "через гвард игра запустилась там, где обычная java не смогла\n" + g["out"]
    assert "[Mebet] closed" not in g["out"] and g["exit"] == base["exit"], \
        ("через гвард ждали тот же исход, что у обычной java (exit %s), получили exit %s\n%s"
         % (base["exit"], g["exit"], g["out"]))
