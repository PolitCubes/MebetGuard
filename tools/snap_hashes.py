#!/usr/bin/env python3
"""Snapshot the SHA-256 of every native library of a client profile.

ТЗ §6 «Собранный список разрешённого»: natives of the game and of mods are unsigned
(LWJGL, SDL3, OpenAL…), so the guard trusts them by SHA-256. This tool walks a client
folder as the launcher lays it out (`natives/<os>/<arch>/…` plus native libraries packed
inside jars, e.g. JNA's `com/sun/jna/win32-x86-64/jnidispatch.dll`) and writes one line
per file:

    <sha256>  <size>  <os>/<arch>  <path>

Usage:
    python3 tools/snap_hashes.py <client dir> <profile name> > config/hashes/<profile>.txt

Run it against the LaunchServer `updates/<profile>` folder for every profile after each
client update, then rebuild and re-sign the guard (ТЗ §6: updating natives = rebuild).
"""
import datetime
import hashlib
import os
import sys
import zipfile

NATIVE_EXT = (".dll", ".so", ".dylib", ".jnilib")

# Folder names used by the launcher (JVMHelper.OS / JVMHelper.ARCH) and by common jar layouts.
OS_ALIASES = {
    "mustdie": "mustdie", "windows": "mustdie", "win32": "mustdie", "win": "mustdie",
    "linux": "linux",
    "macosx": "macosx", "macos": "macosx", "darwin": "macosx", "osx": "macosx",
}
ARCH_ALIASES = {
    "x86-64": "x86-64", "x86_64": "x86-64", "amd64": "x86-64", "x64": "x86-64",
    "x86": "x86", "i386": "x86", "i686": "x86",
    "arm64": "arm64", "aarch64": "arm64",
    "arm32": "arm32", "arm": "arm32", "armhf": "arm32",
}


def classify(parts):
    """Return '<os>/<arch>' guessed from path components, or 'any/any'."""
    os_name, arch = "any", "any"
    for p in parts:
        low = p.lower()
        if low in OS_ALIASES and os_name == "any":
            os_name = OS_ALIASES[low]
            continue
        if low in ARCH_ALIASES and arch == "any":
            arch = ARCH_ALIASES[low]
            continue
        # jar layouts such as "win32-x86-64", "linux-aarch64", "darwin-x86-64"
        if "-" in low:
            head, _, tail = low.partition("-")
            if head in OS_ALIASES and tail in ARCH_ALIASES:
                return OS_ALIASES[head] + "/" + ARCH_ALIASES[tail]
    if os_name == "any":
        for p in parts:
            low = p.lower()
            if low.endswith(".dll"):
                os_name = "mustdie"
            elif low.endswith((".dylib", ".jnilib")):
                os_name = "macosx"
            elif low.endswith(".so"):
                os_name = "linux"
    return os_name + "/" + arch


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    root, profile = sys.argv[1], sys.argv[2]
    rows = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            low = name.lower()
            if low.endswith(NATIVE_EXT):
                with open(full, "rb") as fh:
                    data = fh.read()
                rows.append((hashlib.sha256(data).hexdigest(), len(data), classify(rel.split("/")), rel))
            elif low.endswith(".jar"):
                try:
                    with zipfile.ZipFile(full) as jar:
                        for info in jar.infolist():
                            if info.filename.lower().endswith(NATIVE_EXT):
                                data = jar.read(info)
                                inner = rel + "!/" + info.filename
                                rows.append((hashlib.sha256(data).hexdigest(), len(data),
                                             classify(info.filename.split("/")), inner))
                except zipfile.BadZipFile:
                    print("warning: not a zip: " + rel, file=sys.stderr)
    out = sys.stdout
    out.write("# profile: %s\n" % profile)
    out.write("# snapped: %s by tools/snap_hashes.py\n" % datetime.date.today().isoformat())
    out.write("# columns: sha256  size  os/arch  path\n")
    for sha, size, plat, rel in rows:
        out.write("%s  %d  %s  %s\n" % (sha, size, plat, rel))
    print("%d native files" % len(rows), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
