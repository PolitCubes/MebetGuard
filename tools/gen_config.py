#!/usr/bin/env python3
"""Turn config/*.json into C++ tables that are compiled into the guard.

ТЗ §3: module levels and all lists are baked into the build; nothing is read from
disk at runtime. Unknown fields or values are a build error, so config and code are
always built together.

Usage:
    gen_config.py --config <dir> --out <dir> --kind release|test --os windows|linux|macos
                  --arch x64|x86|arm64|universal --version <x.y.z> [--commit <sha>]

Writes:
    <out>/mebet_config.hpp      — modules, options, exit reasons, reporting, build info
    <out>/mebet_trust_data.hpp  — roots (DER), publishers, signers, denylist, native hashes
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys

LEVELS = ("off", "report", "close", "on")
ROOT_CLASSES = ("public", "ms_ivr")
DENY_KINDS = ("leaf_sha256", "issuer_serial", "publisher_file", "file_sha256")


class ConfigError(Exception):
    pass


def fail(msg):
    raise ConfigError(msg)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check_keys(obj, where, required, optional=()):
    if not isinstance(obj, dict):
        fail("%s: expected an object" % where)
    allowed = set(required) | set(optional) | {"$comment"}
    for k in obj:
        if k not in allowed:
            fail("%s: unknown field '%s'" % (where, k))
    for k in required:
        if k not in obj:
            fail("%s: missing field '%s'" % (where, k))


def ident(s, where):
    if not re.fullmatch(r"[a-z][a-z0-9_]*", s):
        fail("%s: '%s' is not a lower_snake_case identifier" % (where, s))
    return s


def norm_name(s):
    """Same rule as mebet::strings::normalize_name: ASCII letters lowered, ASCII digits
    kept, other ASCII (space, punctuation) dropped, non-ASCII kept as is."""
    out = []
    for ch in s:
        o = ord(ch)
        if o < 128:
            if ch.isalpha():
                out.append(ch.lower())
            elif ch.isdigit():
                out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def c_str(s):
    """Narrow C++ string literal; non-ASCII is escaped as \\u and becomes UTF-8 because the
    execution character set is UTF-8 (MSVC /utf-8, GCC and Clang by default)."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif 32 <= o < 127:
            out.append(ch)
        elif o < 32:
            out.append("\\%03o" % o)
        elif o <= 0xFFFF:
            out.append("\\u%04x" % o)
        else:
            out.append("\\U%08x" % o)
    out.append('"')
    return "".join(out)


def w_str(s):
    return "L" + c_str(s)


def bytes_init(b):
    return ", ".join("0x%02x" % x for x in b)


def hex32(s, where):
    s = s.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", s):
        fail("%s: '%s' is not a SHA-256 hex string" % (where, s))
    return bytes.fromhex(s)


def read_pem(path):
    lines = []
    inside = False
    with open(path, encoding="ascii") as fh:
        for line in fh:
            line = line.strip()
            if line == "-----BEGIN CERTIFICATE-----":
                inside = True
                continue
            if line == "-----END CERTIFICATE-----":
                break
            if inside:
                lines.append(line)
    if not lines:
        fail("%s: no certificate" % path)
    return base64.b64decode("".join(lines))


def gen_modules(cfg, kind):
    check_keys(cfg, "modules.json", ["modules", "options"])
    mods = []
    seen = set()
    for i, m in enumerate(cfg["modules"]):
        where = "modules.json modules[%d]" % i
        check_keys(m, where, ["id", "title", "section", "release", "test"], ["locked"])
        mid = ident(m["id"], where)
        if mid in seen:
            fail("%s: duplicate id %s" % (where, mid))
        seen.add(mid)
        for k in ("release", "test"):
            if m[k] not in LEVELS:
                fail("%s: level '%s' must be one of %s" % (where, m[k], LEVELS))
        if m["release"] == "off":
            fail("%s: the release build enables every module (ТЗ §3); 'off' is only for test" % where)
        if m.get("locked") and (m["release"] != "close" or m["test"] != "close"):
            fail("%s: a locked module closes in every build" % where)
        mods.append((mid, m["title"], m[kind], bool(m.get("locked"))))
    if "dev_mode" not in seen:
        fail("modules.json: dev_mode is mandatory")
    for mid, _, level, locked in mods:
        if mid == "dev_mode" and (level != "close" or not locked):
            fail("modules.json: dev_mode must be locked to 'close' (ТЗ §8)")
    opts = []
    for name, o in cfg["options"].items():
        if name == "$comment":
            continue
        where = "modules.json options.%s" % name
        ident(name, where)
        check_keys(o, where, ["value", "why"])
        v = o["value"]
        if isinstance(v, bool):
            opts.append("inline constexpr bool %s = %s;" % (name, "true" if v else "false"))
        elif isinstance(v, int):
            if v < 0:
                fail("%s: negative" % where)
            opts.append("inline constexpr unsigned %s = %du;" % (name, v))
        else:
            fail("%s: value must be bool or non-negative int" % where)
    return mods, opts


def gen_reasons(cfg):
    check_keys(cfg, "exit_codes.json", ["codes"])
    out = []
    ids, codes = set(), set()
    for i, c in enumerate(cfg["codes"]):
        where = "exit_codes.json codes[%d]" % i
        check_keys(c, where, ["id", "code", "title_ru", "title_en", "ru", "en"])
        rid = ident(c["id"], where)
        code = c["code"]
        if not isinstance(code, int) or not (200 <= code <= 239):
            fail("%s: code must be in 200..239" % where)
        if rid in ids or code in codes:
            fail("%s: duplicate id or code" % where)
        ids.add(rid)
        codes.add(code)
        out.append(c)
    for required in ("internal_error", "agent_integrity", "untrusted_module", "dev_mode"):
        if required not in ids:
            fail("exit_codes.json: missing required reason %s" % required)
    return out


def gen_roots(cfg, config_dir):
    check_keys(cfg, "roots.json", ["roots"])
    roots = []
    seen = set()
    for i, r in enumerate(cfg["roots"]):
        where = "roots.json roots[%d]" % i
        check_keys(r, where, ["id", "class", "file", "sha256", "name"])
        rid = ident(r["id"], where)
        if rid in seen:
            fail("%s: duplicate id" % where)
        seen.add(rid)
        if r["class"] not in ROOT_CLASSES:
            fail("%s: class must be one of %s" % (where, ROOT_CLASSES))
        der = read_pem(os.path.join(config_dir, r["file"]))
        digest = hashlib.sha256(der).digest()
        if digest != hex32(r["sha256"], where):
            fail("%s: SHA-256 of %s does not match the declared value" % (where, r["file"]))
        roots.append({"id": rid, "class": r["class"], "der": der, "sha256": digest, "name": r["name"]})
    if len(roots) > 32:
        fail("roots.json: at most 32 roots (root_mask is 32 bits)")
    return roots


def gen_publishers(cfg, roots):
    check_keys(cfg, "publishers.json", ["publishers"])
    root_index = {r["id"]: i for i, r in enumerate(roots)}
    pubs, signers = [], []
    seen = set()
    for i, p in enumerate(cfg["publishers"]):
        where = "publishers.json publishers[%d]" % i
        check_keys(p, where, ["id", "name", "group", "signers", "roots", "added", "review_by"],
                   ["covers", "cert_observations", "min_product_version"])
        pid = ident(p["id"], where)
        if pid in seen:
            fail("%s: duplicate id" % where)
        seen.add(pid)
        mask = 0
        for rid in p["roots"]:
            if rid not in root_index:
                fail("%s: unknown root '%s'" % (where, rid))
            mask |= 1 << root_index[rid]
        mpv = p.get("min_product_version")
        if mpv is not None and not re.fullmatch(r"\d+(\.\d+){0,3}", mpv):
            fail("%s: min_product_version must look like 1.2.3" % where)
        if not p["signers"]:
            fail("%s: at least one signer" % where)
        for j, s in enumerate(p["signers"]):
            sw = "%s signers[%d]" % (where, j)
            check_keys(s, sw, ["cn", "o"], ["issuer_cn"])
            if norm_name(s["o"]) == norm_name("Open Source Developer") and "issuer_cn" not in s:
                fail("%s: Certum Open Source signers need issuer_cn (ТЗ §6)" % sw)
            signers.append((len(pubs), norm_name(s["cn"]), norm_name(s["o"]),
                            norm_name(s["issuer_cn"]) if "issuer_cn" in s else None))
        obs = []
        for o in p.get("cert_observations", []):
            o = o.strip().upper()
            if not re.fullmatch(r"[0-9A-F]{4,64}", o):
                fail("%s: cert_observations entries are hex serial prefixes" % where)
            obs.append(o.lstrip("0") or "0")
        pubs.append({"id": pid, "name": p["name"], "group": p["group"], "mask": mask, "mpv": mpv, "obs": obs})
    return pubs, signers


def gen_denylist(cfg):
    check_keys(cfg, "denylist.json", ["entries"])
    out = []
    for i, e in enumerate(cfg["entries"]):
        where = "denylist.json entries[%d]" % i
        kind = e.get("kind")
        if kind not in DENY_KINDS:
            fail("%s: kind must be one of %s" % (where, DENY_KINDS))
        if kind == "leaf_sha256" or kind == "file_sha256":
            check_keys(e, where, ["id", "kind", "sha256", "reason"])
            out.append((e["id"], kind, None, None, None, hex32(e["sha256"], where)))
        elif kind == "issuer_serial":
            check_keys(e, where, ["id", "kind", "issuer_cn", "serial", "reason"])
            serial = e["serial"].strip().upper()
            if not re.fullmatch(r"[0-9A-F]+", serial):
                fail("%s: serial must be hex" % where)
            out.append((e["id"], kind, norm_name(e["issuer_cn"]), serial.lstrip("0") or "0", None, None))
        else:
            check_keys(e, where, ["id", "kind", "cn", "o", "file", "reason"])
            out.append((e["id"], kind, norm_name(e["cn"]), norm_name(e["o"]), e["file"].lower(), None))
    return out


def gen_hashes(config_dir, target_os, arch):
    os_dir = {"windows": "mustdie", "linux": "linux", "macos": "macosx"}[target_os]
    arches = {"x64": ["x86-64"], "x86": ["x86"], "arm64": ["arm64"],
              "universal": ["x86-64", "arm64"]}[arch]
    rows = {}
    profiles = []
    hdir = os.path.join(config_dir, "hashes")
    for name in sorted(os.listdir(hdir)):
        if not name.endswith(".txt"):
            continue
        profiles.append(name[:-4])
        with open(os.path.join(hdir, name), encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 3)
                if len(parts) != 4:
                    fail("hashes/%s:%d: expected 'sha256 size os/arch path'" % (name, ln))
                sha, size, plat, path = parts
                p_os, _, p_arch = plat.partition("/")
                if p_os not in (os_dir, "any"):
                    continue
                if p_arch not in arches and p_arch != "any":
                    continue
                digest = hex32(sha, "hashes/%s:%d" % (name, ln))
                rows[(int(size), digest)] = name[:-4] + ":" + path
    ordered = sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1]))
    return ordered, profiles


def write(path, text):
    old = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            old = fh.read()
    if old != text:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--kind", required=True, choices=("release", "test"))
    ap.add_argument("--os", required=True, choices=("windows", "linux", "macos"))
    ap.add_argument("--arch", required=True, choices=("x64", "x86", "arm64", "universal"))
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", default="")
    a = ap.parse_args()

    cfg_dir = a.config
    modules, options = gen_modules(load(os.path.join(cfg_dir, "modules.json")), a.kind)
    reasons = gen_reasons(load(os.path.join(cfg_dir, "exit_codes.json")))
    rep = load(os.path.join(cfg_dir, "reporting.json"))
    check_keys(rep, "reporting.json", ["errors_dsn", "reports_dsn", "limits"])
    limits = rep["limits"]
    check_keys(limits, "reporting.json limits",
               ["events_per_session", "inventory_per_session", "event_bytes", "string_chars",
                "list_items", "memory_bytes", "input_report_interval_s"])
    for dsn_key in ("errors_dsn", "reports_dsn"):
        dsn = rep[dsn_key]
        if dsn and not re.fullmatch(r"https://[0-9a-f]+@[A-Za-z0-9.\-]+(:\d+)?/\d+", dsn):
            fail("reporting.json %s: expected https://<key>@<host>/<project id>" % dsn_key)
    roots = gen_roots(load(os.path.join(cfg_dir, "roots.json")), cfg_dir)
    pubs, signers = gen_publishers(load(os.path.join(cfg_dir, "publishers.json")), roots)
    deny = gen_denylist(load(os.path.join(cfg_dir, "denylist.json")))
    hashes, profiles = gen_hashes(cfg_dir, a.os, a.arch)

    os.makedirs(a.out, exist_ok=True)

    h = []
    h.append("// Generated by tools/gen_config.py from config/*.json. Do not edit.")
    h.append("#pragma once")
    h.append('#include "config_types.hpp"')
    h.append("namespace mebet::config {")
    h.append("enum class Module : unsigned char {")
    for mid, _, _, _ in modules:
        h.append("    %s," % mid)
    h.append("    count_")
    h.append("};")
    h.append("inline constexpr ModuleDef kModules[] = {")
    for mid, title, level, locked in modules:
        h.append("    { %s, %s, Level::%s, %s }," % (c_str(mid), c_str(title), level, "true" if locked else "false"))
    h.append("};")
    h.append("enum class Reason : unsigned char {")
    for r in reasons:
        h.append("    %s," % r["id"])
    h.append("    count_")
    h.append("};")
    h.append("inline constexpr ReasonDef kReasons[] = {")
    for r in reasons:
        h.append("    { %s, %d, %s, %s, %s, %s }," % (c_str(r["id"]), r["code"], w_str(r["title_ru"]),
                                                     w_str(r["title_en"]), w_str(r["ru"]), w_str(r["en"])))
    h.append("};")
    h.append("namespace opt {")
    h.extend("    " + o for o in options)
    h.append("}  // namespace opt")
    h.append("inline constexpr const char* kBuildKind = %s;" % c_str(a.kind))
    h.append("inline constexpr bool kTestBuild = %s;" % ("true" if a.kind == "test" else "false"))
    h.append("inline constexpr const char* kVersion = %s;" % c_str(a.version))
    h.append("inline constexpr const char* kCommit = %s;" % c_str(a.commit))
    h.append("inline constexpr const char* kErrorsDsn = %s;" % c_str(rep["errors_dsn"]))
    h.append("inline constexpr const char* kReportsDsn = %s;" % c_str(rep["reports_dsn"]))
    for k, v in limits.items():
        if not isinstance(v, int) or v <= 0:
            fail("reporting.json limits.%s must be a positive int" % k)
        h.append("inline constexpr unsigned kLimit_%s = %du;" % (k, v))
    h.append("}  // namespace mebet::config")
    write(os.path.join(a.out, "mebet_config.hpp"), "\n".join(h) + "\n")

    t = []
    t.append("// Generated by tools/gen_config.py from config/*.json. Do not edit.")
    t.append("#pragma once")
    t.append('#include "config_types.hpp"')
    t.append("namespace mebet::config {")
    for r in roots:
        t.append("inline constexpr unsigned char kRootDer_%s[] = { %s };" % (r["id"], bytes_init(r["der"])))
    t.append("inline constexpr RootDef kRoots[] = {")
    for r in roots:
        cls = "public_ca" if r["class"] == "public" else r["class"]
        t.append("    { %s, RootClass::%s, kRootDer_%s, sizeof(kRootDer_%s), { %s }, %s }," % (
            c_str(r["id"]), cls, r["id"], r["id"], bytes_init(r["sha256"]), c_str(r["name"])))
    t.append("};")
    t.append("inline constexpr PublisherDef kPublishers[] = {")
    for p in pubs:
        t.append("    { %s, %s, %s, 0x%08xu, %s }," % (c_str(p["id"]), c_str(p["name"]), c_str(p["group"]), p["mask"],
                                                     c_str(p["mpv"]) if p["mpv"] else "nullptr"))
    t.append("};")
    obs_rows = [(i, o) for i, p in enumerate(pubs) for o in p["obs"]]
    t.append("// Serial prefixes already seen per publisher (ТЗ §6 cert_observations): history only;")
    t.append("// a serial outside this list is reported as a new certificate, never blocked.")
    if obs_rows:
        t.append("inline constexpr ObservationDef kObservations[] = {")
        for i, o in obs_rows:
            t.append("    { %d, %s }," % (i, c_str(o)))
        t.append("};")
        t.append("inline constexpr unsigned kObservationCount = %d;" % len(obs_rows))
    else:
        t.append("inline constexpr ObservationDef kObservations[1] = {};")
        t.append("inline constexpr unsigned kObservationCount = 0;")
    t.append("inline constexpr SignerDef kSigners[] = {")
    for pi, cn, o, issuer in signers:
        t.append("    { %d, %s, %s, %s }," % (pi, c_str(cn), c_str(o), c_str(issuer) if issuer else "nullptr"))
    t.append("};")
    if deny:
        t.append("inline constexpr DenyDef kDenylist[] = {")
        for did, kind, x, y, z, sha in deny:
            t.append("    { %s, DenyKind::%s, %s, %s, %s, { %s } }," % (
                c_str(did), kind, c_str(x) if x else "nullptr", c_str(y) if y else "nullptr",
                c_str(z) if z else "nullptr", bytes_init(sha) if sha else "0"))
        t.append("};")
        t.append("inline constexpr unsigned kDenylistCount = %d;" % len(deny))
    else:
        t.append("inline constexpr DenyDef kDenylist[1] = {};")
        t.append("inline constexpr unsigned kDenylistCount = 0;")
    t.append("// Native libraries trusted by SHA-256 for this target, sorted by size (lookup by size first).")
    t.append("// Profiles: %s" % ", ".join(profiles))
    if hashes:
        t.append("inline constexpr HashDef kNativeHashes[] = {")
        for (size, digest), label in hashes:
            t.append("    { %du, { %s }, %s }," % (size, bytes_init(digest), c_str(label)))
        t.append("};")
        t.append("inline constexpr unsigned kNativeHashCount = %d;" % len(hashes))
    else:
        t.append("inline constexpr HashDef kNativeHashes[1] = {};")
        t.append("inline constexpr unsigned kNativeHashCount = 0;")
    t.append("}  // namespace mebet::config")
    write(os.path.join(a.out, "mebet_trust_data.hpp"), "\n".join(t) + "\n")

    missing = [p for p in ("classic", "modern") if p not in profiles]
    if missing:
        print("gen_config: warning: no native hash list for profile(s) %s — their natives will be "
              "treated as unknown (ТЗ §6, run tools/snap_hashes.py)" % ", ".join(missing), file=sys.stderr)
    print("gen_config: %d modules, %d reasons, %d roots, %d publishers (%d signers), %d denylist, %d hashes"
          % (len(modules), len(reasons), len(roots), len(pubs), len(signers), len(deny), len(hashes)),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConfigError as e:
        print("gen_config: error: %s" % e, file=sys.stderr)
        sys.exit(1)
