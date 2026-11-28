#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Did the smoke events of tests/native/report_smoke.cpp arrive in their GlitchTip projects?

    glitchtip_check.py --marker <marker> [--org politcubes] [--wait 180]

Environment (CI: repository secrets): MEBET_ERRORS_DSN, MEBET_REPORTS_DSN — the project id and
the host come from them, so no project slug is configured anywhere; GLITCHTIP_TOKEN — a GlitchTip
API token with event:read / project:read / org:read, optional: without it the check is skipped
with a warning (the send step has already required 2xx). Neither the DSNs nor the token are printed.

For each channel, both events (smoke.small and smoke.large) with the tag smoke=<marker> must be in
the project of that channel's DSN. GlitchTip stores events asynchronously, so it is asked again
until --wait seconds have passed.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DSN_RX = re.compile(r"(https?)://[0-9a-f]+@([A-Za-z0-9.\-]+(?::\d+)?)/(\d+)")
KINDS = ("smoke.small", "smoke.large")


def api(base, token, path, params=None):
    url = base + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                               "Accept": "application/json",
                                               "User-Agent": "mebet-ci-glitchtip-check"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def tags_of(ev):
    out = {}
    for t in ev.get("tags") or []:
        if isinstance(t, dict):
            out[t.get("key")] = t.get("value")
        elif isinstance(t, (list, tuple)) and len(t) == 2:
            out[t[0]] = t[1]
    return out


def found_kinds(base, token, org, project_id, marker):
    """The smoke kinds with this marker that GlitchTip already has in the project."""
    path = "/api/0/organizations/%s/issues/" % org
    issues = api(base, token, path, {"project": project_id, "query": "smoke:" + marker, "limit": 25})
    if not issues:
        # The issue's tag index is filled asynchronously: look at the smoke issues themselves.
        issues = api(base, token, path, {"project": project_id, "query": "CI smoke", "limit": 25})
    kinds = set()
    for issue in issues:
        events = api(base, token, "/api/0/issues/%s/events/" % issue["id"])
        for ev in events[:100]:
            t = tags_of(ev)
            if t.get("smoke") == marker and t.get("type") in KINDS:
                kinds.add(t["type"])
    return kinds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--marker", required=True)
    ap.add_argument("--org", default="politcubes")
    ap.add_argument("--wait", type=int, default=180)
    a = ap.parse_args()

    token = os.environ.get("GLITCHTIP_TOKEN", "").strip()
    if not token:
        # Optional: without a token the 2xx answers of the send step are the whole check.
        print("::warning::GLITCHTIP_TOKEN repository secret is not set: GlitchTip answered 2xx, "
              "but arrival in the projects is not checked (docs/reports.md)")
        return 0
    channels = []
    for name, var in (("errors", "MEBET_ERRORS_DSN"), ("reports", "MEBET_REPORTS_DSN")):
        m = DSN_RX.fullmatch(os.environ.get(var, "").strip())
        if not m:
            print("::error::%s is not a DSN" % var)
            return 1
        channels.append((name, "%s://%s" % (m.group(1), m.group(2)), m.group(3)))

    deadline = time.monotonic() + a.wait
    pending = {name for name, _, _ in channels}
    while True:
        for name, base, pid in channels:
            if name not in pending:
                continue
            try:
                kinds = found_kinds(base, token, a.org, pid, a.marker)
            except (urllib.error.URLError, ValueError, KeyError) as e:
                print("%s: GlitchTip API: %s" % (name, getattr(e, "code", None) or type(e).__name__))
                kinds = set()
            if set(KINDS) <= kinds:
                print("%s: project %s has %s for marker %s" % (name, pid, ", ".join(KINDS), a.marker))
                pending.discard(name)
        if not pending:
            return 0
        if time.monotonic() > deadline:
            for name in sorted(pending):
                print("::error::%s: the smoke events for %s did not show up in GlitchTip within %d s"
                      % (name, a.marker, a.wait))
            return 1
        time.sleep(10)


if __name__ == "__main__":
    sys.exit(main())
