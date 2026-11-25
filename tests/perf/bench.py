#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""How much the guard costs: the same Java workloads timed without the guard and through it.

    python tests/perf/bench.py --guard <MebetGuard> --java <JAVA_HOME>
                               [--reps 3] [--warmup 3] [--measure 10] [--only a,b]
                               [--json out.json] [--markdown out.md]

Every benchmark runs in its own JVM: a warm-up window (JIT), then a measured window of at least
--measure seconds (10 by default) whose mean round time is the result. The two modes alternate
(A B B A ...) so a CPU that heats up or a noisy neighbour hits both the same way, and each
mode's value is the median over the reps. Start-up is timed outside: the wall clock of a
process that exits at once. The report says how much slower the guarded run is, in %, and marks
a difference smaller than the spread between reps as "в пределах шума". It also sums up what the
guard itself spent per module (its "[Mebet] guard time" line at exit).
"""
import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXE = ".exe" if os.name == "nt" else ""

WHAT = {
    "startup": "запуск процесса до main() и выход",
    "cpu_hash": "SHA-256, 192 МБ (чистые вычисления)",
    "cpu_sort": "сортировка 2 млн long",
    "cpu_math": "мандельброт 1280×960 (double)",
    "alloc_young": "32 млн короткоживущих объектов (молодой GC)",
    "alloc_huge": "256 массивов по 8 МБ (огромные объекты, коммит кучи)",
    "threads": "4000 потоков: старт и выход",
    "class_load": "4000 классов в новых загрузчиках",
    "jni_deflate": "zip-сжатие 30 × 256 КБ (JNI)",
    "game_tick": "360 игровых тиков: физика, сетка, мусор, параллельно",
    "frame_pacing": "кадр 144 FPS: тик + отрисовка 1280×720, окно 30 с (среднее время кадра)",
    "native_alloc": "1000 нативных блоков по 1 МБ (VirtualAlloc/Free)",
    "file_mmap": "2000 отображений файла по 4 МБ",
    "ffm_downcall": "30 млн нативных вызовов через FFM",
}


def java_feature(java_home):
    try:
        text = (Path(java_home) / "release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    m = re.search(r'JAVA_VERSION="(\d+)(?:\.(\d+))?', text)
    if not m:
        return 0
    major = int(m.group(1))
    return int(m.group(2) or 0) if major == 1 else major


def run(cmd, env, timeout=600):
    t0 = time.perf_counter()
    p = subprocess.run([str(c) for c in cmd], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace"), time.perf_counter() - t0


def build(java_home, work):
    classes = work / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    sources = [HERE / "MebetBench.java", HERE / "MebetBenchPayload.java"]
    if java_feature(java_home) >= 22:
        sources.append(HERE / "MebetBenchFfm.java")
    javac = Path(java_home) / "bin" / ("javac" + EXE)
    code, out, _ = run([javac, "-d", classes] + sources, os.environ.copy())
    if code != 0:
        sys.exit("javac failed:\n" + out)
    return classes


GUARD_TIME = re.compile(r"\[Mebet\] guard time: (.*)")
GUARD_ITEM = re.compile(r"(\w+)=([\d.]+)ms/(\d+)")


def guard_time(out):
    m = GUARD_TIME.search(out)
    return {k: float(ms) for k, ms, _ in GUARD_ITEM.findall(m.group(1))} if m else {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard", required=True)
    ap.add_argument("--java", required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--warmup", type=float, default=3.0, help="warm-up window, s")
    ap.add_argument("--measure", type=float, default=10.0, help="measured window, s (at least)")
    ap.add_argument("--startup-reps", type=int, default=10)
    ap.add_argument("--only", default="")
    ap.add_argument("--work", default=str(HERE / "_work"))
    ap.add_argument("--xmx", default="1g")
    ap.add_argument("--json", default="")
    ap.add_argument("--markdown", default="")
    a = ap.parse_args()

    java_home = Path(a.java).resolve()
    java = java_home / "bin" / ("java" + EXE)
    guard = Path(a.guard).resolve()
    work = Path(a.work).resolve()
    classes = build(java_home, work)
    env = os.environ.copy()
    env["JAVA_HOME"] = str(java_home)
    env["MEBET_TEST_NO_UI"] = "1"
    jvm = ["-Xmx" + a.xmx]
    if java_feature(java_home) >= 22:
        jvm.append("--enable-native-access=ALL-UNNAMED")
    head = {"baseline": java, "guarded": guard}

    _, out, _ = run([java] + jvm + ["-cp", classes, "MebetBench", "list"], env)
    names = re.search(r"BENCHES (.*)", out).group(1).split()
    if a.only:
        names = [n for n in names if n in set(a.only.split(","))]

    values = {n: {"baseline": [], "guarded": []} for n in ["startup"] + names}
    frames = {"baseline": [], "guarded": []}  # frame_pacing: the full BENCH record per run
    spent = {}  # module -> list of ms per guarded run

    def one(mode, args):
        code, out, secs = run([head[mode]] + jvm + ["-cp", classes, "MebetBench"] + args, env)
        if code != 0:
            sys.exit("%s %s failed (exit %s):\n%s" % (mode, " ".join(args), code, out))
        if mode == "guarded":
            for k, v in guard_time(out).items():
                spent.setdefault(k, []).append(v)
        return out, secs

    # Start-up: the whole process, timed outside.
    for i in range(a.startup_reps):
        for mode in (("baseline", "guarded") if i % 2 == 0 else ("guarded", "baseline")):
            _, secs = one(mode, ["startup"])
            values["startup"][mode].append(secs * 1000)
    # Workloads: the in-JVM median round time.
    for rep in range(a.reps):
        for name in names:
            for mode in (("baseline", "guarded") if rep % 2 == 0 else ("guarded", "baseline")):
                out, _ = one(mode, [name, str(a.warmup), str(a.measure)])
                m = re.search(r"BENCH (\{.*\})", out)
                if not m:
                    sys.exit("no BENCH line from %s %s:\n%s" % (mode, name, out))
                rec = json.loads(m.group(1))
                values[name][mode].append(rec["mean_ms"])
                if name == "frame_pacing":
                    frames[mode].append(rec)
        print("rep %d/%d done" % (rep + 1, a.reps), flush=True)

    rows, ratios = [], []
    for name, v in values.items():
        b, g = statistics.median(v["baseline"]), statistics.median(v["guarded"])
        noise = max(_spread(v["baseline"]), _spread(v["guarded"]))
        over = (g - b) / b * 100 if b else 0.0
        rows.append(dict(name=name, what=WHAT.get(name, ""), baseline_ms=b, guarded_ms=g,
                         overhead_pct=over, noise_pct=noise, within_noise=abs(over) <= noise))
        if name != "startup":
            ratios.append(g / b)
    mean = (math.exp(sum(math.log(r) for r in ratios) / len(ratios)) - 1) * 100 if ratios else 0.0

    md = render(rows, mean, spent, a.reps, a.warmup, a.measure, frames)
    print(md)
    if a.markdown:
        Path(a.markdown).write_text(md, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md + "\n")
    if a.json:
        Path(a.json).write_text(json.dumps(dict(rows=rows, mean_overhead_pct=mean, guard_spent_ms=spent),
                                           ensure_ascii=False, indent=2), encoding="utf-8")


def _spread(xs):
    """Spread between reps, % of the median: how much the same thing varies run to run."""
    if len(xs) < 2:
        return 0.0
    med = statistics.median(xs)
    return (max(xs) - min(xs)) / med * 100 if med else 0.0


def render_frames(frames):
    """Frame pacing: the tail of the frame-time distribution, where stutter lives."""
    if not frames["baseline"] or not frames["guarded"]:
        return []
    med = lambda mode, key: statistics.median(r[key] for r in frames[mode])  # noqa: E731
    budget = frames["baseline"][0]["budget_ms"]
    lines = ["#### Плавность кадров (144 FPS, бюджет кадра %.2f мс)" % budget, "",
             "Время работы каждого кадра за окно 30 с; медиана по повторам. Фризы прячутся в хвосте "
             "(p99, p99.9, максимум) и в числе кадров, не уложившихся в бюджет.", "",
             "| | p50 | p99 | p99.9 | максимум | не уложились в бюджет | кадров |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for mode, label in (("baseline", "без гварда"), ("guarded", "с гвардом")):
        lines.append("| %s | %.2f мс | %.2f мс | %.2f мс | %.2f мс | %d | %d |" % (
            label, med(mode, "p50_ms"), med(mode, "p99_ms"), med(mode, "p999_ms"), med(mode, "max_ms"),
            med(mode, "over_budget"), med(mode, "frames")))
    return lines + [""]


def render(rows, mean, spent, reps, warmup, measure, frames=None):
    lines = ["### Сколько стоит страж", "",
             ("Каждая нагрузка: прогрев %g с, затем окно замера не меньше %g с; значение — среднее "
              "время раунда в окне (с паузами GC). Медиана по %d повторам, режимы чередуются. "
              "«Шум» — разброс между повторами.") % (warmup, measure, reps), "",
             "| нагрузка | раунд — что нагружает | без гварда | с гвардом | разница | шум |",
             "|---|---|---:|---:|---:|---:|"]
    for r in rows:
        diff = "%+.1f %%" % r["overhead_pct"]
        if r["within_noise"]:
            diff += " (в пределах шума)"
        lines.append("| `%s` | %s | %.1f мс | %.1f мс | %s | ±%.1f %% |" % (
            r["name"], r["what"], r["baseline_ms"], r["guarded_ms"], diff, r["noise_pct"] / 2))
    lines += ["", "**В среднем по нагрузкам (без запуска): %+.1f %%.**" % mean, ""]
    if frames:
        lines += render_frames(frames)
    if spent:
        lines += ["<details><summary>На что тратит время сам страж (за один запуск)</summary>", "",
                  "| модуль | мс, медиана | мс, максимум |", "|---|---:|---:|"]
        for k, v in sorted(spent.items(), key=lambda kv: -statistics.median(kv[1])):
            lines.append("| `%s` | %.1f | %.1f |" % (k, statistics.median(v), max(v)))
        lines += ["", "</details>", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
