#!/usr/bin/env python3
"""Render MTP1-E benchmark results.

Reads a run directory produced by benchmark/run-bench.sh, prints a compact
median +/- stdev table of every metric (stdlib only), and - when matplotlib is
installed - renders comparison bar charts and iperf3 per-second time-series
PNGs into <run>/charts/.

Usage:
    python3 benchmark/plot.py [RUN_DIR] [--scenario SCEN] [--iter N]
                              [--out DIR] [--help]

With no RUN_DIR the most recently created run under benchmark/results/ is used.
--scenario selects the scenario for the time-series line charts (default:
single). --iter selects which iteration's iperf JSON feeds the time-series
(default: 2).
"""

import argparse
import json
import os
import re
import statistics
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_ROOT = os.path.join(SCRIPT_DIR, "results")

BACKENDS = ("xdp", "nft")

# summary.tsv column -> (human label, cast, printf-like format)
METRICS = [
    ("udp_bps",       "UDP throughput (bits/s)", float, "{:,.0f}"),
    ("udp_pps",       "UDP packets/s",           float, "{:,.0f}"),
    ("udp_lost",      "UDP lost packets",        float, "{:,.0f}"),
    ("udp_jitter_ms", "UDP jitter (ms)",         float, "{:.3f}"),
    ("tcp_bps",       "TCP throughput (bits/s)", float, "{:,.0f}"),
    ("rtt_avg_ms",    "RTT avg (ms)",            float, "{:.3f}"),
    ("cpu_jif",       "CPU busy jiffies",        float, "{:,.0f}"),
    ("rss_kb",        "RSS (KiB)",               float, "{:,.0f}"),
    ("add_ms",        "rule add time (ms)",      float, "{:.1f}"),
    ("del_ms",        "rule del time (ms)",      float, "{:.1f}"),
    ("drop_pps",      "DROP rate (pkts/s)",      float, "{:,.0f}"),
    ("udp2_bps",      "UDP ctl throughput (bits/s)", float, "{:,.0f}"),
    ("udp2_pps",      "UDP ctl packets/s",       float, "{:,.0f}"),
    ("udp2_lost",     "UDP ctl lost packets",    float, "{:,.0f}"),
    ("udp2_jitter_ms","UDP ctl jitter (ms)",     float, "{:.3f}"),
]

# (metric, axis label) and the value divider for plotting (bps -> Mbit/s).
BAR_METRICS = [
    ("udp_bps",       "UDP throughput (Mbit/s)", 1e6),
    ("tcp_bps",       "TCP throughput (Mbit/s)", 1e6),
    ("udp_pps",       "UDP packets/s",           1.0),
    ("udp_lost",      "UDP lost packets",        1.0),
    ("udp_jitter_ms", "UDP jitter (ms)",         1.0),
    ("rtt_avg_ms",    "RTT avg (ms)",            1.0),
    ("cpu_jif",       "CPU busy jiffies",        1.0),
    ("rss_kb",        "RSS (KiB)",               1.0),
    ("add_ms",        "rule add time (ms)",      1.0),
    ("del_ms",        "rule del time (ms)",      1.0),
    ("drop_pps",      "DROP rate (pkts/s)",      1.0),
    ("udp2_bps",      "UDP controlled throughput (Mbit/s)", 1e6),
    ("udp2_pps",      "UDP controlled packets/s", 1.0),
    ("udp2_lost",     "UDP controlled lost packets", 1.0),
    ("udp2_jitter_ms","UDP controlled jitter (ms)", 1.0),
]


def latest_run(root):
    """Return the most recent results/<YYYYmmdd-HHMMSS> directory."""
    if not os.path.isdir(root):
        return None
    runs = [d for d in os.listdir(root) if re.fullmatch(r"\d{8}-\d{6}", d)]
    return os.path.join(root, sorted(runs)[-1]) if runs else None


def read_summary(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            line = line.rstrip("\n")
            if line:
                rows.append(dict(zip(header, line.split("\t"))))
    return rows


def aggregate(rows):
    """Return (per-metric aggregated stats, ordered scenario list)."""
    col = {m: {b: {} for b in BACKENDS} for m, *_ in METRICS}
    scenarios = []
    for row in rows:
        backend, scenario = row.get("backend", ""), row.get("scenario", "")
        if scenario and scenario not in scenarios:
            scenarios.append(scenario)
        for m, *_ in METRICS:
            try:
                v = float(row.get(m, "") or "")
            except ValueError:
                v = None
            col[m][backend].setdefault(scenario, []).append(v)

    agg = {}
    for m, *_ in METRICS:
        agg[m] = {b: {} for b in BACKENDS}
        for b in BACKENDS:
            for s, vals in col[m][b].items():
                nums = [v for v in vals if v is not None]
                agg[m][b][s] = {
                    "vals": nums,
                    "median": statistics.median(nums) if nums else None,
                    "stdev": statistics.stdev(nums) if len(nums) > 1 else 0.0,
                    "n": len(nums),
                }
    return agg, scenarios


def print_table(agg, scenarios):
    print(f"{'metric':<24}{'backend':<8}{'scenario':<10}{'median':>16}{'stdev':>12}{'n':>4}")
    for m, label, _, fmt in METRICS:
        print(f"{label}")
        for b in BACKENDS:
            for s in scenarios:
                cell = agg[m][b].get(s)
                if not cell or cell["median"] is None:
                    print(f"{'':<24}{b:<8}{s:<10}{'-':>16}{'-':>12}{0:>4}")
                    continue
                print(f"{'':<24}{b:<8}{s:<10}"
                      f"{fmt.format(cell['median']):>16}"
                      f"{fmt.format(cell['stdev']):>12}"
                      f"{cell['n']:>4}")


def human(v):
    if v >= 1e9:
        return f"{v / 1e9:.2f}G"
    if v >= 1e6:
        return f"{v / 1e6:.1f}M"
    if v >= 1e3:
        return f"{v / 1e3:.1f}k"
    return f"{v:.2g}"


def render_bars(agg, scenarios, out_dir):
    colors = {"xdp": "#1f77b4", "nft": "#ff7f0e"}
    x = list(range(len(scenarios)))
    width = 0.38

    for metric, ylabel, scale in BAR_METRICS:
        fig, ax = plt.subplots(figsize=(9, 4.5))
        for b in BACKENDS:
            medians = [agg[metric][b].get(s, {}).get("median") for s in scenarios]
            stdevs = [agg[metric][b].get(s, {}).get("stdev") for s in scenarios]
            heights = [((v or 0.0) / scale) for v in medians]
            errs = [(e or 0.0) / scale for e in stdevs]
            off = ((width / 2) if b == "xdp" else -(width / 2))
            ax.bar([pos + off for pos in x], heights, width, yerr=errs,
                   label=("XDP" if b == "xdp" else "nftables"),
                   color=colors[b], capsize=3)
            for pos, h in zip(x, heights):
                if h:
                    ax.annotate(human(h * scale), xy=(pos + off, h),
                                xytext=(0, 2), textcoords="offset points",
                                ha="center", fontsize=7)
        ax.set_xticks(x)
        ax.set_xticklabels(scenarios)
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel)
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, f"{metric}.png"), dpi=150)
        plt.close(fig)


def read_series(path):
    """(x-seconds cumulative, y Mbit/s) from one iperf -J interval list."""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return [], []
    xs, ys, t = [], [], 0.0
    for interval in d.get("intervals", []):
        s = interval.get("sum", {})
        t += float(s.get("seconds") or 0.0)
        xs.append(t)
        ys.append(float(s.get("bits_per_second") or 0.0) / 1e6)
    return xs, ys


def render_timeseries(run_dir, scenario, iteration, out_dir):
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.5))
    for mode, ax, ylabel in (("udp", axes[0], "UDP Mbit/s"),
                             ("tcp", axes[1], "TCP Mbit/s")):
        for b in BACKENDS:
            path = os.path.join(run_dir, f"{b}-{scenario}", f"iperf-{mode}.json")
            if not os.path.isfile(path):
                continue
            xs, ys = read_series(path)
            if xs:
                ax.plot(xs, ys, label=("XDP" if b == "xdp" else "nftables"),
                        marker=".", markersize=3)
        ax.set_title(f"{mode.upper()} throughput over time ({scenario}, iter {iteration})")
        ax.set_xlabel("seconds")
        ax.set_ylabel(ylabel)
        ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "timeseries.png"), dpi=150)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description="Render benchmark results.")
    ap.add_argument("run_dir", nargs="?", default=None,
                    help="results/<run> dir; defaults to the latest run")
    ap.add_argument("--scenario", default="single",
                    help="scenario used for time-series charts (default: single)")
    ap.add_argument("--iter", type=int, default=2,
                    help="iteration label for time-series titles (default: 2)")
    ap.add_argument("--out", default=None,
                    help="chart output dir; default <run>/charts")
    args = ap.parse_args()

    run_dir = args.run_dir or latest_run(RESULTS_ROOT)
    if not run_dir or not os.path.isfile(os.path.join(run_dir, "summary.tsv")):
        sys.exit(f"bench-plot: no summary.tsv found under {run_dir or RESULTS_ROOT}")

    rows = read_summary(os.path.join(run_dir, "summary.tsv"))
    agg, scenarios = aggregate(rows)
    print_table(agg, scenarios)

    if rows and all(float(r.get("udp_bps") or 0) == 0 for r in rows):
        print("\nWARN: every row reports udp_bps=0 - the run's traffic metrics "
              "are void (check run-bench.sh metric parsing).", file=sys.stderr)

    if not HAS_MPL:
        print("\ncharts skipped: matplotlib not installed "
              "(table above was printed with stdlib only)", file=sys.stderr)
        return

    out_dir = args.out or os.path.join(run_dir, "charts")
    os.makedirs(out_dir, exist_ok=True)
    render_bars(agg, scenarios, out_dir)
    render_timeseries(run_dir, args.scenario, args.iter, out_dir)
    print(f"\ncharts written to {out_dir}")


if __name__ == "__main__":
    main()