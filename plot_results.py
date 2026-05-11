#!/usr/bin/env python3
"""
plot_results.py — Vẽ biểu đồ từ CSV kết quả benchmark
=======================================================
Dùng sau khi đã có file CSV từ các kịch bản thực nghiệm.

Cách dùng:
  # Kịch bản 1a:
  python3 plot_results.py --scenario 1a --csv 1a/results/exp1a_*.csv

  # Kịch bản 1b:
  python3 plot_results.py --scenario 1b --csv 1b/results/exp_1b_*.csv

  # Kịch bản 2 (dùng summary CSV):
  python3 plot_results.py --scenario 2 --csv 2/results/exp_2_summary_*.csv

  # Output vào thư mục cụ thể:
  python3 plot_results.py --scenario 1a --csv results.csv --output charts/

Yêu cầu:
  pip install matplotlib pandas
"""

import argparse
import os
import sys

# Kiểm tra thư viện
try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend — chạy được kể cả không có display
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    import pandas as pd
except ImportError:
    print("Lỗi: Cần cài matplotlib và pandas.")
    print("  pip install matplotlib pandas")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# STYLE CHUNG
# ─────────────────────────────────────────────────────────────────────────────
COLORS = {
    "baseline":     "#4caf50",   # xanh lá
    "iptables_only":"#f44336",   # đỏ
    "feedback_loop":"#2196f3",   # xanh dương
    "no_feedback":  "#ff9800",   # cam
    "full_stack":   "#2196f3",   # xanh dương
    "xdp":          "#2196f3",   # xanh dương
    "iptables":     "#f44336",   # đỏ
}
PHASE_LABELS = {
    "baseline":      "Baseline",
    "iptables_only": "Iptables Only",
    "feedback_loop": "Feedback Loop (XDP)",
    "no_feedback":   "No Feedback",
    "full_stack":    "Full Stack (XDP)",
}

def setup_style():
    plt.rcParams.update({
        "figure.facecolor": "#1e1e2e",
        "axes.facecolor":   "#2a2a3e",
        "axes.edgecolor":   "#555577",
        "axes.labelcolor":  "#ccccee",
        "xtick.color":      "#ccccee",
        "ytick.color":      "#ccccee",
        "text.color":       "#ccccee",
        "grid.color":       "#444466",
        "grid.linestyle":   "--",
        "grid.alpha":       0.5,
        "font.family":      "DejaVu Sans",
        "font.size":        11,
        "axes.titlesize":   13,
        "axes.titleweight": "bold",
        "legend.facecolor": "#2a2a3e",
        "legend.edgecolor": "#555577",
    })


# ─────────────────────────────────────────────────────────────────────────────
# KỊCH BẢN 1a — Feedback Loop Iptables → XDP
# ─────────────────────────────────────────────────────────────────────────────
def plot_scenario_1a(df: pd.DataFrame, out_dir: str):
    """
    Vẽ 4 biểu đồ cho kịch bản 1a:
      1. CPU usage theo thời gian (3 phase)
      2. Nginx latency theo thời gian
      3. XDP rules count theo thời gian (feedback loop kích hoạt lúc nào)
      4. Legitimate user OK rate theo phase (bar chart)
    """
    phases = df["phase"].unique().tolist()
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle("Kịch bản 1a — Feedback Loop: Iptables → XDP\n(SYN Flood benchmark)", fontsize=15)

    # ── 1. CPU usage ──
    ax = axes[0, 0]
    for phase in ["baseline", "iptables_only", "feedback_loop"]:
        sub = df[df["phase"] == phase]
        if sub.empty:
            continue
        ax.plot(range(len(sub)), sub["cpu_percent"].values,
                label=PHASE_LABELS.get(phase, phase),
                color=COLORS.get(phase, "#aaaaaa"), linewidth=1.8)
    ax.set_title("CPU Usage (%) theo thời gian")
    ax.set_xlabel("Giây")
    ax.set_ylabel("CPU (%)")
    ax.set_ylim(0, 100)
    ax.legend()
    ax.grid(True)

    # ── 2. Nginx latency ──
    ax = axes[0, 1]
    for phase in ["baseline", "iptables_only", "feedback_loop"]:
        sub = df[df["phase"] == phase]
        if sub.empty:
            continue
        ax.plot(range(len(sub)), sub["nginx_latency_ms"].values,
                label=PHASE_LABELS.get(phase, phase),
                color=COLORS.get(phase, "#aaaaaa"), linewidth=1.8)
    ax.set_title("Nginx Response Latency (ms)")
    ax.set_xlabel("Giây")
    ax.set_ylabel("Latency (ms)")
    ax.legend()
    ax.grid(True)

    # ── 3. XDP rules count ──
    ax = axes[1, 0]
    sub = df[df["phase"] == "feedback_loop"]
    if not sub.empty:
        ax.plot(range(len(sub)), sub["xdp_rules_count"].values,
                color="#9c27b0", linewidth=2, label="XDP Rules Count")
        ax.fill_between(range(len(sub)), sub["xdp_rules_count"].values,
                        alpha=0.3, color="#9c27b0")
    ax.set_title("XDP Rules Count (Feedback Loop Phase)")
    ax.set_xlabel("Giây")
    ax.set_ylabel("Số rules trong BPF Map")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend()
    ax.grid(True)

    # ── 4. Legitimate user OK rate ──
    ax = axes[1, 1]
    phase_order = [p for p in ["baseline", "iptables_only", "feedback_loop"] if p in phases]
    ok_rates = []
    for phase in phase_order:
        sub = df[df["phase"] == phase]
        rate = sub["legitimate_user_ok"].mean() * 100 if not sub.empty else 0
        ok_rates.append(rate)

    bars = ax.bar(
        [PHASE_LABELS.get(p, p) for p in phase_order],
        ok_rates,
        color=[COLORS.get(p, "#aaaaaa") for p in phase_order],
        edgecolor="#333355", linewidth=1.2, width=0.5
    )
    for bar, val in zip(bars, ok_rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{val:.0f}%", ha="center", va="bottom", fontsize=11)
    ax.set_title("Legitimate User OK Rate theo Phase")
    ax.set_ylabel("Tỉ lệ mẫu OK (%)")
    ax.set_ylim(0, 115)
    ax.axhline(y=80, color="#ffeb3b", linestyle="--", linewidth=1.2, label="Ngưỡng pass 80%")
    ax.legend()
    ax.grid(True, axis="y")

    plt.tight_layout()
    out_path = os.path.join(out_dir, "scenario_1a.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Đã lưu: {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# KỊCH BẢN 1b — Slow Loris: Suricata → watcher → XDP
# ─────────────────────────────────────────────────────────────────────────────
def plot_scenario_1b(df: pd.DataFrame, out_dir: str):
    """
    Vẽ 4 biểu đồ cho kịch bản 1b:
      1. nginx_conn_established theo thời gian (key metric Slow Loris)
      2. CPU usage theo thời gian
      3. XDP rules count (phase full_stack)
      4. Legitimate user OK rate theo phase
    """
    phases = df["phase"].unique().tolist()
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle("Kịch bản 1b — Slow Loris: Suricata → watcher → XDP", fontsize=15)

    # ── 1. Nginx connections ESTABLISHED ──
    ax = axes[0, 0]
    for phase in ["baseline", "no_feedback", "full_stack"]:
        sub = df[df["phase"] == phase]
        if sub.empty:
            continue
        ax.plot(range(len(sub)), sub["nginx_conn_established"].values,
                label=PHASE_LABELS.get(phase, phase),
                color=COLORS.get(phase, "#aaaaaa"), linewidth=1.8)
    ax.set_title("Nginx ESTABLISHED Connections\n(tăng cao = Slow Loris đang chiếm connection pool)")
    ax.set_xlabel("Giây")
    ax.set_ylabel("Số connections")
    ax.legend()
    ax.grid(True)

    # ── 2. CPU usage ──
    ax = axes[0, 1]
    for phase in ["baseline", "no_feedback", "full_stack"]:
        sub = df[df["phase"] == phase]
        if sub.empty:
            continue
        ax.plot(range(len(sub)), sub["cpu_percent"].values,
                label=PHASE_LABELS.get(phase, phase),
                color=COLORS.get(phase, "#aaaaaa"), linewidth=1.8)
    ax.set_title("CPU Usage (%)")
    ax.set_xlabel("Giây")
    ax.set_ylabel("CPU (%)")
    ax.set_ylim(0, 100)
    ax.legend()
    ax.grid(True)

    # ── 3. XDP rules (full_stack phase) ──
    ax = axes[1, 0]
    sub = df[df["phase"] == "full_stack"]
    if not sub.empty:
        ax.plot(range(len(sub)), sub["xdp_rules_count"].values,
                color="#9c27b0", linewidth=2, label="XDP Rules Count")
        ax.fill_between(range(len(sub)), sub["xdp_rules_count"].values,
                        alpha=0.3, color="#9c27b0")
        # Đánh dấu thời điểm XDP rule đầu tiên được thêm
        first_block = sub[sub["xdp_rules_count"] > 0]
        if not first_block.empty:
            idx = first_block.index[0] - sub.index[0]
            ax.axvline(x=idx, color="#ffeb3b", linestyle="--", linewidth=1.5,
                       label=f"Block lúc giây {idx}")
    ax.set_title("XDP Rules Count (Full Stack Phase)\nMốc: lúc nào Slow Loris bị block")
    ax.set_xlabel("Giây trong phase full_stack")
    ax.set_ylabel("Số rules")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend()
    ax.grid(True)

    # ── 4. Legitimate user OK rate ──
    ax = axes[1, 1]
    phase_order = [p for p in ["baseline", "no_feedback", "full_stack"] if p in phases]
    ok_rates = [df[df["phase"] == p]["legitimate_user_ok"].mean() * 100
                for p in phase_order]
    bars = ax.bar(
        [PHASE_LABELS.get(p, p) for p in phase_order],
        ok_rates,
        color=[COLORS.get(p, "#aaaaaa") for p in phase_order],
        edgecolor="#333355", linewidth=1.2, width=0.5
    )
    for bar, val in zip(bars, ok_rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{val:.0f}%", ha="center", va="bottom", fontsize=11)
    ax.set_title("Legitimate User OK Rate theo Phase")
    ax.set_ylabel("Tỉ lệ mẫu OK (%)")
    ax.set_ylim(0, 115)
    ax.axhline(y=80, color="#ffeb3b", linestyle="--", linewidth=1.2, label="Ngưỡng pass 80%")
    ax.legend()
    ax.grid(True, axis="y")

    plt.tight_layout()
    out_path = os.path.join(out_dir, "scenario_1b.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Đã lưu: {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# KỊCH BẢN 2 — GeoIP: XDP vs Iptables/ipset
# ─────────────────────────────────────────────────────────────────────────────
def plot_scenario_2(df: pd.DataFrame, out_dir: str):
    """
    Vẽ 4 biểu đồ cho kịch bản 2 từ summary CSV:
      1. Latency p50 vs ruleset size (XDP vs Iptables)
      2. Latency p99 vs ruleset size
      3. Requests/sec vs ruleset size
      4. CPU avg vs ruleset size
    """
    # Normalize columns
    df.columns = [c.strip() for c in df.columns]

    # Chuẩn hóa latency — wrk trả về dạng "12.34ms" hoặc "1.23s"
    def parse_latency_ms(val):
        try:
            val = str(val).strip()
            if val.endswith("ms"):
                return float(val[:-2])
            elif val.endswith("s"):
                return float(val[:-1]) * 1000
            elif val == "N/A" or val == "":
                return None
            return float(val)
        except Exception:
            return None

    for col in ["latency_p50", "latency_p95", "latency_p99"]:
        if col in df.columns:
            df[col] = df[col].apply(parse_latency_ms)

    for col in ["req_per_sec", "cpu_avg", "ruleset_size"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    xdp_df = df[df["implementation"] == "xdp"].sort_values("ruleset_size")
    ipt_df = df[df["implementation"] == "iptables"].sort_values("ruleset_size")

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle("Kịch bản 2 — GeoIP: XDP BPF LPM Trie vs Iptables/ipset\n(Latency khi ruleset tăng dần)", fontsize=15)

    x_labels = [str(int(x)) for x in sorted(df["ruleset_size"].dropna().unique())]

    def plot_metric(ax, col, title, ylabel, log_scale=False):
        if col not in df.columns:
            ax.text(0.5, 0.5, f"Không có cột '{col}'", ha="center", transform=ax.transAxes)
            return
        xdp_vals = xdp_df[col].values
        ipt_vals = ipt_df[col].values
        x = range(len(x_labels))
        ax.plot(x, xdp_vals, "o-", color=COLORS["xdp"], linewidth=2.2,
                markersize=7, label="XDP (BPF LPM Trie)")
        ax.plot(x, ipt_vals, "s--", color=COLORS["iptables"], linewidth=2.2,
                markersize=7, label="Iptables/ipset")
        ax.fill_between(x, xdp_vals, ipt_vals, alpha=0.12, color="#9c27b0",
                        label="Khoảng chênh lệch")
        ax.set_xticks(list(x))
        ax.set_xticklabels(x_labels)
        ax.set_title(title)
        ax.set_xlabel("Số CIDR trong ruleset")
        ax.set_ylabel(ylabel)
        if log_scale:
            ax.set_yscale("log")
        ax.legend()
        ax.grid(True)

    plot_metric(axes[0, 0], "latency_p50", "Latency p50 (median) theo Ruleset Size", "Latency (ms)")
    plot_metric(axes[0, 1], "latency_p99", "Latency p99 theo Ruleset Size\n(tail latency — quan trọng nhất)", "Latency (ms)")
    plot_metric(axes[1, 0], "req_per_sec", "Throughput (Requests/sec)", "req/s")
    plot_metric(axes[1, 1], "cpu_avg",     "CPU Average (%)", "CPU (%)")

    # Thêm annotation "O(1) lookup" cho XDP nếu latency gần phẳng
    ax = axes[0, 1]
    if "latency_p99" in xdp_df.columns and xdp_df["latency_p99"].notna().sum() >= 2:
        vals = xdp_df["latency_p99"].dropna().values
        if max(vals) - min(vals) < 5:  # gần phẳng
            ax.annotate("→ XDP gần O(1)\n  không tăng theo size",
                        xy=(len(vals) - 1, vals[-1]),
                        xytext=(len(vals) - 2.5, vals[-1] + 10),
                        arrowprops=dict(arrowstyle="->", color="#4caf50"),
                        color="#4caf50", fontsize=10)

    plt.tight_layout()
    out_path = os.path.join(out_dir, "scenario_2.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Đã lưu: {out_path}")

    # ── Biểu đồ thêm: so sánh p50/p99 side-by-side grouped bar ──
    fig2, ax2 = plt.subplots(figsize=(14, 6))
    fig2.suptitle("So sánh Latency XDP vs Iptables theo từng mức ruleset", fontsize=13)

    n = len(x_labels)
    x = range(n)
    width = 0.2

    if "latency_p50" in xdp_df.columns:
        ax2.bar([i - width * 1.5 for i in x], xdp_df["latency_p50"].values,
                width, label="XDP p50", color=COLORS["xdp"], alpha=0.85, edgecolor="#333355")
        ax2.bar([i - width * 0.5 for i in x], ipt_df["latency_p50"].values,
                width, label="Iptables p50", color=COLORS["iptables"], alpha=0.85, edgecolor="#333355")
    if "latency_p99" in xdp_df.columns:
        ax2.bar([i + width * 0.5 for i in x], xdp_df["latency_p99"].values,
                width, label="XDP p99", color=COLORS["xdp"], alpha=0.5, edgecolor="#2196f3")
        ax2.bar([i + width * 1.5 for i in x], ipt_df["latency_p99"].values,
                width, label="Iptables p99", color=COLORS["iptables"], alpha=0.5, edgecolor="#f44336")

    ax2.set_xticks(list(x))
    ax2.set_xticklabels(x_labels)
    ax2.set_xlabel("Số CIDR trong ruleset")
    ax2.set_ylabel("Latency (ms)")
    ax2.legend()
    ax2.grid(True, axis="y")

    out_path2 = os.path.join(out_dir, "scenario_2_grouped.png")
    fig2.savefig(out_path2, dpi=150, bbox_inches="tight")
    plt.close(fig2)
    print(f"[OK] Đã lưu: {out_path2}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Vẽ biểu đồ từ CSV kết quả benchmark hybrid firewall"
    )
    parser.add_argument("--scenario", required=True, choices=["1a", "1b", "2"],
                        help="Kịch bản: 1a, 1b, hoặc 2")
    parser.add_argument("--csv", required=True,
                        help="Đường dẫn file CSV (dùng glob pattern nếu cần)")
    parser.add_argument("--output", default=".",
                        help="Thư mục lưu ảnh biểu đồ (mặc định: thư mục hiện tại)")
    args = parser.parse_args()

    # Xử lý glob
    import glob
    csv_files = sorted(glob.glob(args.csv))
    if not csv_files:
        print(f"[ERROR] Không tìm thấy file CSV: {args.csv}")
        sys.exit(1)
    csv_path = csv_files[-1]  # Lấy file mới nhất nếu có nhiều
    print(f"[*] Đọc CSV: {csv_path}")

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[ERROR] Không đọc được CSV: {e}")
        sys.exit(1)

    print(f"[*] Số dòng: {len(df)} | Các cột: {list(df.columns)}")

    os.makedirs(args.output, exist_ok=True)
    setup_style()

    if args.scenario == "1a":
        if "phase" not in df.columns:
            print("[ERROR] CSV thiếu cột 'phase' — đây có phải file của kịch bản 1a không?")
            sys.exit(1)
        plot_scenario_1a(df, args.output)
        print("\nĐã vẽ xong kịch bản 1a. Các file ảnh:")
        print(f"  {args.output}/scenario_1a.png")

    elif args.scenario == "1b":
        if "phase" not in df.columns:
            print("[ERROR] CSV thiếu cột 'phase' — đây có phải file của kịch bản 1b không?")
            sys.exit(1)
        plot_scenario_1b(df, args.output)
        print("\nĐã vẽ xong kịch bản 1b. Các file ảnh:")
        print(f"  {args.output}/scenario_1b.png")

    elif args.scenario == "2":
        if "implementation" not in df.columns:
            print("[ERROR] CSV thiếu cột 'implementation' — cần dùng summary CSV (exp_2_summary_*.csv)")
            sys.exit(1)
        plot_scenario_2(df, args.output)
        print("\nĐã vẽ xong kịch bản 2. Các file ảnh:")
        print(f"  {args.output}/scenario_2.png")
        print(f"  {args.output}/scenario_2_grouped.png")


if __name__ == "__main__":
    main()
