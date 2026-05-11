#!/usr/bin/env python3
"""
monitor.py — Thu thập metrics cho tất cả kịch bản thực nghiệm
=============================================================
Script này chạy liên tục trong suốt thực nghiệm, mỗi giây gọi:
  - GET /health (XDP Core API) để lấy CPU, RAM, xdp_attached
  - HTTP GET đến nginx từ góc nhìn legitimate user (ns_50)
  - Đọc /proc/net/dev để lấy packet counters trên interface
  - Đọc iptables counters
  - Đọc connection count của nginx qua ss

Dữ liệu ghi vào file CSV theo đường dẫn OUTPUT_CSV.
Chạy song song với các script tấn công và script kịch bản.

Cách dùng:
  python3 monitor.py --phase baseline --output results/exp1a.csv
  python3 monitor.py --phase iptables_only --output results/exp1a.csv --append
  python3 monitor.py --phase feedback_loop --output results/exp1a.csv --append

Dừng bằng Ctrl+C hoặc gửi SIGTERM.
"""

import argparse
import csv
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# ===========================================================================
# CẤU HÌNH — Chỉnh sửa các biến này cho phù hợp với môi trường lab
# ===========================================================================

# Địa chỉ XDP Core REST API (chạy trên Firewall VM)
XDP_API_BASE = "http://127.0.0.1:8080"

# Địa chỉ nginx trên Victim VM — đây là target probe cho legitimate user
NGINX_TARGET = "http://10.10.2.2"

# Interface mà XDP đang attach — tên card mạng cần chỉnh thủ công!
# Ví dụ: "eth0", "enp0s3", "ens33" — tùy máy
IFACE = "enp0s8"  # Interface XDP attach — mặt nhìn về Attacker VM

# Timeout cho mỗi lần probe nginx (giây)
# Nếu nginx không trả lời trong thời gian này, coi như legitimate user bị ảnh hưởng
NGINX_PROBE_TIMEOUT = 2.0

# Khoảng cách giữa hai lần thu thập (giây)
SAMPLE_INTERVAL = 1.0

# Ngưỡng latency (ms) để coi legitimate user là "ok"
# Nếu latency vượt ngưỡng này → legitimate_user_ok = 0 dù nginx vẫn trả HTTP 200
# Máy yếu (VirtualBox): 500ms là hợp lý
# Nếu máy mạnh hơn (bare metal): nên giảm xuống 100-200ms
LATENCY_THRESHOLD_MS = 500.0

# ===========================================================================
# CÁC HÀM ĐỌC METRICS
# ===========================================================================

def get_xdp_health():
    """
    Gọi GET /health để lấy CPU, Memory, xdp_attached từ XDP Core.
    Trả về dict, hoặc dict rỗng nếu API không phản hồi.
    
    Lưu ý thiết kế: REST API chỉ là control plane — overhead của HTTP call
    này không ảnh hưởng đến data plane (XDP drop packet trong kernel).
    """
    try:
        url = f"{XDP_API_BASE}/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            data = json.loads(resp.read().decode())
            return {
                "xdp_cpu_percent": data.get("CPU", data.get("cpu_percent", 0)),
                "xdp_mem_mb": data.get("Memory_MB", data.get("memory_mb", 0)),
                "xdp_attached": 1 if data.get("xdp_attached", False) else 0,
            }
    except Exception:
        # API không phản hồi — có thể XDP Core chưa khởi động
        return {"xdp_cpu_percent": -1, "xdp_mem_mb": -1, "xdp_attached": -1}


def get_xdp_rules_count():
    """
    Gọi GET /rules để đếm số luật đang active trong BPF Map.
    Hữu ích để xác nhận feedback loop đã push rule thành công.
    """
    try:
        url = f"{XDP_API_BASE}/rules"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            data = json.loads(resp.read().decode())
            # API trả về list các rules
            if isinstance(data, list):
                return len(data)
            return 0
    except Exception:
        return -1


def probe_nginx():
    """
    Gửi HTTP GET đến nginx và đo response time + status code.
    Đây là chỉ số quan trọng nhất: legitimate user có truy cập được không?
    
    Quan trọng: Script này nên chạy trên Firewall VM nhưng probe từ góc nhìn
    của ns_50. Trong thực tế lab, bạn có thể cần chạy monitor.py trên Attacker VM
    trong namespace ns_50 để có kết quả chính xác nhất.
    Nếu chạy trên Firewall VM, thay NGINX_TARGET thành 10.10.2.2 vẫn hợp lệ
    vì traffic hợp lệ đi qua eth1 (không qua XDP trên eth0).
    """
    start = time.time()
    try:
        req = urllib.request.Request(
            NGINX_TARGET,
            headers={"User-Agent": "BenchmarkMonitor/1.0"}
        )
        with urllib.request.urlopen(req, timeout=NGINX_PROBE_TIMEOUT) as resp:
            elapsed_ms = (time.time() - start) * 1000
            status = resp.status
            # legitimate_user_ok = 1 chỉ khi HTTP 200 VÀ latency trong ngưỡng
            ok = 1 if (status == 200 and elapsed_ms < LATENCY_THRESHOLD_MS) else 0
            return {
                "nginx_latency_ms": round(elapsed_ms, 2),
                "nginx_http_status": status,
                "legitimate_user_ok": ok,
            }
    except urllib.error.URLError:
        # Connection refused hoặc timeout — nginx chết hoặc bị block
        elapsed_ms = (time.time() - start) * 1000
        return {
            "nginx_latency_ms": round(elapsed_ms, 2),
            "nginx_http_status": 0,
            "legitimate_user_ok": 0,
        }
    except Exception:
        return {
            "nginx_latency_ms": NGINX_PROBE_TIMEOUT * 1000,
            "nginx_http_status": 0,
            "legitimate_user_ok": 0,
        }


def get_system_cpu():
    """
    Đọc CPU usage từ /proc/stat.
    Đo system-wide CPU (không chỉ một process) vì XDP drop tại driver
    không có process riêng, nhưng sẽ giảm softirq và interrupt của kernel.
    Đây là lý do tại sao dùng /proc/stat thay vì psutil.cpu_percent().
    """
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()  # Dòng đầu: "cpu  user nice system idle iowait ..."
        fields = line.split()
        # Bỏ chữ "cpu" ở đầu, lấy các giá trị số
        values = [int(x) for x in fields[1:]]
        # total = tổng tất cả states, idle = idle + iowait
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return {"cpu_total": total, "cpu_idle": idle}
    except Exception:
        return {"cpu_total": 0, "cpu_idle": 0}


def calc_cpu_percent(prev, curr):
    """
    Tính CPU usage (%) từ hai snapshot liên tiếp của /proc/stat.
    Phải lấy delta giữa hai lần đọc, không phải giá trị tuyệt đối.
    """
    total_delta = curr["cpu_total"] - prev["cpu_total"]
    idle_delta = curr["cpu_idle"] - prev["cpu_idle"]
    if total_delta == 0:
        return 0.0
    return round((1.0 - idle_delta / total_delta) * 100.0, 2)


def get_memory_mb():
    """Đọc RAM usage từ /proc/meminfo."""
    try:
        meminfo = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        used_mb = round((total - available) / 1024, 2)
        return used_mb
    except Exception:
        return -1


def get_iface_stats(iface):
    """
    Đọc packet/byte counters của interface từ /proc/net/dev.
    Dùng để tính drop rate và throughput.
    """
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f:
                if iface in line:
                    parts = line.split()
                    # Format: iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets ...
                    return {
                        "rx_packets": int(parts[2]),
                        "rx_drop": int(parts[4]),
                        "tx_packets": int(parts[10]),
                    }
    except Exception:
        pass
    return {"rx_packets": -1, "rx_drop": -1, "tx_packets": -1}


def get_iptables_drop_count():
    """
    Đọc tổng số packet bị Iptables drop.
    Parse output của 'iptables -nvL' và cộng tồn tất cả DROP target.
    Cần chạy với quyền root.
    """
    try:
        result = subprocess.run(
            ["iptables", "-nvL", "--line-numbers"],
            capture_output=True, text=True, timeout=2
        )
        total_drops = 0
        for line in result.stdout.splitlines():
            parts = line.split()
            # Dòng có DROP target, cột 3 là target, cột 1 là packet count
            if len(parts) >= 3 and parts[2] == "DROP":
                try:
                    # iptables dùng K/M suffix — xử lý đơn giản
                    count_str = parts[0]
                    if count_str.endswith("K"):
                        total_drops += int(float(count_str[:-1]) * 1000)
                    elif count_str.endswith("M"):
                        total_drops += int(float(count_str[:-1]) * 1_000_000)
                    else:
                        total_drops += int(count_str)
                except ValueError:
                    pass
        return total_drops
    except Exception:
        return -1


def get_nginx_conn_stats():
    """
    Đọc số lượng TCP connection đến port 80 của nginx.
    Dùng 'ss' để lấy ESTABLISHED và TIME_WAIT connections.
    Quan trọng cho kịch bản Slow Loris — connection count tăng là dấu hiệu tấn công.
    """
    try:
        result = subprocess.run(
            ["ss", "-tn", "state", "established", "dport", ":80"],
            capture_output=True, text=True, timeout=2
        )
        # Đếm số dòng (trừ header)
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        established = max(0, len(lines) - 1)  # trừ dòng header

        result2 = subprocess.run(
            ["ss", "-tn", "state", "close-wait", "dport", ":80"],
            capture_output=True, text=True, timeout=2
        )
        lines2 = [l for l in result2.stdout.splitlines() if l.strip()]
        close_wait = max(0, len(lines2) - 1)

        return {
            "nginx_conn_established": established,
            "nginx_conn_close_wait": close_wait,
        }
    except Exception:
        return {"nginx_conn_established": -1, "nginx_conn_close_wait": -1}


# ===========================================================================
# MAIN LOOP
# ===========================================================================

# Flag để dừng gracefully khi nhận Ctrl+C hoặc SIGTERM
running = True

def handle_signal(signum, frame):
    global running
    running = False
    print("\n[monitor] Nhận tín hiệu dừng, đang ghi nốt dữ liệu và thoát...")


def main():
    parser = argparse.ArgumentParser(description="Thu thập metrics thực nghiệm firewall")
    parser.add_argument("--phase", required=True,
                        help="Tên phase thực nghiệm (vd: baseline, iptables_only, feedback_loop)")
    parser.add_argument("--output", required=True,
                        help="Đường dẫn file CSV output (vd: results/exp1a.csv)")
    parser.add_argument("--append", action="store_true",
                        help="Nếu có flag này, append vào file CSV thay vì ghi đè")
    parser.add_argument("--interval", type=float, default=SAMPLE_INTERVAL,
                        help=f"Khoảng cách lấy mẫu tính bằng giây (mặc định: {SAMPLE_INTERVAL})")
    args = parser.parse_args()

    # Đăng ký signal handler để dừng gracefully
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Tạo thư mục output nếu chưa có
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)

    # Xác định mode ghi file: ghi đè hoặc append
    file_mode = "a" if args.append else "w"

    # Các cột của CSV — thứ tự này cố định, không thay đổi giữa các phase
    fieldnames = [
        "timestamp",            # ISO 8601
        "phase",                # tên phase do người dùng truyền vào
        "cpu_percent",          # system-wide CPU usage
        "mem_mb",               # RAM đang dùng (MB)
        "nginx_latency_ms",     # latency probe đến nginx
        "nginx_http_status",    # HTTP status code (0 = không kết nối được)
        "legitimate_user_ok",   # 1 nếu HTTP 200 và latency < ngưỡng, 0 nếu không
        "nginx_conn_established",  # TCP ESTABLISHED đến port 80
        "nginx_conn_close_wait",   # TCP CLOSE_WAIT (dấu hiệu Slow Loris)
        "xdp_cpu_percent",      # CPU từ XDP health API
        "xdp_mem_mb",           # RAM từ XDP health API
        "xdp_attached",         # XDP có đang attach không (1/0)
        "xdp_rules_count",      # Số rule đang active trong BPF Map
        "iptables_drops_total", # Tổng packet bị Iptables drop
        "iface_rx_packets",     # Packet nhận vào trên interface
        "iface_rx_drop",        # Packet bị drop tại interface (kernel/driver level)
    ]

    with open(args.output, file_mode, newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Chỉ ghi header nếu đang tạo file mới
        if file_mode == "w":
            writer.writeheader()

        print(f"[monitor] Bắt đầu thu thập metrics — phase: {args.phase}")
        print(f"[monitor] Output: {args.output} (mode: {'append' if args.append else 'new file'})")
        print(f"[monitor] Interval: {args.interval}s | Nginx target: {NGINX_TARGET}")
        print(f"[monitor] Latency threshold: {LATENCY_THRESHOLD_MS}ms")
        print("[monitor] Nhấn Ctrl+C để dừng\n")

        # Lấy snapshot CPU đầu tiên để tính delta ở iteration tiếp theo
        prev_cpu = get_system_cpu()
        sample_count = 0

        while running:
            loop_start = time.time()

            # --- Thu thập tất cả metrics ---
            curr_cpu = get_system_cpu()
            cpu_pct = calc_cpu_percent(prev_cpu, curr_cpu)
            prev_cpu = curr_cpu

            mem = get_memory_mb()
            nginx = probe_nginx()
            xdp_health = get_xdp_health()
            xdp_rules = get_xdp_rules_count()
            ipt_drops = get_iptables_drop_count()
            iface = get_iface_stats(IFACE)
            conn = get_nginx_conn_stats()

            # --- Tổng hợp vào một row ---
            row = {
                "timestamp": datetime.now().isoformat(),
                "phase": args.phase,
                "cpu_percent": cpu_pct,
                "mem_mb": mem,
                "nginx_latency_ms": nginx["nginx_latency_ms"],
                "nginx_http_status": nginx["nginx_http_status"],
                "legitimate_user_ok": nginx["legitimate_user_ok"],
                "nginx_conn_established": conn["nginx_conn_established"],
                "nginx_conn_close_wait": conn["nginx_conn_close_wait"],
                "xdp_cpu_percent": xdp_health["xdp_cpu_percent"],
                "xdp_mem_mb": xdp_health["xdp_mem_mb"],
                "xdp_attached": xdp_health["xdp_attached"],
                "xdp_rules_count": xdp_rules,
                "iptables_drops_total": ipt_drops,
                "iface_rx_packets": iface["rx_packets"],
                "iface_rx_drop": iface["rx_drop"],
            }

            writer.writerow(row)
            csvfile.flush()  # Ghi ngay, không đợi buffer đầy — quan trọng khi thực nghiệm bị ngắt đột ngột

            sample_count += 1

            # In tóm tắt nhanh ra terminal để theo dõi realtime
            status_icon = "✓" if row["legitimate_user_ok"] == 1 else "✗"
            print(
                f"[{row['timestamp'][:19]}] "
                f"CPU:{cpu_pct:5.1f}% | "
                f"MEM:{mem:6.1f}MB | "
                f"Nginx:{nginx['nginx_http_status']} {nginx['nginx_latency_ms']:6.1f}ms {status_icon} | "
                f"XDP rules:{xdp_rules:4d} | "
                f"IPT drops:{ipt_drops:8d} | "
                f"Conn:{conn['nginx_conn_established']:4d}"
            )

            # Cảnh báo nếu legitimate user bị ảnh hưởng
            if row["legitimate_user_ok"] == 0:
                print(f"  ⚠️  CẢNH BÁO: Legitimate user bị ảnh hưởng! (status={nginx['nginx_http_status']}, latency={nginx['nginx_latency_ms']}ms)")

            # Giữ đúng interval, trừ đi thời gian đã dùng để thu thập
            elapsed = time.time() - loop_start
            sleep_time = max(0, args.interval - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)

    print(f"\n[monitor] Hoàn thành. Đã ghi {sample_count} samples vào {args.output}")


if __name__ == "__main__":
    main()
