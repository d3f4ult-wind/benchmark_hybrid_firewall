#!/usr/bin/env python3
# =============================================================================
# watcher.py — Kịch bản 1b (Slow Loris)
# Đọc Suricata EVE JSON log realtime, extract IP tấn công,
# gọi XDP Core API để block ngay tại tầng driver.
# =============================================================================
# Cách dùng:
#   sudo python3 watcher.py [--eve-log /var/log/suricata/eve.json]
#                           [--xdp-api http://127.0.0.1:8080]
#                           [--log-file feedback_loop_1b.log]
#                           [--dry-run]
#
# --dry-run: in ra những gì sẽ làm nhưng không thực sự gọi API.
#            Dùng để test rule Suricata mà không ảnh hưởng firewall.
# =============================================================================

import argparse
import json
import os
import signal
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CẤU HÌNH MẶC ĐỊNH
# ─────────────────────────────────────────────────────────────────────────────

EVE_LOG_PATH   = "/var/log/suricata/eve.json"
XDP_API_BASE   = "http://127.0.0.1:8080"
LOG_FILE_PATH  = "feedback_loop_1b.log"

# Danh sách port TCP cần block khi phát hiện IP xấu.
# QUAN TRỌNG — lỗi thiết kế exact-match trong XDP Core:
#   rule_map dùng BPF_MAP_TYPE_HASH với key {subnet_id, proto, port}.
#   port=0 KHÔNG phải wildcard — phải gọi API riêng cho từng port.
#   Xem chi tiết ở phần 3 của instruction.md.
PORTS_TO_BLOCK = [80]   # Thêm 443 vào đây nếu cần

# Thời gian debounce: sau khi đã block một IP, bỏ qua mọi alert
# thêm cho IP đó trong N giây. Tránh gọi API lặp lại vô ích.
DEBOUNCE_SECONDS = 10

# IP không bao giờ được block — legitimate user probe.
# ns_50 là điều kiện thành công bắt buộc của mọi kịch bản.
WHITELIST = {"10.10.1.50"}

# Tên signature trong Suricata alert để lọc — chỉ phản ứng với
# alert liên quan đến Slow Loris, không phản ứng với alert khác.
SLOWLORIS_KEYWORDS = ["SLOWLORIS", "slowloris", "slow attack", "connection flood"]

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

log_fh = None  # file handle, mở ở main()

def log(msg: str):
    """Ghi log ra file và stdout đồng thời."""
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    if log_fh:
        log_fh.write(line + "\n")
        log_fh.flush()

# ─────────────────────────────────────────────────────────────────────────────
# XDP API — helper functions
# ─────────────────────────────────────────────────────────────────────────────

def xdp_post_rule(ip: str, proto: int, port: int, dry_run: bool) -> bool:
    """
    Gọi POST /rules để thêm một rule block vào BPF Map.

    Trả về True nếu thành công (hoặc dry-run), False nếu lỗi.
    Sau khi rule vào Map, XDP lookup hoàn toàn trong kernel — overhead
    của HTTP call này chỉ xảy ra một lần duy nhất per IP/port.
    """
    payload = json.dumps({
        "subnet": f"{ip}/32",   # block đúng IP đó, không phải cả subnet
        "proto":  proto,
        "port":   port,
        "action": "DROP"
    }).encode()

    if dry_run:
        log(f"  [DRY-RUN] POST /rules → subnet={ip}/32 proto={proto} port={port}")
        return True

    req = urllib.request.Request(
        url    = f"{XDP_API_BASE}/rules",
        data   = payload,
        method = "POST",
        headers= {"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status in (200, 201)
    except urllib.error.URLError as e:
        log(f"  [ERROR] POST /rules thất bại: {e}")
        return False

def xdp_verify_rule(ip: str, dry_run: bool) -> bool:
    """
    Gọi GET /rules để verify rule của IP đã thực sự vào BPF Map.
    Trả về True nếu tìm thấy.
    """
    if dry_run:
        return True
    try:
        req = urllib.request.Request(f"{XDP_API_BASE}/rules", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            # data thường là list các rule, mỗi rule có field "subnet"
            rules = data if isinstance(data, list) else data.get("rules", [])
            return any(ip in r.get("subnet", "") for r in rules)
    except Exception as e:
        log(f"  [WARN] Không verify được rule: {e}")
        return False

def block_ip(ip: str, dry_run: bool, t_detected: float):
    """
    Block một IP bằng cách gọi XDP API cho từng port trong PORTS_TO_BLOCK
    và cho ICMP (proto=1, port=0).

    Ghi timestamp chính xác để tính detection + response latency.
    Latency = thời điểm XDP API trả về thành công − t_detected (lúc alert xuất hiện trong log).
    """
    t_start = time.time()
    log(f"[BLOCK] Phát hiện IP tấn công: {ip}")
    log(f"        Detection latency (alert→watcher): {(t_start - t_detected)*1000:.1f} ms")

    success = True

    # Block TCP trên từng port riêng lẻ — vì exact-match, không có wildcard
    for port in PORTS_TO_BLOCK:
        ok = xdp_post_rule(ip, proto=6, port=port, dry_run=dry_run)
        log(f"  → TCP port {port}: {'OK' if ok else 'FAIL'}")
        success = success and ok

    # Block ICMP — với ICMP, port=0 là bắt buộc (hardcode trong xdp-filter.c)
    ok = xdp_post_rule(ip, proto=1, port=0, dry_run=dry_run)
    log(f"  → ICMP (proto=1, port=0): {'OK' if ok else 'FAIL'}")
    success = success and ok

    if success:
        t_end = time.time()
        log(f"  [LATENCY] Tổng detection+response latency: {(t_end - t_detected)*1000:.1f} ms")

        # Verify rule đã vào BPF Map
        if xdp_verify_rule(ip, dry_run):
            log(f"  [VERIFY] Rule của {ip} đã xác nhận có trong BPF Map.")
        else:
            log(f"  [WARN] Không tìm thấy rule của {ip} trong BPF Map sau khi push!")
    else:
        log(f"  [ERROR] Có lỗi khi block {ip} — xem log ở trên.")

# ─────────────────────────────────────────────────────────────────────────────
# EVE JSON TAIL
# ─────────────────────────────────────────────────────────────────────────────


# Flag toàn cục để dừng gracefully khi nhận SIGTERM hoặc Ctrl+C
watcher_running = True


def handle_stop_signal(signum, frame):
    global watcher_running
    watcher_running = False


signal.signal(signal.SIGTERM, handle_stop_signal)
signal.signal(signal.SIGINT,  handle_stop_signal)


def is_slowloris_alert(event: dict) -> bool:

    """
    Kiểm tra một event từ EVE JSON có phải alert Slow Loris không.
    Chỉ xét event_type == "alert" và signature chứa keyword liên quan.
    """
    if event.get("event_type") != "alert":
        return False
    sig = event.get("alert", {}).get("signature", "")
    return any(kw in sig for kw in SLOWLORIS_KEYWORDS)

def tail_eve_log(path: str, dry_run: bool):
    """
    Mở EVE JSON log và đọc realtime (giống `tail -f`).
    Với mỗi dòng JSON mới, parse và xử lý nếu là alert Slow Loris.

    Dùng seek đến cuối file lúc đầu để tránh xử lý các alert cũ từ lần chạy trước.
    """
    blocked     = {}  # {ip: timestamp_lần_block_cuối} — dùng cho debounce
    line_buffer = ""

    log(f"[WATCHER] Bắt đầu theo dõi: {path}")
    log(f"[WATCHER] XDP API: {XDP_API_BASE}")
    log(f"[WATCHER] Ports sẽ block: TCP {PORTS_TO_BLOCK} + ICMP")
    log(f"[WATCHER] Whitelist (không bao giờ block): {WHITELIST}")
    if dry_run:
        log("[WATCHER] *** CHẾ ĐỘ DRY-RUN — không gọi XDP API thực sự ***")

    # Chờ file tồn tại — Suricata có thể chưa tạo file ngay
    while not os.path.exists(path):
        log(f"[WATCHER] Chờ file {path} xuất hiện...")
        time.sleep(2)

    with open(path, "r") as f:
        # Seek đến cuối để chỉ đọc event mới từ lúc watcher khởi động
        f.seek(0, 2)
        log("[WATCHER] Đang chờ alert từ Suricata...")

        while watcher_running:
            line = f.readline()
            if not line:
                # Không có data mới, sleep ngắn rồi thử lại
                time.sleep(0.1)
                continue

            line = line.strip()
            if not line:
                continue

            # Parse JSON — bỏ qua dòng lỗi format
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Lấy timestamp từ event để tính latency chính xác
            # EVE JSON dùng ISO 8601, ví dụ: "2025-01-01T12:00:00.123456+0000"
            try:
                ts_str = event.get("timestamp", "")
                # Python 3.7+ hỗ trợ fromisoformat nhưng không nhận "+0000"
                # Normalize về format chuẩn
                ts_str_clean = ts_str.replace("+0000", "+00:00").replace("Z", "+00:00")
                from datetime import timezone
                t_detected = datetime.fromisoformat(ts_str_clean).timestamp()
            except Exception:
                # Fallback: dùng thời điểm watcher đọc được dòng này
                t_detected = time.time()

            if not is_slowloris_alert(event):
                continue

            src_ip  = event.get("src_ip", "")
            sig     = event.get("alert", {}).get("signature", "unknown")

            if not src_ip:
                continue

            # Kiểm tra whitelist — ns_50 không bao giờ bị block
            if src_ip in WHITELIST:
                log(f"[SKIP] {src_ip} có trong whitelist, bỏ qua alert: {sig}")
                continue

            # Debounce — tránh gọi API nhiều lần cho cùng IP trong thời gian ngắn
            now = time.time()
            last_blocked = blocked.get(src_ip, 0)
            if now - last_blocked < DEBOUNCE_SECONDS:
                # IP này vừa được block rồi, bỏ qua
                continue

            log(f"[ALERT] Suricata: {sig} | src={src_ip}")
            blocked[src_ip] = now
            block_ip(src_ip, dry_run, t_detected)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    global XDP_API_BASE, log_fh

    parser = argparse.ArgumentParser(
        description="Suricata EVE watcher → XDP feedback loop (kịch bản 1b Slow Loris)"
    )
    parser.add_argument("--eve-log",  default=EVE_LOG_PATH,  help="Đường dẫn file eve.json")
    parser.add_argument("--xdp-api",  default=XDP_API_BASE,  help="Base URL của XDP Core API")
    parser.add_argument("--log-file", default=LOG_FILE_PATH, help="File ghi evidence log")
    parser.add_argument("--dry-run",  action="store_true",   help="Không gọi API, chỉ in ra màn hình")
    args = parser.parse_args()

    XDP_API_BASE = args.xdp_api

    # Mở file log
    log_fh = open(args.log_file, "a")
    log("=" * 70)
    log("WATCHER KHỞI ĐỘNG — Kịch bản 1b Slow Loris")
    log("=" * 70)

    try:
        tail_eve_log(args.eve_log, args.dry_run)
    except KeyboardInterrupt:
        log("[WATCHER] Dừng bởi người dùng (Ctrl+C).")
    finally:
        log_fh.close()

if __name__ == "__main__":
    main()