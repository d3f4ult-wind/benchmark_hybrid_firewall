#!/usr/bin/env python3
"""
feedback_loop_iptables.py — Feedback Loop: Iptables → XDP (Kịch bản 1a)
========================================================================
Luồng hoạt động:
  1. Iptables đang chặn SYN Flood với rule LOG+DROP — mỗi packet bị drop
     sẽ để lại một dòng trong kernel log với prefix "XDP_CANDIDATE: ".
  2. Script này đọc kernel log realtime (tail /var/log/kern.log hoặc journald).
  3. Khi phát hiện IP mới bị Iptables log, gọi XDP API để push IP đó
     xuống BPF Map với action DROP.
  4. Từ packet tiếp theo, XDP drop tại driver — Iptables không còn phải
     xử lý IP đó nữa, giải phóng tài nguyên.

Ghi chú thiết kế — tại sao dùng LOG prefix thay vì parse iptables -nvL:
  Đọc counter từ "iptables -nvL" chỉ cho biết tổng số packet bị drop,
  không cho biết IP nào đang bị drop. LOG target ghi đúng src IP vào log,
  đây là thông tin cần để gọi API.

Ghi chú về port trong XDP API:
  Do hạn chế của mã nguồn kế thừa (rule_map dùng BPF_MAP_TYPE_HASH với
  exact-match key), port=0 KHÔNG phải wildcard cho TCP/UDP. Nếu attacker
  tấn công vào port 80, ta phải gọi API với port=80. Script này block
  một danh sách port phổ biến cho mỗi IP xấu được phát hiện.
  Riêng ICMP (proto=1) thì port=0 là đúng và bắt buộc.

Cách dùng:
  sudo python3 feedback_loop_iptables.py
  sudo python3 feedback_loop_iptables.py --log-file /var/log/kern.log
  sudo python3 feedback_loop_iptables.py --use-journald
"""

import argparse
import json
import re
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# ===========================================================================
# CẤU HÌNH
# ===========================================================================

# Địa chỉ XDP Core REST API
XDP_API_BASE = "http://127.0.0.1:8080"

# Prefix trong iptables LOG rule — phải khớp với setup_rules_1a.sh
# Iptables sẽ log mỗi packet bị DROP với prefix này vào kernel log
IPTABLES_LOG_PREFIX = "XDP_CANDIDATE: "

# Đường dẫn kernel log mặc định (Ubuntu/Debian)
# Nếu distro dùng journald không có file này → dùng flag --use-journald
DEFAULT_LOG_FILE = "/var/log/kern.log"

# Danh sách port cần block cho mỗi IP xấu bị phát hiện.
# Lý do cần list này: XDP API yêu cầu exact-match port (không có wildcard).
# Kịch bản 1a tập trung vào SYN Flood vào port 80 của nginx.
# Thêm port khác nếu kịch bản thực tế cần.
# Máy mạnh hơn / kịch bản phức tạp hơn: thêm 443, 8080, etc.
PORTS_TO_BLOCK = [80]

# Protocols cần block: TCP=6, UDP=17, ICMP=1
# Kịch bản 1a dùng SYN Flood (TCP). Nếu test UDP Flood thì thêm 17.
PROTOS_TO_BLOCK = [
    {"proto": 6, "ports": PORTS_TO_BLOCK},   # TCP — SYN Flood
    {"proto": 1, "ports": [0]},               # ICMP — port=0 là bắt buộc (xem ghi chú trên)
]

# Thời gian chờ tối thiểu giữa hai lần xử lý cùng một IP (giây)
# Tránh gọi API nhiều lần cho cùng một IP khi log xuất hiện liên tục
DEBOUNCE_SECONDS = 5.0

# Thời gian timeout cho mỗi lần gọi XDP API (giây)
API_TIMEOUT = 2.0

# File log của chính script này — để làm evidence trong báo cáo
FEEDBACK_LOG_FILE = "feedback_loop_1a.log"

# ===========================================================================
# REGEX PARSE KERNEL LOG
# ===========================================================================

# Pattern để parse dòng log từ iptables LOG target.
# Ví dụ dòng log thực tế:
# May 10 12:34:56 firewall kernel: [12345.678] XDP_CANDIDATE: IN=enp0s3 OUT= SRC=10.10.1.2 DST=10.10.2.2 PROTO=TCP ...
LOG_PATTERN = re.compile(
    r"XDP_CANDIDATE:.*?SRC=(\d+\.\d+\.\d+\.\d+).*?DST=(\d+\.\d+\.\d+\.\d+).*?PROTO=(\w+)"
)

# ===========================================================================
# STATE
# ===========================================================================

running = True
# Dict lưu IP đã xử lý và timestamp lần xử lý gần nhất
# Format: { "10.10.1.2": 1234567890.123 }
processed_ips: dict[str, float] = {}
journald_proc = None  # tham chiếu tới subprocess journalctl — để terminate khi nhận signal


def handle_signal(signum, frame):
    global running, journald_proc
    running = False
    # Terminate journalctl subprocess ngay lập tức để giải phóng readline() khỏi trạng thái block
    if journald_proc and journald_proc.poll() is None:
        journald_proc.terminate()
    print("\n[feedback_loop] Nhận tín hiệu dừng...")


# ===========================================================================
# LOGGING
# ===========================================================================

def log(message: str):
    """
    Ghi log ra terminal và file cùng lúc.
    File log này là evidence quan trọng cho báo cáo — ghi lại chính xác
    thời điểm nào IP nào được push xuống XDP.
    """
    timestamp = datetime.now().isoformat()
    line = f"[{timestamp}] {message}"
    print(line)
    try:
        with open(FEEDBACK_LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ===========================================================================
# XDP API
# ===========================================================================

def push_ip_to_xdp(ip: str) -> bool:
    """
    Đẩy một IP xuống XDP để block bằng cách gọi POST /rules cho từng
    proto/port combination cần thiết.

    Trả về True nếu tất cả các lần gọi API thành công, False nếu có lỗi.

    Ghi chú về thiết kế API: REST API chỉ là control plane — overhead HTTP
    ở đây chỉ xảy ra một lần duy nhất cho mỗi IP. Sau khi rule được ghi
    vào BPF Map, mọi packet của IP đó bị XDP drop tại driver mà không
    đi qua API nữa.
    """
    all_success = True
    subnet = f"{ip}/32"  # Block chính xác IP đơn lẻ, không phải cả subnet

    for proto_config in PROTOS_TO_BLOCK:
        proto = proto_config["proto"]
        for port in proto_config["ports"]:
            payload = {
                "subnet": subnet,
                "proto": proto,
                "port": port,
                "action": "DROP"
            }
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    f"{XDP_API_BASE}/rules",
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
                    status = resp.status
                    if status in (200, 201):
                        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
                        log(f"  ✓ XDP rule added: {subnet} proto={proto_name} port={port} action=DROP")
                    else:
                        log(f"  ✗ XDP API returned unexpected status {status} for {subnet} proto={proto} port={port}")
                        all_success = False
            except urllib.error.URLError as e:
                log(f"  ✗ XDP API connection error: {e.reason}")
                all_success = False
            except Exception as e:
                log(f"  ✗ XDP API unexpected error: {e}")
                all_success = False

    return all_success


def verify_xdp_rule_exists(ip: str) -> bool:
    """
    Sau khi push rule, gọi GET /rules để xác nhận rule đã được ghi vào
    BPF Map thành công. Đây là bước verification quan trọng — đảm bảo
    feedback loop thực sự có hiệu lực trước khi script kết luận đã block.
    """
    try:
        req = urllib.request.Request(f"{XDP_API_BASE}/rules", method="GET")
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            rules = json.loads(resp.read().decode())
            subnet = f"{ip}/32"
            for rule in rules:
                if rule.get("subnet") == subnet:
                    return True
            return False
    except Exception:
        return False  # Không verify được, nhưng không block flow


# ===========================================================================
# LOG PARSING
# ===========================================================================

def process_log_line(line: str):
    """
    Parse một dòng kernel log, kiểm tra xem có phải log từ Iptables không,
    extract IP attacker, và push xuống XDP nếu cần.
    """
    if IPTABLES_LOG_PREFIX not in line:
        return

    match = LOG_PATTERN.search(line)
    if not match:
        return

    src_ip = match.group(1)
    dst_ip = match.group(2)
    proto_str = match.group(3)

    # Bỏ qua nếu IP này đã được xử lý gần đây (debounce)
    now = time.time()
    last_processed = processed_ips.get(src_ip, 0)
    if now - last_processed < DEBOUNCE_SECONDS:
        return

    # Đánh dấu IP này đang được xử lý
    processed_ips[src_ip] = now

    log(f"[DETECTED] Iptables log: SRC={src_ip} DST={dst_ip} PROTO={proto_str}")
    log(f"[ACTION]   Đang đẩy {src_ip} xuống XDP để block tại driver...")

    # Gọi XDP API để push rule
    t_start = time.time()
    success = push_ip_to_xdp(src_ip)
    t_elapsed = (time.time() - t_start) * 1000

    if success:
        # Verify rule đã được ghi vào BPF Map
        if verify_xdp_rule_exists(src_ip):
            log(f"[VERIFIED] IP {src_ip} đã được confirm trong BPF Map. "
                f"XDP sẽ block tất cả traffic từ IP này tại driver. "
                f"Thời gian push API: {t_elapsed:.1f}ms")
        else:
            log(f"[WARNING]  API call thành công nhưng KHÔNG tìm thấy rule trong BPF Map. "
                f"Kiểm tra lại XDP Core.")
    else:
        log(f"[ERROR]    Không thể push {src_ip} xuống XDP. "
                f"Iptables vẫn tiếp tục xử lý IP này.")


# ===========================================================================
# MAIN — HAI CHẾ ĐỘ ĐỌC LOG
# ===========================================================================

def tail_log_file(log_file: str):
    """
    Đọc log file theo kiểu tail -f — theo dõi realtime.
    Phù hợp khi hệ thống ghi kern.log ra file (Ubuntu với rsyslog).
    """
    log(f"[feedback_loop] Đọc kernel log từ file: {log_file}")
    log(f"[feedback_loop] Chờ Iptables LOG với prefix: '{IPTABLES_LOG_PREFIX}'")

    try:
        # Mở file và seek đến cuối để chỉ đọc các dòng mới
        with open(log_file, "r") as f:
            f.seek(0, 2)  # Seek đến cuối file

            while running:
                line = f.readline()
                if line:
                    process_log_line(line.rstrip())
                else:
                    # Không có dòng mới — chờ một chút rồi thử lại
                    time.sleep(0.05)
    except FileNotFoundError:
        log(f"[ERROR] Không tìm thấy file log: {log_file}")
        log("[ERROR] Thử dùng --use-journald nếu hệ thống dùng systemd-journald")
        sys.exit(1)


def tail_journald():
    """
    Đọc kernel log từ journald realtime bằng subprocess.
    Phù hợp khi hệ thống dùng systemd và không có /var/log/kern.log.
    Ubuntu 20.04+ mặc định dùng journald.
    """
    global journald_proc
    log("[feedback_loop] Đọc kernel log từ journald (journalctl -kf)")
    log(f"[feedback_loop] Chờ Iptables LOG với prefix: '{IPTABLES_LOG_PREFIX}'")

    try:
        # journalctl -k = kernel messages, -f = follow (realtime), -n 0 = bỏ qua log cũ
        journald_proc = subprocess.Popen(
            ["journalctl", "-kf", "-n", "0", "--output=short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1  # Line-buffered
        )

        import select
        while running:
            # Dùng select với timeout 0.5s thay vì readline() blocking mãi
            # Khi running = False và proc bị terminate, select sẽ trả về ngay
            ready, _, _ = select.select([journald_proc.stdout], [], [], 0.5)
            if ready:
                line = journald_proc.stdout.readline()
                if line:
                    process_log_line(line.rstrip())
                else:
                    break  # EOF — proc đã kết thúc

        if journald_proc.poll() is None:
            journald_proc.terminate()
            journald_proc.wait(timeout=3)

    except FileNotFoundError:
        log("[ERROR] Không tìm thấy journalctl. Thử dùng --log-file thay thế.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Feedback Loop: Iptables → XDP (Kịch bản 1a)"
    )
    parser.add_argument(
        "--log-file", default=DEFAULT_LOG_FILE,
        help=f"Đường dẫn kernel log file (mặc định: {DEFAULT_LOG_FILE})"
    )
    parser.add_argument(
        "--use-journald", action="store_true",
        help="Đọc từ journald thay vì file (dùng khi không có /var/log/kern.log)"
    )
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    log("=" * 60)
    log("Feedback Loop Iptables → XDP — Kịch bản 1a")
    log(f"XDP API: {XDP_API_BASE}")
    log(f"Ports to block per IP: {PORTS_TO_BLOCK}")
    log(f"Protocols: TCP(6), ICMP(1)")
    log(f"Debounce: {DEBOUNCE_SECONDS}s")
    log("=" * 60)

    # Kiểm tra XDP Core có đang chạy không trước khi bắt đầu
    try:
        req = urllib.request.Request(f"{XDP_API_BASE}/health", method="GET")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            health = json.loads(resp.read().decode())
            log(f"[CHECK] XDP Core online. xdp_attached={health.get('xdp_attached')}")
    except Exception as e:
        log(f"[WARNING] Không thể kết nối XDP Core tại {XDP_API_BASE}: {e}")
        log("[WARNING] Script vẫn tiếp tục, nhưng feedback loop sẽ không hoạt động cho đến khi API sẵn sàng.")

    if args.use_journald:
        tail_journald()
    else:
        tail_log_file(args.log_file)

    log(f"[feedback_loop] Đã xử lý {len(processed_ips)} IP(s) trong phiên này:")
    for ip, ts in processed_ips.items():
        log(f"  - {ip} (lần cuối xử lý: {datetime.fromtimestamp(ts).isoformat()})")
    log("Kết thúc.")


if __name__ == "__main__":
    main()
