#!/usr/bin/env python3
# =============================================================================
# load_geoip_xdp.py — Kịch bản 2 (GeoIP)
# Đọc file GeoLite2-Country-Blocks-IPv4.csv, lọc CIDR của quốc gia chỉ định,
# nạp vào XDP BPF Map (subnet_map / rule_map) qua REST API.
#
# Mục đích benchmark: chứng minh BPF LPM Trie lookup là O(1) theo số entries —
# khi ruleset tăng từ 100 lên 10.000 CIDR, latency của XDP không thay đổi.
# So sánh với Iptables/ipset ở load_geoip_iptables.sh.
# =============================================================================
# Cách dùng:
#   sudo python3 load_geoip_xdp.py \
#       --blocks  GeoLite2-Country-Blocks-IPv4.csv \
#       --locations GeoLite2-Country-Locations-en.csv \
#       --country CN \
#       --limit 1000 \
#       [--clear-first] \
#       [--dry-run]
#
# --limit: số CIDR tối đa nạp vào (dùng cho 5 mức: 100/500/1000/5000/10000)
# --clear-first: xóa toàn bộ rules cũ trước khi nạp (dùng khi đổi mức ruleset)
# --dry-run: chỉ parse và in ra, không gọi API
# =============================================================================

import argparse
import csv
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

XDP_API_BASE = "http://127.0.0.1:8080"

# ns_50 là legitimate user — không bao giờ được nằm trong ruleset
WHITELIST_CHECK = ["10.10.1.50/32", "10.10.1.0/24", "10.10.2.0/24"]

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}", flush=True)

# -----------------------------------------------------------------------------
# BƯỚC 1: Đọc file locations để map geoname_id → country_iso_code
# GeoLite2 dùng hai file riêng: Blocks chứa CIDR + geoname_id,
# Locations chứa geoname_id + country_iso_code. Cần join hai file.
# -----------------------------------------------------------------------------
def build_geoname_map(locations_path: str, country_code: str) -> set:
    """
    Trả về set các geoname_id thuộc về country_code chỉ định.
    Dùng set vì tra cứu O(1) khi duyệt qua hàng triệu dòng Blocks.
    """
    geonames = set()
    with open(locations_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("country_iso_code", "").upper() == country_code.upper():
                gid = row.get("geoname_id", "").strip()
                if gid:
                    geonames.add(gid)
    log(f"Tìm thấy {len(geonames)} geoname_id cho quốc gia '{country_code}'.")
    return geonames

# -----------------------------------------------------------------------------
# BƯỚC 2: Lọc CIDR từ file Blocks theo geoname_id
# -----------------------------------------------------------------------------
def load_cidrs(blocks_path: str, geonames: set, limit: int) -> list:
    """
    Đọc file Blocks, trả về danh sách CIDR (tối đa `limit` entries)
    thuộc về các geoname_id đã lọc.
    """
    cidrs = []
    with open(blocks_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if len(cidrs) >= limit:
                break
            gid = row.get("geoname_id", "").strip()
            if not gid:
                # Một số dòng dùng registered_country_geoname_id thay thế
                gid = row.get("registered_country_geoname_id", "").strip()
            if gid in geonames:
                cidr = row.get("network", "").strip()
                if cidr:
                    cidrs.append(cidr)
    log(f"Đã lọc {len(cidrs)} CIDR (giới hạn {limit}).")
    return cidrs

# -----------------------------------------------------------------------------
# BƯỚC 3: Kiểm tra whitelist — đảm bảo không block nhầm legitimate user
# Đây là kiểm tra an toàn bắt buộc trước khi nạp bất kỳ rule nào.
# -----------------------------------------------------------------------------
def check_whitelist_collision(cidrs: list) -> bool:
    """
    Kiểm tra xem có CIDR nào trong danh sách có thể block ns_50 (10.10.1.50)
    không. Trong thực tế dataset GeoLite2 dùng IP public nên sẽ không có
    xung đột với 10.10.x.x, nhưng kiểm tra vẫn cần thiết để đảm bảo.
    Trả về True nếu an toàn (không có xung đột).
    """
    # Dải 10.x.x.x là RFC1918 private — không bao giờ xuất hiện trong GeoLite2
    # Nhưng vẫn kiểm tra prefix cơ bản để chắc chắn
    for cidr in cidrs:
        if cidr.startswith("10."):
            log(f"[WARN] CIDR {cidr} nằm trong dải 10.x.x.x — có thể ảnh hưởng lab!")
            return False
    return True

# -----------------------------------------------------------------------------
# BƯỚC 4: Xóa toàn bộ rules cũ (nếu --clear-first)
# Cần thiết khi chuyển giữa các mức ruleset trong benchmark
# -----------------------------------------------------------------------------
def clear_all_rules(dry_run: bool):
    if dry_run:
        log("[DRY-RUN] Bỏ qua bước xóa rules.")
        return
    try:
        req = urllib.request.Request(f"{XDP_API_BASE}/rules", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            rules = data if isinstance(data, list) else data.get("rules", [])

        deleted = 0
        for r in rules:
            payload = json.dumps(r).encode()
            del_req = urllib.request.Request(
                f"{XDP_API_BASE}/rules",
                data=payload, method="DELETE",
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(del_req, timeout=5)
            deleted += 1
        log(f"Đã xóa {deleted} rules cũ.")
    except Exception as e:
        log(f"[WARN] Lỗi khi xóa rules: {e}")

# -----------------------------------------------------------------------------
# BƯỚC 5: Nạp CIDR vào XDP qua REST API
#
# Lưu ý thiết kế quan trọng: mỗi CIDR cần 2 API call riêng biệt vì lỗi
# exact-match trong XDP Core — một call cho TCP port 80, một cho ICMP port 0.
# Đây là chi phí của lỗi thiết kế kế thừa, không thể tránh khỏi cho đến khi
# source code được sửa.
#
# Để tránh làm chậm quá trình nạp, script dùng batch logging: chỉ in tiến độ
# mỗi 100 entries thay vì mỗi entry.
# -----------------------------------------------------------------------------
def push_rules_to_xdp(cidrs: list, dry_run: bool) -> dict:
    """
    Nạp từng CIDR vào BPF Map qua XDP API.
    Trả về dict chứa thống kê: tổng số call, thành công, thất bại, thời gian.
    """
    stats = {"total": 0, "success": 0, "failed": 0, "elapsed_ms": 0}
    t_start = time.time()

    for i, cidr in enumerate(cidrs):
        # TCP port 80 — vì exact-match, phải chỉ định port cụ thể
        for proto, port in [(6, 80), (1, 0)]:  # TCP port 80, ICMP port 0
            payload = json.dumps({
                "subnet": cidr,
                "proto":  proto,
                "port":   port,
                "action": "DROP"
            }).encode()

            stats["total"] += 1

            if dry_run:
                stats["success"] += 1
                continue

            req = urllib.request.Request(
                f"{XDP_API_BASE}/rules",
                data=payload, method="POST",
                headers={"Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status in (200, 201):
                        stats["success"] += 1
                    else:
                        stats["failed"] += 1
            except urllib.error.URLError as e:
                stats["failed"] += 1
                if stats["failed"] <= 5:  # chỉ log 5 lỗi đầu để tránh spam
                    log(f"  [ERROR] {cidr} proto={proto}: {e}")

        # In tiến độ mỗi 100 CIDR
        if (i + 1) % 100 == 0 or (i + 1) == len(cidrs):
            elapsed = (time.time() - t_start) * 1000
            log(f"  Tiến độ: {i+1}/{len(cidrs)} CIDR — {elapsed:.0f}ms đã trôi qua")

    stats["elapsed_ms"] = (time.time() - t_start) * 1000
    return stats

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------
def main():
    global XDP_API_BASE # Khai báo global cho biến XDP_API_BASE
    parser = argparse.ArgumentParser(
        description="Nạp GeoIP CIDR vào XDP BPF Map — kịch bản 2"
    )
    parser.add_argument("--blocks",    required=True, help="GeoLite2-Country-Blocks-IPv4.csv")
    parser.add_argument("--locations", required=True, help="GeoLite2-Country-Locations-en.csv")
    parser.add_argument("--country",   default="CN",  help="ISO country code (mặc định: CN)")
    parser.add_argument("--limit",     type=int, default=1000,
                        help="Số CIDR tối đa nạp vào (100/500/1000/5000/10000)")
    parser.add_argument("--clear-first", action="store_true",
                        help="Xóa toàn bộ rules cũ trước khi nạp")
    parser.add_argument("--xdp-api",  default=XDP_API_BASE,
                        help="Base URL của XDP Core API")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Parse và in ra nhưng không gọi API")
    args = parser.parse_args()

    
    XDP_API_BASE = args.xdp_api

    log("=" * 60)
    log(f"load_geoip_xdp.py — country={args.country}, limit={args.limit}")
    log("=" * 60)

    # Kiểm tra XDP API còn sống không
    if not args.dry_run:
        try:
            urllib.request.urlopen(f"{XDP_API_BASE}/health", timeout=5)
        except Exception:
            log("[ERROR] XDP Core API không phản hồi. Dừng lại.")
            sys.exit(1)

    # Pipeline: locations → geonames → CIDRs → whitelist check → push
    geonames = build_geoname_map(args.locations, args.country)
    if not geonames:
        log(f"[ERROR] Không tìm thấy geoname_id nào cho '{args.country}'. Kiểm tra file locations.")
        sys.exit(1)

    cidrs = load_cidrs(args.blocks, geonames, args.limit)
    if not cidrs:
        log("[ERROR] Không lọc được CIDR nào. Kiểm tra file blocks và country code.")
        sys.exit(1)

    if not check_whitelist_collision(cidrs):
        log("[ERROR] Phát hiện xung đột với dải IP lab. Dừng lại để bảo vệ ns_50.")
        sys.exit(1)
    log("[OK] Không có xung đột với dải IP lab.")

    if args.clear_first:
        clear_all_rules(args.dry_run)

    log(f"Bắt đầu nạp {len(cidrs)} CIDR vào XDP BPF Map...")
    stats = push_rules_to_xdp(cidrs, args.dry_run)

    log("")
    log("─" * 60)
    log(f"KẾT QUẢ NẠP:")
    log(f"  CIDR đã xử lý:   {len(cidrs)}")
    log(f"  API calls tổng:  {stats['total']} (mỗi CIDR = 2 calls: TCP+ICMP)")
    log(f"  Thành công:      {stats['success']}")
    log(f"  Thất bại:        {stats['failed']}")
    log(f"  Thời gian nạp:   {stats['elapsed_ms']:.0f} ms")
    log(f"  Tốc độ nạp:      {len(cidrs) / (stats['elapsed_ms']/1000):.1f} CIDR/s")
    if args.dry_run:
        log("  (DRY-RUN — không có rule nào thực sự được nạp)")
    log("─" * 60)

if __name__ == "__main__":
    main()