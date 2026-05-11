#!/usr/bin/env bash
# =============================================================================
# load_geoip_iptables.sh — Kịch bản 2 (GeoIP)
# Nạp CIDR GeoIP vào ipset rồi dùng Iptables FORWARD rule để block.
#
# Mục đích benchmark: so sánh overhead lookup của ipset (dựa trên hash table
# trong kernel) với XDP BPF LPM Trie khi số CIDR tăng dần.
# Lý thuyết: ipset hash:net phải resolve CIDR prefix, overhead tăng theo
# kích thước set; XDP LPM Trie là O(log n) về lý thuyết nhưng được tối ưu
# rất cao trong kernel → thực tế gần như O(1) với kích thước thực tế.
# =============================================================================
# Cách dùng:
#   sudo bash load_geoip_iptables.sh \
#       --blocks  GeoLite2-Country-Blocks-IPv4.csv \
#       --locations GeoLite2-Country-Locations-en.csv \
#       --country CN \
#       --limit   1000 \
#       [--clear-first]
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────
# BIẾN MẶC ĐỊNH
# ─────────────────────────────────────────
BLOCKS_FILE=""
LOCATIONS_FILE=""
COUNTRY="CN"
LIMIT=1000
CLEAR_FIRST=0
IPSET_NAME="geoip_block"

# ─────────────────────────────────────────
# XỬ LÝ THAM SỐ
# ─────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --blocks)     BLOCKS_FILE="$2";    shift 2 ;;
        --locations)  LOCATIONS_FILE="$2"; shift 2 ;;
        --country)    COUNTRY="$2";        shift 2 ;;
        --limit)      LIMIT="$2";          shift 2 ;;
        --clear-first) CLEAR_FIRST=1;      shift   ;;
        *) echo "Tham số không hợp lệ: $1"; exit 1 ;;
    esac
done

if [[ -z "$BLOCKS_FILE" || -z "$LOCATIONS_FILE" ]]; then
    echo "Thiếu --blocks hoặc --locations. Dùng: bash $0 --blocks <file> --locations <file>"
    exit 1
fi

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "========================================================"
log "load_geoip_iptables.sh — country=$COUNTRY, limit=$LIMIT"
log "========================================================"

# ─────────────────────────────────────────
# BƯỚC 1: Kiểm tra và cài ipset nếu cần
# ─────────────────────────────────────────
if ! command -v ipset &>/dev/null; then
    log "Cài ipset..."
    apt-get install -y -qq ipset
fi

# ─────────────────────────────────────────
# BƯỚC 2: Lọc CIDR từ CSV bằng Python
# (bash không xử lý CSV tốt, dùng python3 inline)
# ─────────────────────────────────────────
log "Lọc CIDR cho quốc gia '$COUNTRY' (tối đa $LIMIT entries)..."

CIDR_TMPFILE=$(mktemp /tmp/geoip_cidrs_XXXXXX.txt)

python3 << PYEOF
import csv, sys

locations_path = "$LOCATIONS_FILE"
blocks_path    = "$BLOCKS_FILE"
country_code   = "$COUNTRY".upper()
limit          = $LIMIT
out_path       = "$CIDR_TMPFILE"

# Bước 1: build geoname_id set
geonames = set()
with open(locations_path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row.get("country_iso_code","").upper() == country_code:
            gid = row.get("geoname_id","").strip()
            if gid:
                geonames.add(gid)

if not geonames:
    print(f"[ERROR] Không tìm thấy geoname_id nào cho '{country_code}'.", file=sys.stderr)
    sys.exit(1)

# Bước 2: lọc CIDR
cidrs = []
with open(blocks_path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if len(cidrs) >= limit:
            break
        gid = row.get("geoname_id","").strip() or row.get("registered_country_geoname_id","").strip()
        if gid in geonames:
            cidr = row.get("network","").strip()
            # Bỏ qua CIDR trong dải 10.x.x.x (dải lab)
            if cidr and not cidr.startswith("10."):
                cidrs.append(cidr)

with open(out_path, "w") as f:
    for cidr in cidrs:
        f.write(cidr + "\n")

print(f"[OK] Đã lọc {len(cidrs)} CIDR → {out_path}")
PYEOF

CIDR_COUNT=$(wc -l < "$CIDR_TMPFILE")
log "Tổng số CIDR sẽ nạp: $CIDR_COUNT"

# ─────────────────────────────────────────
# BƯỚC 3: Xóa ipset và iptables rule cũ nếu --clear-first
# ─────────────────────────────────────────
if [[ $CLEAR_FIRST -eq 1 ]]; then
    log "Xóa ipset và iptables rule cũ..."
    # Xóa iptables rule tham chiếu đến set trước, sau đó mới xóa set
    iptables -D FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    ipset destroy "$IPSET_NAME" 2>/dev/null || true
    log "  Đã xóa set '$IPSET_NAME'."
fi

# ─────────────────────────────────────────
# BƯỚC 4: Tạo ipset và nạp CIDR
#
# Dùng ipset restore (batch mode) thay vì gọi 'ipset add' từng dòng.
# Batch mode nhanh hơn rất nhiều: tất cả entries được nạp vào kernel
# trong một syscall thay vì N syscall riêng lẻ.
# ─────────────────────────────────────────
log "Tạo ipset '$IPSET_NAME' và nạp $CIDR_COUNT CIDR..."
T_START=$(date +%s%3N)

# Tạo set mới (hoặc flush nếu đã tồn tại)
ipset create "$IPSET_NAME" hash:net family inet hashsize 65536 maxelem 65536 2>/dev/null || \
    ipset flush "$IPSET_NAME"

# Tạo file batch cho ipset restore
IPSET_BATCH=$(mktemp /tmp/ipset_batch_XXXXXX.txt)
echo "create $IPSET_NAME hash:net family inet hashsize 65536 maxelem 65536 -exist" > "$IPSET_BATCH"
while IFS= read -r cidr; do
    echo "add $IPSET_NAME $cidr -exist"
done < "$CIDR_TMPFILE" >> "$IPSET_BATCH"

# Nạp vào kernel qua batch
ipset restore < "$IPSET_BATCH"

T_END=$(date +%s%3N)
ELAPSED=$((T_END - T_START))

log "Đã nạp $CIDR_COUNT CIDR vào ipset trong ${ELAPSED}ms."

# ─────────────────────────────────────────
# BƯỚC 5: Thêm Iptables FORWARD rule
# Chèn vào đầu chain (-I) để được kiểm tra trước các rule khác.
# ─────────────────────────────────────────
log "Thêm Iptables FORWARD rule..."

# Xóa rule cũ nếu đã tồn tại (tránh duplicate)
iptables -D FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
iptables -I FORWARD -m set --match-set "$IPSET_NAME" src -j DROP

log "  Đã thêm: iptables -I FORWARD -m set --match-set $IPSET_NAME src -j DROP"

# ─────────────────────────────────────────
# BƯỚC 6: Verify
# ─────────────────────────────────────────
ACTUAL_COUNT=$(ipset list "$IPSET_NAME" | grep -c "^[0-9]" || true)
log "Verify: ipset '$IPSET_NAME' hiện có $ACTUAL_COUNT entries."

# ─────────────────────────────────────────
# DỌN DẸP FILE TẠM
# ─────────────────────────────────────────
rm -f "$CIDR_TMPFILE" "$IPSET_BATCH"

log "========================================================"
log "KẾT QUẢ NẠP (Iptables/ipset):"
log "  CIDR đã nạp:    $CIDR_COUNT"
log "  ipset entries:  $ACTUAL_COUNT"
log "  Thời gian nạp:  ${ELAPSED}ms"
log "========================================================"