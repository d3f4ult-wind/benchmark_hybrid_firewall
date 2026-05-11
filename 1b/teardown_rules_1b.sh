#!/usr/bin/env bash
# =============================================================================
# teardown_rules_1b.sh — Kịch bản 1b (Slow Loris)
# Dọn dẹp toàn bộ sau khi thực nghiệm kết thúc.
# Chạy trên: Firewall VM, với quyền root.
# =============================================================================
# Những gì script này làm:
#   1. Dừng watcher.py nếu còn chạy
#   2. Xóa toàn bộ XDP rules được tạo ra trong thực nghiệm
#   3. Dừng Suricata (tùy chọn — xem flag --keep-suricata)
#   4. Restore suricata.yaml về bản gốc (nếu --keep-suricata không được dùng)
#   5. KHÔNG xóa kết quả CSV và log — đây là dữ liệu thực nghiệm quý giá
# =============================================================================
set -euo pipefail

KEEP_SURICATA=0
if [[ "${1:-}" == "--keep-suricata" ]]; then
    KEEP_SURICATA=1
fi

SURICATA_CONF="/etc/suricata/suricata.yaml"
WATCHER_PID_FILE="/tmp/watcher_1b.pid"
MONITOR_PID_FILE="/tmp/monitor_1b.pid"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

echo "============================================================"
echo " teardown_rules_1b.sh — Kịch bản Slow Loris"
echo "============================================================"

# ─────────────────────────────────────────
# BƯỚC 1: Dừng các process còn đang chạy
# ─────────────────────────────────────────
log "Dừng các process thực nghiệm..."

for pidfile in "$WATCHER_PID_FILE" "$MONITOR_PID_FILE"; do
    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" && log "  Đã dừng PID $pid ($(basename "$pidfile"))"
        fi
        rm -f "$pidfile"
    fi
done

# Phòng trường hợp watcher/monitor bị tách khỏi PID file
pkill -f "watcher.py" 2>/dev/null && log "  Đã kill watcher.py còn sót" || true
pkill -f "monitor.py" 2>/dev/null && log "  Đã kill monitor.py còn sót" || true

# ─────────────────────────────────────────
# BƯỚC 2: Xóa XDP rules
# ─────────────────────────────────────────
log "Xóa XDP rules..."
if curl -sf http://127.0.0.1:8080/health > /dev/null 2>&1; then
    RULES=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null || echo "[]")
    COUNT=$(echo "$RULES" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get('rules',[])))" \
        2>/dev/null || echo "0")

    if [[ "$COUNT" -gt 0 ]]; then
        echo "$RULES" | python3 << 'EOF'
import sys, json, urllib.request
rules = json.load(sys.stdin)
if isinstance(rules, dict):
    rules = rules.get("rules", [])
deleted = 0
for r in rules:
    payload = json.dumps(r).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8080/rules",
        data=payload, method="DELETE",
        headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        deleted += 1
    except Exception as e:
        print(f"  Lỗi khi xóa rule {r}: {e}")
print(f"  Đã xóa {deleted} rules khỏi BPF Map.")
EOF
    else
        log "  Không có rule nào trong BPF Map."
    fi
else
    log "  [WARN] XDP API không phản hồi — bỏ qua bước xóa rules."
fi

# ─────────────────────────────────────────
# BƯỚC 3: Xử lý Suricata
# ─────────────────────────────────────────
if [[ $KEEP_SURICATA -eq 1 ]]; then
    log "Flag --keep-suricata được dùng — giữ nguyên Suricata."
else
    log "Dừng Suricata và restore config gốc..."
    systemctl stop suricata 2>/dev/null || true
    systemctl disable suricata 2>/dev/null || true

    # Restore config gốc nếu có backup
    if [[ -f "${SURICATA_CONF}.orig" ]]; then
        cp "${SURICATA_CONF}.orig" "$SURICATA_CONF"
        log "  Đã restore $SURICATA_CONF về bản gốc."
    fi
    log "  Suricata đã dừng."
fi

# ─────────────────────────────────────────
# BƯỚC 4: Xác nhận trạng thái cuối
# ─────────────────────────────────────────
echo ""
echo "============================================================"
echo " TEARDOWN HOÀN TẤT"
echo "============================================================"
echo " XDP rules còn lại: $(curl -sf http://127.0.0.1:8080/rules 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); rules=d if isinstance(d,list) else d.get('rules',[]); print(len(rules))" 2>/dev/null || echo 'N/A (API không phản hồi)')"
echo " Suricata:          $(systemctl is-active suricata 2>/dev/null || echo 'stopped')"
echo ""
echo " Dữ liệu thực nghiệm được GIỮ NGUYÊN tại:"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ls -lh "$SCRIPT_DIR/results/" 2>/dev/null || echo "  (thư mục results/ không tồn tại)"
echo "============================================================"