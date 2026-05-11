#!/usr/bin/env bash
# =============================================================================
# teardown_rules_2.sh — Kịch bản 2 (GeoIP)
# Dọn dẹp toàn bộ sau khi thực nghiệm kết thúc.
# Chạy trên: Firewall VM, với quyền root.
# =============================================================================
set -euo pipefail

ATTACKER_IP="10.10.1.2"
ATTACKER_USER="user"
FAKE_ATTACKER_IP="1.180.1.1"
MONITOR_PID_FILE="/tmp/monitor_2.pid"
ATTACKER_PID_FILE="/tmp/attacker_2.pid"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

echo "============================================================"
echo " teardown_rules_2.sh — Kịch bản GeoIP"
echo "============================================================"

# ─────────────────────────────────────────
# BƯỚC 1: Dừng các process còn chạy
# ─────────────────────────────────────────
log "Dừng các process thực nghiệm còn sót..."
for pidfile in "$MONITOR_PID_FILE" "$ATTACKER_PID_FILE"; do
    [[ -f "$pidfile" ]] && {
        kill "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
    }
done
pkill -f "monitor.py"  2>/dev/null || true
pkill -f "hping3"      2>/dev/null || true

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
        print(f"  Lỗi xóa {r}: {e}")
print(f"  Đã xóa {deleted} XDP rules.")
EOF
    else
        log "  Không có XDP rule nào."
    fi
else
    log "  [WARN] XDP API không phản hồi."
fi

# ─────────────────────────────────────────
# BƯỚC 3: Xóa ipset và iptables rule
# ─────────────────────────────────────────
log "Xóa ipset và iptables rule..."
iptables -D FORWARD -m set --match-set geoip_block src -j DROP 2>/dev/null && \
    log "  Đã xóa iptables FORWARD rule." || true
ipset destroy geoip_block 2>/dev/null && \
    log "  Đã xóa ipset 'geoip_block'." || \
    log "  ipset 'geoip_block' không tồn tại (OK)."

# ─────────────────────────────────────────
# BƯỚC 4: Nhắc hủy SNAT trên Attacker VM
# ─────────────────────────────────────────
echo ""
log "Nhắc nhở: Hủy SNAT trên Attacker VM..."
echo ""
echo "  Chạy lệnh sau trên Attacker VM để hủy IP giả mạo:"
echo ""
echo "    sudo iptables -t nat -D POSTROUTING -o eth0 \\"
echo "        -j SNAT --to-source $FAKE_ATTACKER_IP"
echo ""

# Thử tự hủy qua SSH nếu có thể
if ssh -o ConnectTimeout=5 -o BatchMode=yes \
        "${ATTACKER_USER}@${ATTACKER_IP}" \
        "sudo iptables -t nat -D POSTROUTING -o eth0 -j SNAT --to-source $FAKE_ATTACKER_IP 2>/dev/null || true" \
        2>/dev/null; then
    log "[AUTO] Đã hủy SNAT trên Attacker VM."
else
    log "[MANUAL] Không thể SSH — vui lòng hủy SNAT thủ công theo hướng dẫn trên."
fi

# ─────────────────────────────────────────
# TỔNG KẾT
# ─────────────────────────────────────────
echo ""
echo "============================================================"
echo " TEARDOWN HOÀN TẤT"
XDP_LEFT=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get('rules',[])))" \
    2>/dev/null || echo "N/A")
echo " XDP rules còn lại: $XDP_LEFT"
echo " ipset geoip_block: $(ipset list geoip_block 2>/dev/null | grep 'Number of entries' || echo 'đã xóa')"
echo ""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo " Dữ liệu thực nghiệm GIỮ NGUYÊN tại:"
ls -lh "$SCRIPT_DIR/results/" 2>/dev/null || echo "  (thư mục results/ trống)"
echo "============================================================"