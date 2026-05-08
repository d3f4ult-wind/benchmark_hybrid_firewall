#!/bin/bash
# teardown_rules_1a.sh — Dọn dẹp sau Kịch bản 1a
# =================================================
# Xóa tất cả Iptables rules và XDP rules đã được tạo trong thực nghiệm.
# Chạy script này sau khi hoàn thành đo lường để trả hệ thống về trạng thái sạch.
#
# Yêu cầu: chạy với quyền root (sudo)
#
# Cách dùng:
#   sudo bash teardown_rules_1a.sh
#   sudo bash teardown_rules_1a.sh --keep-xdp   # Giữ XDP rules, chỉ xóa Iptables

set -e

XDP_API_BASE="http://127.0.0.1:8080"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Lỗi: Script này cần chạy với quyền root (sudo)"
        exit 1
    fi
}

check_root
log "=== Teardown Kịch bản 1a ==="

# ---------------------------------------------------------------------------
# Xóa tất cả Iptables rules
# ---------------------------------------------------------------------------

log "Đang xóa Iptables rules..."
iptables -F          # Flush tất cả built-in chains
iptables -X          # Xóa tất cả custom chains (bao gồm SYN_FLOOD_DETECT)
iptables -Z          # Reset counters
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
log "Iptables đã được reset về trạng thái sạch."

# ---------------------------------------------------------------------------
# Xóa tất cả XDP rules qua API
# ---------------------------------------------------------------------------

KEEP_XDP=false
for arg in "$@"; do
    if [ "$arg" == "--keep-xdp" ]; then
        KEEP_XDP=true
    fi
done

if [ "$KEEP_XDP" = false ]; then
    log "Đang xóa XDP rules qua API..."
    
    # Lấy danh sách rules hiện tại rồi xóa từng cái một
    RULES=$(curl -s --max-time 3 "$XDP_API_BASE/rules" 2>/dev/null || echo "[]")
    
    if [ "$RULES" = "[]" ] || [ -z "$RULES" ]; then
        log "Không có XDP rule nào cần xóa."
    else
        log "Danh sách XDP rules hiện tại: $RULES"
        log "Đang xóa từng rule..."
        # Parse và xóa từng rule bằng Python một dòng
        python3 -c "
import json, urllib.request, sys
rules = json.loads('$RULES')
for rule in rules:
    try:
        data = json.dumps(rule).encode()
        req = urllib.request.Request('$XDP_API_BASE/rules', data=data,
              headers={'Content-Type':'application/json'}, method='DELETE')
        urllib.request.urlopen(req, timeout=2)
        print(f'  Đã xóa rule: {rule}')
    except Exception as e:
        print(f'  Lỗi khi xóa {rule}: {e}', file=sys.stderr)
" 2>&1 || log "CẢNH BÁO: Không thể xóa XDP rules (XDP Core có thể không chạy)"
    fi
else
    log "Bỏ qua xóa XDP rules (--keep-xdp)"
fi

# ---------------------------------------------------------------------------
# Xác nhận trạng thái sau teardown
# ---------------------------------------------------------------------------

log ""
log "=== Trạng thái sau teardown ==="
log "Iptables rules:"
iptables -nvL --line-numbers 2>&1 | head -30
log ""
log "=== Teardown hoàn tất ==="
