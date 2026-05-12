#!/bin/bash
# run_script_manual_1a.sh — Chạy toàn bộ Kịch bản 1a thủ công
# ==========================================================
# Script này orchestrate 3 phase của kịch bản 1a:
#
#   Phase 1 — Baseline    : Không có tấn công, chỉ legitimate traffic
#   Phase 2 — Iptables-only: SYN Flood, Iptables chặn, XDP transparent
#   Phase 3 — Feedback Loop: SYN Flood, Iptables LOG → feedback_loop.py → XDP block
#
# Mỗi phase chạy PHASE_DURATION giây, monitor.py ghi CSV liên tục.
# Sau mỗi phase, script dừng tấn công và đợi hệ thống ổn định trước khi
# chuyển sang phase tiếp theo.
#
# Cách dùng:
#   sudo bash run_script_manual_1a.sh
#   sudo bash run_script_manual_1a.sh --output results/run1.csv --duration 120
#
# Yêu cầu:
#   - Chạy trên Firewall VM với quyền root
#   - Tấn công được trigger thủ công trên Attacker VM
#   - setup_rules_1a.sh đã được chạy trước
#   - monitor.py nằm ở ../monitor.py (relative với file này)

set -e

# ---------------------------------------------------------------------------
# CẤU HÌNH
# ---------------------------------------------------------------------------

ATTACKER_NS="ns_10"               # Network namespace dùng để tấn công
ATTACKER_NS_IP="10.10.1.10"       # IP của ns_10
VICTIM_IP="10.10.2.2"
VICTIM_PORT="80"

# Thời gian mỗi phase (giây)
PHASE_DURATION=60
COOLDOWN=10

# Output CSV
OUTPUT_CSV="results/exp1a_manual_$(date +%Y%m%d_%H%M%S).csv"
MONITOR_SCRIPT="./monitor.py"
FEEDBACK_SCRIPT="./feedback_loop_iptables.py"
XDP_API_BASE="http://127.0.0.1:8080"

for i in "$@"; do
    case $i in
        --output=*)
            OUTPUT_CSV="${i#*=}"
            ;;
        --duration=*)
            PHASE_DURATION="${i#*=}"
            ;;
    esac
done

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Lỗi: Script này cần chạy với quyền root (sudo)"
        exit 1
    fi
}

start_attack() {
    echo ""
    echo "┌──────────────────────────────────────────────────────────┐"
    echo "│  [MANUAL] Hãy chạy lệnh sau trên Attacker VM:            │"
    echo "│  sudo ip netns exec $ATTACKER_NS hping3 -S -p $VICTIM_PORT --flood $VICTIM_IP │"
    echo "│                                                          │"
    echo "│  (Chờ lệnh bắt đầu gửi request trước khi tiếp tục)       │"
    echo "└──────────────────────────────────────────────────────────┘"
    read -r -p ">> Nhấn Enter để xác nhận đã chạy lệnh thành công trên Attacker VM: "
    log "[MANUAL] Tiếp tục theo xác nhận của người dùng."
}

stop_attack() {
    echo ""
    echo "┌──────────────────────────────────────────────────────────┐"
    echo "│  [MANUAL] Hãy dừng hping3 trên Attacker VM!              │"
    echo "│  (Nhấn Ctrl+C ở terminal bên kia hoặc chạy lệnh:)        │"
    echo "│  sudo pkill -9 -f hping3                                 │"
    echo "└──────────────────────────────────────────────────────────┘"
    read -r -p ">> Nhấn Enter để xác nhận đã dừng tấn công: "
    log "[MANUAL] Tiếp tục theo xác nhận của người dùng."
}

# Reset XDP rules (xóa tất cả rules khỏi BPF Map)
reset_xdp_rules() {
    log "[XDP] Đang xóa tất cả XDP rules..."
    python3 -c "
import json, urllib.request
try:
    req = urllib.request.Request('$XDP_API_BASE/rules', method='GET')
    with urllib.request.urlopen(req, timeout=2) as r:
        rules = json.loads(r.read())
    for rule in rules:
        data = json.dumps(rule).encode()
        req2 = urllib.request.Request('$XDP_API_BASE/rules', data=data,
               headers={'Content-Type':'application/json'}, method='DELETE')
        urllib.request.urlopen(req2, timeout=2)
    print(f'  Đã xóa {len(rules)} XDP rule(s)')
except Exception as e:
    print(f'  XDP reset error: {e}')
"
}

cleanup() {
    log "Script bị interrupt, đang cleanup..."
    [ -n "${MONITOR_PID:-}" ] && kill $MONITOR_PID 2>/dev/null || true
    [ -n "${FEEDBACK_PID:-}" ] && kill $FEEDBACK_PID 2>/dev/null || true
    log "Cleanup hoàn tất. Nhớ dừng tấn công thủ công trên Attacker VM!"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ---------------------------------------------------------------------------
check_root
mkdir -p "$(dirname "$OUTPUT_CSV")" 2>/dev/null || mkdir -p results

log "=========================================================="
log "Kịch bản 1a (MANUAL) — Feedback Loop: Iptables → XDP"
log "=========================================================="
log "Output CSV  : $OUTPUT_CSV"
log "Phase duration: ${PHASE_DURATION}s | Cooldown: ${COOLDOWN}s"
log "Victim      : $VICTIM_IP:$VICTIM_PORT"
log ""

log "[CHECK] Kiểm tra XDP Core API..."
if curl -sf --max-time 2 "$XDP_API_BASE/health" > /dev/null; then
    log "[CHECK] XDP Core: OK"
else
    log "[ERROR] XDP Core không phản hồi tại $XDP_API_BASE"
    exit 1
fi

log "[CHECK] Kiểm tra nginx trên Victim..."
if curl -sf --max-time 3 "http://$VICTIM_IP" > /dev/null; then
    log "[CHECK] nginx: OK"
else
    log "[WARNING] nginx không phản hồi — kiểm tra lại Victim VM."
fi

log "[CLEAN] Kiểm tra và dọn process thừa..."
for proc in watcher.py feedback_loop_iptables.py monitor.py; do
    if pgrep -f "$proc" > /dev/null 2>&1; then
        pkill -f "$proc" 2>/dev/null || true
        sleep 1
        log "[CLEAN][WARN] Đã kill process thừa: $proc"
    else
        log "[CLEAN][OK] Không có process thừa: $proc"
    fi
done

reset_xdp_rules
XDP_COUNT=$(curl -sf "$XDP_API_BASE/rules" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
log "[CLEAN] XDP rules hiện tại: $XDP_COUNT"
if [[ "$XDP_COUNT" != "0" ]]; then
    log "[CLEAN][ERROR] Còn $XDP_COUNT XDP rule sau khi reset! Dừng lại."
    exit 1
fi
log ""

# ---------------------------------------------------------------------------
# PHASE 1 — BASELINE
# ---------------------------------------------------------------------------
log "========== PHASE 1: Baseline (${PHASE_DURATION}s) =========="
log "Không có tấn công. Chỉ legitimate traffic từ ns_50."
log "Đang bắt đầu monitor.py cho Phase 1..."

python3 "$MONITOR_SCRIPT" --phase baseline --output "$OUTPUT_CSV" &
MONITOR_PID=$!
log "monitor.py PID: $MONITOR_PID"

sleep "$PHASE_DURATION"

kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true
MONITOR_PID=""
log "Phase 1 hoàn tất."

log "Cooldown ${COOLDOWN}s..."
sleep "$COOLDOWN"

# ---------------------------------------------------------------------------
# PHASE 2 — IPTABLES ONLY
# ---------------------------------------------------------------------------
log ""
log "========== PHASE 2: Iptables-only (${PHASE_DURATION}s) =========="
log "SYN Flood bật, Iptables chặn, XDP transparent (không nhận rule từ feedback loop)."

start_attack

sleep 2
python3 "$MONITOR_SCRIPT" --phase iptables_only --output "$OUTPUT_CSV" --append &
MONITOR_PID=$!

sleep "$PHASE_DURATION"

kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true
MONITOR_PID=""
stop_attack
log "Phase 2 hoàn tất."

log "Cooldown ${COOLDOWN}s..."
sleep "$COOLDOWN"

# ---------------------------------------------------------------------------
# PHASE 3 — FEEDBACK LOOP ACTIVE
# ---------------------------------------------------------------------------
log ""
log "========== PHASE 3: Feedback Loop (${PHASE_DURATION}s) =========="
log "SYN Flood bật, Iptables LOG → feedback_loop.py → XDP block tại driver."

log "Đang khởi động feedback_loop_iptables.py..."
python3 "$FEEDBACK_SCRIPT" --use-journald &
FEEDBACK_PID=$!
log "feedback_loop PID: $FEEDBACK_PID"
sleep 1

start_attack

sleep 2
python3 "$MONITOR_SCRIPT" --phase feedback_loop --output "$OUTPUT_CSV" --append &
MONITOR_PID=$!

sleep "$PHASE_DURATION"

kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true
MONITOR_PID=""
stop_attack
kill $FEEDBACK_PID 2>/dev/null || true
wait $FEEDBACK_PID 2>/dev/null || true
FEEDBACK_PID=""
log "Phase 3 hoàn tất."

# ---------------------------------------------------------------------------
# KẾT QUẢ
# ---------------------------------------------------------------------------
log ""
log "=========================================================="
log "Thực nghiệm 1a (MANUAL) hoàn tất!"
log "Dữ liệu CSV: $OUTPUT_CSV"
log ""

python3 -c "
import csv
from collections import defaultdict

totals = defaultdict(lambda: {'samples': 0, 'cpu_sum': 0, 'latency_sum': 0,
                               'ok_count': 0, 'xdp_rules_max': 0})
with open('$OUTPUT_CSV') as f:
    for row in csv.DictReader(f):
        p = row['phase']
        totals[p]['samples'] += 1
        try:
            totals[p]['cpu_sum'] += float(row['cpu_percent'])
            totals[p]['latency_sum'] += float(row['nginx_latency_ms'])
            totals[p]['ok_count'] += int(row['legitimate_user_ok'])
            totals[p]['xdp_rules_max'] = max(totals[p]['xdp_rules_max'],
                                              int(row.get('xdp_rules_count', 0)))
        except (ValueError, KeyError):
            pass

print('Phase             | Samples | Avg CPU | Avg Latency | User OK% | XDP Rules')
print('-' * 75)
for phase, d in totals.items():
    n = d['samples'] or 1
    print(f\"{phase:<18}| {n:7d} | {d['cpu_sum']/n:6.1f}% | {d['latency_sum']/n:8.1f}ms | {d['ok_count']/n*100:6.1f}%  | {d['xdp_rules_max']:5d}\")
" 2>/dev/null || log "Không thể tạo summary — kiểm tra file CSV"

log ""
log "Để dọn dẹp sau thực nghiệm:"
log "  sudo bash teardown_rules_1a.sh"
