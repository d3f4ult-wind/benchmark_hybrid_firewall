#!/bin/bash
# run_experiment_1a.sh — Chạy toàn bộ Kịch bản 1a tự động
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
#   sudo bash run_experiment_1a.sh
#   sudo bash run_experiment_1a.sh --output results/run1.csv --duration 120
#
# Yêu cầu:
#   - Chạy trên Firewall VM với quyền root
#   - Attacker VM phải ssh-accessible hoặc tấn công được trigger thủ công
#   - setup_rules_1a.sh đã được chạy trước
#   - monitor.py nằm ở ../../monitor.py (relative với file này)
#   - hping3 cài trên Attacker VM

set -e

# ---------------------------------------------------------------------------
# CẤU HÌNH
# ---------------------------------------------------------------------------

ATTACKER_IP="10.10.1.2"          # IP chính của Attacker VM — chỉ dùng để SSH
ATTACKER_SSH_USER="kali"          # Username SSH trên Attacker VM
ATTACKER_SUDO_PASS="kali"         # Mật khẩu sudo trên Attacker VM (dùng cho lab)
ATTACKER_NS="ns_10"               # Network namespace dùng để tấn công
ATTACKER_NS_IP="10.10.1.10"       # IP của ns_10 — source IP thực tế của attack
                                   # Dùng ns_10 thay vì eth0 (10.10.1.2) để:
                                   #   1. XDP block 10.10.1.10 không ảnh hưởng SSH
                                   #   2. Phân tách rõ ràng attacker vs SSH control plane
VICTIM_IP="10.10.2.2"
VICTIM_PORT="80"

# Thời gian mỗi phase (giây)
# Máy yếu (VirtualBox): 60 giây là đủ để thấy rõ hiệu ứng
# Nếu máy mạnh hơn (bare metal): tăng lên 120-180 giây để có nhiều data points hơn
PHASE_DURATION=60

# Thời gian chờ giữa các phase để hệ thống ổn định (giây)
COOLDOWN=10

# Output CSV — monitor.py sẽ ghi vào đây
OUTPUT_CSV="results/exp1a_$(date +%Y%m%d_%H%M%S).csv"

# Đường dẫn tới monitor.py 
MONITOR_SCRIPT="./monitor.py"

# Đường dẫn tới feedback_loop script
FEEDBACK_SCRIPT="./feedback_loop_iptables.py"

# XDP API
XDP_API_BASE="http://127.0.0.1:8080"

# ---------------------------------------------------------------------------
# PARSE ARGUMENTS
# ---------------------------------------------------------------------------

for i in "$@"; do
    case $i in
        --output=*)
            OUTPUT_CSV="${i#*=}"
            ;;
        --duration=*)
            PHASE_DURATION="${i#*=}"
            ;;
        --attacker-user=*)
            ATTACKER_SSH_USER="${i#*=}"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Lỗi: Script này cần chạy với quyền root (sudo)"
        exit 1
    fi
}

# Gửi lệnh tấn công sang Attacker VM qua SSH, chạy trong namespace ns_10
# Source IP sẽ là 10.10.1.10 (không phải 10.10.1.2) — đảm bảo XDP block
# không ảnh hưởng đến SSH control plane qua eth0
start_attack() {
    log "[ATTACK] Kiểm tra SSH đến Attacker VM ($ATTACKER_SSH_USER@$ATTACKER_IP)..."

    # Kiểm tra SSH trước, log kết quả rõ ràng
    if ! ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
             -o ConnectTimeout=5 \
             "$ATTACKER_SSH_USER@$ATTACKER_IP" "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
        log "[ATTACK][ERROR] Không thể SSH đến $ATTACKER_IP. Kiểm tra kết nối!"
        MANUAL_ATTACK=true
        return 1
    fi
    log "[ATTACK][OK] SSH đến $ATTACKER_IP thành công."

    # Kiểm tra namespace ns_10 tồn tại
    if ! ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
             "$ATTACKER_SSH_USER@$ATTACKER_IP" \
             "ip netns list | grep -q $ATTACKER_NS" 2>/dev/null; then
        log "[ATTACK][ERROR] Namespace '$ATTACKER_NS' không tồn tại trên Attacker VM!"
        log "[ATTACK]        Tạo bằng: sudo ip netns add $ATTACKER_NS && ..."
        MANUAL_ATTACK=true
        return 1
    fi
    log "[ATTACK][OK] Namespace $ATTACKER_NS (source IP: $ATTACKER_NS_IP) đã sẵn sàng."

    # Khởi động hping3 trong namespace ns_10
    # hping3 cần raw socket (CAP_NET_RAW) — bắt buộc dùng sudo
    # Dùng echo | sudo -S để tránh prompt password trong batch mode
    log "[ATTACK] Bắt đầu SYN Flood: $ATTACKER_NS_IP → $VICTIM_IP:$VICTIM_PORT"
    HPING_PID=$(ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$ATTACKER_SSH_USER@$ATTACKER_IP" \
        "echo '$ATTACKER_SUDO_PASS' | sudo -S ip netns exec $ATTACKER_NS hping3 -S -p $VICTIM_PORT --flood $VICTIM_IP \
         > /tmp/hping3.log 2>&1 & echo \$!" 2>/dev/null)

    # Xác nhận hping3 đã thực sự khởi động
    sleep 1
    if [[ -z "$HPING_PID" || ! "$HPING_PID" =~ ^[0-9]+$ ]]; then
        log "[ATTACK][ERROR] Không lấy được PID của hping3 — có thể lệnh không chạy!"
        MANUAL_ATTACK=true
        return 1
    fi

    # Xác nhận process thực sự đang chạy trên Attacker VM
    if ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
           "$ATTACKER_SSH_USER@$ATTACKER_IP" \
           "ps -p $HPING_PID > /dev/null 2>&1" 2>/dev/null; then
        log "[ATTACK][OK] hping3 đang chạy trong $ATTACKER_NS (PID: $HPING_PID, src: $ATTACKER_NS_IP)"
        echo "$HPING_PID" > /tmp/attack_pid.txt
    else
        log "[ATTACK][WARN] PID $HPING_PID không tồn tại — hping3 có thể đã crash. Xem /tmp/hping3.log."
    fi
}

# Dừng tấn công
stop_attack() {
    log "[ATTACK] Đang dừng SYN Flood..."
    # Kill bằng SIGKILL (-9) để chắc chắn, sau đó chờ 2s mới kiểm tra
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$ATTACKER_SSH_USER@$ATTACKER_IP" \
        "echo '$ATTACKER_SUDO_PASS' | sudo -S pkill -9 -f hping3 2>/dev/null; true" 2>/dev/null || true
    sleep 2
    if ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
           "$ATTACKER_SSH_USER@$ATTACKER_IP" \
           "pgrep -x hping3 > /dev/null 2>&1 && echo RUNNING || echo STOPPED" 2>/dev/null | grep -q STOPPED; then
        log "[ATTACK][OK] hping3 đã dừng trên Attacker VM."
    else
        log "[ATTACK][WARN] hping3 có thể vẫn đang chạy — kiểm tra thủ công nếu cần."
    fi
    rm -f /tmp/attack_pid.txt
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

# Trap để đảm bảo cleanup khi script bị interrupt
cleanup() {
    log "Script bị interrupt, đang cleanup..."
    stop_attack 2>/dev/null || true
    [ -n "$MONITOR_PID" ] && kill $MONITOR_PID 2>/dev/null || true
    [ -n "$FEEDBACK_PID" ] && kill $FEEDBACK_PID 2>/dev/null || true
    log "Cleanup hoàn tất."
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ---------------------------------------------------------------------------

check_root
mkdir -p "$(dirname "$OUTPUT_CSV")" 2>/dev/null || mkdir -p results

log "=========================================================="
log "Kịch bản 1a — Feedback Loop: Iptables → XDP"
log "=========================================================="
log "Output CSV  : $OUTPUT_CSV"
log "Phase duration: ${PHASE_DURATION}s | Cooldown: ${COOLDOWN}s"
log "Attacker    : $ATTACKER_IP (user: $ATTACKER_SSH_USER)"
log "Victim      : $VICTIM_IP:$VICTIM_PORT"
log ""
log "=========================================================="
log "MẸO: Để xem thông số CPU/Latency realtime từ monitor.py,"
log "hãy mở thêm 1 terminal SSH vào Firewall VM và chạy lệnh:"
log "    tail -f /tmp/monitor_exp.log"
log "=========================================================="
log ""

# Kiểm tra XDP Core
log "[CHECK] Kiểm tra XDP Core API..."
if curl -sf --max-time 2 "$XDP_API_BASE/health" > /dev/null; then
    log "[CHECK] XDP Core: OK"
else
    log "[ERROR] XDP Core không phản hồi tại $XDP_API_BASE"
    log "[ERROR] Hãy chắc chắn XDP Core đang chạy trước khi tiếp tục."
    exit 1
fi

# Kiểm tra nginx trên Victim
log "[CHECK] Kiểm tra nginx trên Victim..."
if curl -sf --max-time 3 "http://$VICTIM_IP" > /dev/null; then
    log "[CHECK] nginx: OK"
else
    log "[WARNING] nginx không phản hồi — kiểm tra lại Victim VM."
fi

# Kiểm tra SSH đến Attacker
log "[CHECK] Kiểm tra SSH đến Attacker VM..."
if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
       "$ATTACKER_SSH_USER@$ATTACKER_IP" "echo ok" &>/dev/null; then
    log "[CHECK] SSH to Attacker: OK"
else
    log "[WARNING] Không thể SSH đến Attacker. Bạn sẽ cần trigger tấn công thủ công."
    log "[WARNING] Lệnh chạy trên Attacker: hping3 -S -p $VICTIM_PORT --flood $VICTIM_IP"
    MANUAL_ATTACK=true
fi

# ---------------------------------------------------------------------------
# Dọn process thừa từ các lần chạy trước (QUAN TRỌNG!)
# ---------------------------------------------------------------------------
# Nếu watcher.py hoặc feedback_loop_iptables.py còn sống sót từ kịch bản khác,
# chúng sẽ can thiệp vào kết quả (block IP trong phase mà không được phép).
log "[CLEAN] Kiểm tra và dọn process thừa..."
for proc in watcher.py feedback_loop_iptables.py; do
    if pgrep -f "$proc" > /dev/null 2>&1; then
        pkill -f "$proc" 2>/dev/null || true
        sleep 1
        log "[CLEAN][WARN] Đã kill process thừa: $proc — đây có thể gây nhiễm kết quả nếu chưa dọn!"
    else
        log "[CLEAN][OK] Không có process thừa: $proc"
    fi
done

# Đặt XDP về transparent mode (không có rules) cho Phase 1 và 2
reset_xdp_rules
XDP_COUNT=$(curl -sf "$XDP_API_BASE/rules" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
log "[CLEAN] XDP rules hiện tại: $XDP_COUNT (phải là 0 trước khi bắt đầu)"
if [[ "$XDP_COUNT" != "0" ]]; then
    log "[CLEAN][ERROR] Còn $XDP_COUNT XDP rule sau khi reset! Dừng lại để tảnh nằn."
    exit 1
fi
log ""

# ---------------------------------------------------------------------------
# PHASE 1 — BASELINE
# ---------------------------------------------------------------------------

log "========== PHASE 1: Baseline (${PHASE_DURATION}s) =========="
log "Không có tấn công. Chỉ legitimate traffic từ ns_50."
log "Đang bắt đầu monitor.py cho Phase 1..."

# Chạy monitor.py ở background, ghi vào CSV mới
python3 "$MONITOR_SCRIPT" --phase baseline --output "$OUTPUT_CSV" > /tmp/monitor_exp.log 2>&1 &
MONITOR_PID=$!
log "monitor.py PID: $MONITOR_PID"

sleep "$PHASE_DURATION"

# Dừng monitor
kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true
MONITOR_PID=""
log "Phase 1 hoàn tất."

log "Cooldown ${COOLDOWN}s..."
sleep "$COOLDOWN"

# ---------------------------------------------------------------------------
# PHASE 2 — IPTABLES ONLY (không có feedback loop)
# ---------------------------------------------------------------------------

log ""
log "========== PHASE 2: Iptables-only (${PHASE_DURATION}s) =========="
log "SYN Flood bật, Iptables chặn, XDP transparent (không nhận rule từ feedback loop)."

# Bắt đầu tấn công
if [ "${MANUAL_ATTACK:-false}" = "true" ]; then
    log "⚠️  MANUAL MODE: Hãy chạy lệnh sau trên Attacker VM RỒI nhấn Enter:"
    log "   hping3 -S -p $VICTIM_PORT --flood $VICTIM_IP"
    read -r -p "Nhấn Enter khi tấn công đã bắt đầu..."
else
    start_attack
fi

# Monitor Phase 2 — append vào cùng CSV
sleep 2  # Đợi traffic ổn định
python3 "$MONITOR_SCRIPT" --phase iptables_only --output "$OUTPUT_CSV" --append > /tmp/monitor_exp.log 2>&1 &
MONITOR_PID=$!

sleep "$PHASE_DURATION"

# Dừng monitor và tấn công
kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true
MONITOR_PID=""
stop_attack
log "Phase 2 hoàn tất."

log "Cooldown ${COOLDOWN}s (đợi hệ thống ổn định)..."
sleep "$COOLDOWN"

# Xác nhận XDP vẫn trong transparent mode (không có rules từ phase trước)
XDP_RULES=$(curl -sf "$XDP_API_BASE/rules" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
log "XDP rules count trước Phase 3: $XDP_RULES (phải là 0)"

# ---------------------------------------------------------------------------
# PHASE 3 — FEEDBACK LOOP ACTIVE
# ---------------------------------------------------------------------------

log ""
log "========== PHASE 3: Feedback Loop (${PHASE_DURATION}s) =========="
log "SYN Flood bật, Iptables LOG → feedback_loop.py → XDP block tại driver."

# Bắt đầu feedback loop script ở background
log "Đang khởi động feedback_loop_iptables.py..."
python3 "$FEEDBACK_SCRIPT" --use-journald &
FEEDBACK_PID=$!
log "feedback_loop PID: $FEEDBACK_PID"
sleep 1  # Đợi script khởi động và kết nối XDP API

# Bắt đầu tấn công lại
if [ "${MANUAL_ATTACK:-false}" = "true" ]; then
    log "⚠️  MANUAL MODE: Hãy chạy lại hping3 trên Attacker VM RỒI nhấn Enter:"
    log "   hping3 -S -p $VICTIM_PORT --flood $VICTIM_IP"
    read -r -p "Nhấn Enter khi tấn công đã bắt đầu..."
else
    start_attack
fi

# Monitor Phase 3 — append vào CSV
sleep 2
python3 "$MONITOR_SCRIPT" --phase feedback_loop --output "$OUTPUT_CSV" --append > /tmp/monitor_exp.log 2>&1 &
MONITOR_PID=$!

sleep "$PHASE_DURATION"

# Dừng tất cả
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
log "Thực nghiệm 1a hoàn tất!"
log "Dữ liệu CSV: $OUTPUT_CSV"
log ""

# In tóm tắt nhanh
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
