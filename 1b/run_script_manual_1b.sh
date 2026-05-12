#!/usr/bin/env bash
# =============================================================================
# run_script_manual.sh — Kịch bản 1b (Slow Loris) - MANUAL
# Orchestrate 3 phase thủ công: baseline → no_feedback → full_stack
# Chạy trên: Firewall VM, với quyền root.
# =============================================================================
#
# THIẾT KẾ PHASE:
#
#   Phase 1 — baseline (60s):
#     Không có tấn công, không có gì đặc biệt. Đo trạng thái bình thường
#     của hệ thống để làm nền so sánh.
#
#   Phase 2 — no_feedback (120s):
#     Slow Loris bắt đầu tấn công. Suricata chạy nhưng watcher.py KHÔNG
#     chạy — không có ai đọc alert và gọi XDP API. Điều này chứng minh
#     rằng dù Suricata phát hiện được, nếu không có feedback loop thì
#     nginx vẫn bị ảnh hưởng. Đây là điều kiện "thiếu một thành phần".
#
#   Phase 3 — full_stack (120s):
#     Reset XDP rules, khởi động watcher.py, chạy lại Slow Loris.
#     Lần này Suricata phát hiện → watcher đọc EVE log → gọi XDP API
#     → XDP block IP tấn công ở tầng driver. Đo detection+response latency.
#
# BIẾN THÀNH CÔNG BẮT BUỘC:
#   - legitimate_user_ok = 1 ở phase 3 (ns_50 phải nhận được HTTP 200)
#   - xdp_rules_count tăng lên trong phase 3 (chứng minh feedback loop hoạt động)
#
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────
# BIẾN CẤU HÌNH
# ─────────────────────────────────────────
ATTACKER_IP="10.10.1.2"          # eth0 của Attacker VM (không bắt buộc dùng trong kịch bản này)
VICTIM_IP="10.10.2.2"            # nginx ở đây
FIREWALL_IFACE="enp0s8"          # Interface hướng về Attacker
ATTACKER_USER="kali"             # SSH user trên Attacker VM (không bắt buộc)
ATTACKER_NS="ns_11"              # Namespace tấn công — source IP 10.10.1.11
ATTACKER_SUDO_PASS="kali"        # Mật khẩu sudo trên Attacker VM (không bắt buộc)

# Thời gian mỗi phase (giây). Override: ./run_script_manual.sh --duration=180
DURATION_BASELINE=60
DURATION_NO_FEEDBACK=120         # Slow Loris cần thời gian để làm cạn connection pool
DURATION_FULL_STACK=120
COOLDOWN=15                      # Giây nghỉ giữa các phase để metrics ổn định

# Tham số Slow Loris
# --socket-count 150: với worker_connections=4096, cần nhiều socket để thấy tác động rõ
# --sleeptime 10: gửi thêm data mỗi 10 giây — đủ chậm để Suricata thấy pattern bất thường
# Tăng lên 500-1000 socket nếu chạy bare metal
SLOWLORIS_TARGET="$VICTIM_IP"
SLOWLORIS_SOCKETS=150            # ĐIỀU CHỈNH nếu cần — xem comment ở trên
SLOWLORIS_SLEEP=10

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
WATCHER_PID_FILE="/tmp/watcher_1b.pid"
MONITOR_PID_FILE="/tmp/monitor_1b.pid"

# ─────────────────────────────────────────
# XỬ LÝ THAM SỐ
# ─────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --duration=*)
            DURATION_BASELINE="${arg#*=}"
            DURATION_NO_FEEDBACK="${arg#*=}"
            DURATION_FULL_STACK="${arg#*=}"
            ;;
    esac
done

# ─────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────
log() { echo "[$(date '+%H:%M:%S')] $*"; }

check_prerequisites() {
    log "Kiểm tra điều kiện tiên quyết..."
    local ok=1

    # Kiểm tra XDP API
    if ! curl -sf http://127.0.0.1:8080/health > /dev/null 2>&1; then
        echo "[-] XDP Core API không chạy trên port 8080!"
        ok=0
    else
        log "[OK] XDP Core API"
    fi

    # Kiểm tra Suricata
    if ! systemctl is-active --quiet suricata; then
        echo "[-] Suricata không chạy! Hãy chạy setup_rules_1b.sh trước."
        ok=0
    else
        log "[OK] Suricata: $(systemctl is-active suricata)"
    fi

    # Kiểm tra monitor.py tồn tại
    if [[ ! -f "$SCRIPT_DIR/../monitor.py" ]]; then
        echo "[-] Không tìm thấy monitor.py tại $SCRIPT_DIR/../monitor.py"
        ok=0
    else
        log "[OK] monitor.py"
    fi

    # Kiểm tra watcher.py tồn tại
    if [[ ! -f "$SCRIPT_DIR/watcher.py" ]]; then
        echo "[-] Không tìm thấy watcher.py tại $SCRIPT_DIR/watcher.py"
        ok=0
    else
        log "[OK] watcher.py"
    fi

    # Kiểm tra victim nginx
    if ! curl -sf --max-time 5 "http://$VICTIM_IP/" > /dev/null 2>&1; then
        echo "[-] Nginx trên Victim ($VICTIM_IP) không phản hồi!"
        echo "    Đảm bảo Victim VM đang chạy và nginx active."
        ok=0
    else
        log "[OK] Nginx tại $VICTIM_IP"
    fi

    if [[ $ok -eq 0 ]]; then
        echo "Không đủ điều kiện. Dừng lại."
        exit 1
    fi
}

start_monitor() {
    local phase="$1"
    local output="$2"
    local append_flag="${3:-}"

    log "Khởi động monitor.py cho phase: $phase"
    python3 "$SCRIPT_DIR/../monitor.py" \
        --phase "$phase" \
        --output "$output" \
        $append_flag &
    echo $! > "$MONITOR_PID_FILE"
    sleep 1
}

stop_monitor() {
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        kill "$(cat "$MONITOR_PID_FILE")" 2>/dev/null || true
        rm -f "$MONITOR_PID_FILE"
        sleep 1
    fi
}

start_slowloris() {
    echo ""
    echo "┌──────────────────────────────────────────────────────────┐"
    echo "│  [MANUAL] Hãy chạy lệnh sau trên Attacker VM:            │"
    echo "│  sudo ip netns exec $ATTACKER_NS slowloris $SLOWLORIS_TARGET --port 80 \\│"
    echo "│    --socket-count $SLOWLORIS_SOCKETS --sleeptime $SLOWLORIS_SLEEP        │"
    echo "│                                                          │"
    echo "│  (Chờ lệnh bắt đầu gửi request trước khi tiếp tục)       │"
    echo "└──────────────────────────────────────────────────────────┘"
    read -r -p ">> Nhấn Enter để xác nhận đã chạy lệnh thành công trên Attacker VM: "
    log "[MANUAL] Tiếp tục theo xác nhận của người dùng."
}

stop_slowloris() {
    echo ""
    echo "┌──────────────────────────────────────────────────────────┐"
    echo "│  [MANUAL] Hãy dừng Slow Loris trên Attacker VM!          │"
    echo "│  (Nhấn Ctrl+C ở terminal bên kia hoặc chạy lệnh:)        │"
    echo "│  sudo pkill -9 -f slowloris                              │"
    echo "└──────────────────────────────────────────────────────────┘"
    read -r -p ">> Nhấn Enter để xác nhận đã dừng tấn công: "
    log "[MANUAL] Tiếp tục theo xác nhận của người dùng."
}

start_watcher() {
    log "Khởi động watcher.py (feedback loop Suricata → XDP)..."
    python3 "$SCRIPT_DIR/watcher.py" \
        --log-file "$RESULTS_DIR/feedback_loop_1b.log" &
    echo $! > "$WATCHER_PID_FILE"
    sleep 1
    log "watcher.py PID: $(cat "$WATCHER_PID_FILE")"
}

stop_watcher() {
    if [[ -f "$WATCHER_PID_FILE" ]]; then
        kill "$(cat "$WATCHER_PID_FILE")" 2>/dev/null || true
        rm -f "$WATCHER_PID_FILE"
        log "watcher.py đã dừng."
    fi
}

clear_xdp_rules() {
    log "Xóa toàn bộ XDP rules (reset trước phase mới)..."
    local rules
    rules=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null || echo "[]")
    local count
    count=$(echo "$rules" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get('rules',[])))" 2>/dev/null || echo "0")

    if [[ "$count" -gt 0 ]]; then
        log "Đang xóa $count rules..."
        echo "$rules" | python3 - << 'EOF'
import sys, json, urllib.request

rules = json.load(sys.stdin)
if isinstance(rules, dict):
    rules = rules.get("rules", [])
for r in rules:
    payload = json.dumps(r).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8080/rules",
        data=payload, method="DELETE",
        headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"  Lỗi xóa rule {r}: {e}")
print(f"  Đã xóa {len(rules)} rules.")
EOF
    else
        log "Không có rule nào cần xóa."
    fi
}

print_summary() {
    local csv="$1"
    echo ""
    echo "============================================================"
    echo " TÓM TẮT KẾT QUẢ — Kịch bản 1b (Slow Loris) - MANUAL"
    echo "============================================================"
    python3 << EOF
import csv, sys
from collections import defaultdict

filepath = "$csv"
phases = defaultdict(lambda: {
    "cpu": [], "latency": [], "legit_ok": [], "conn_est": [], "xdp_rules": []
})

try:
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            p = row.get("phase", "unknown")
            try:
                phases[p]["cpu"].append(float(row.get("cpu_percent", 0)))
                phases[p]["latency"].append(float(row.get("nginx_latency_ms", 0)))
                phases[p]["legit_ok"].append(int(row.get("legitimate_user_ok", 0)))
                phases[p]["conn_est"].append(float(row.get("nginx_conn_established", 0)))
                phases[p]["xdp_rules"].append(int(row.get("xdp_rules_count", 0)))
            except (ValueError, KeyError):
                pass

    for phase, data in phases.items():
        if not data["cpu"]:
            continue
        avg = lambda x: sum(x)/len(x) if x else 0
        legit_rate = sum(data["legit_ok"]) / len(data["legit_ok"]) * 100 if data["legit_ok"] else 0
        print(f"\n  Phase: {phase}")
        print(f"    CPU avg:              {avg(data['cpu']):.1f}%")
        print(f"    Nginx latency avg:    {avg(data['latency']):.1f} ms")
        print(f"    Conn established avg: {avg(data['conn_est']):.0f}")
        print(f"    XDP rules (max):      {max(data['xdp_rules'], default=0)}")
        print(f"    Legitimate user OK:   {legit_rate:.0f}% of samples")
        status = "✓ PASS" if legit_rate >= 80 else "✗ FAIL (legitimate user bị ảnh hưởng)"
        print(f"    Status:               {status}")

except FileNotFoundError:
    print(f"  Không tìm thấy file CSV: {filepath}")
EOF
    echo "============================================================"
    echo " CSV đầy đủ: $csv"
    echo " Evidence log: $RESULTS_DIR/feedback_loop_1b.log"
    echo "============================================================"
}

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
echo "============================================================"
echo " run_script_manual.sh — Kịch bản Slow Loris (Thủ công)"
echo " $(date)"
echo "============================================================"

# Tạo thư mục kết quả
mkdir -p "$RESULTS_DIR"
CSV_OUTPUT="$RESULTS_DIR/exp_1b_manual_$(date +%Y%m%d_%H%M%S).csv"

# Kiểm tra điều kiện
check_prerequisites

# Dọn process thừa từ các lần chạy trước — tránh nhiễm kết quả
log "[CLEAN] Kiểm tra process thừa..."
for proc in watcher.py feedback_loop_iptables.py; do
    if pgrep -f "$proc" > /dev/null 2>&1; then
        pkill -f "$proc" 2>/dev/null || true
        log "[CLEAN][WARN] Đã kill process thừa: $proc"
    else
        log "[CLEAN][OK] Không có process thừa: $proc"
    fi
done

# Xóa XDP rules thừa
XDP_COUNT=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo "?")
if [[ "$XDP_COUNT" != "0" && "$XDP_COUNT" != "?" ]]; then
    log "[CLEAN][WARN] Còn $XDP_COUNT XDP rule — đang xóa..."
    curl -sf http://127.0.0.1:8080/rules 2>/dev/null | python3 -c "
import sys,json,urllib.request
rules=json.load(sys.stdin)
for r in (rules if isinstance(rules,list) else []):
    req=urllib.request.Request('http://127.0.0.1:8080/rules',json.dumps(r).encode(),{'Content-Type':'application/json'},'DELETE')
    try: urllib.request.urlopen(req,timeout=3)
    except: pass
print(f'Xóa {len(rules)} rules.')
" 2>/dev/null
else
    log "[CLEAN][OK] XDP sạch (0 rules)."
fi

echo ""
echo "Cấu hình thực nghiệm:"
echo "  Thời gian mỗi phase: baseline=${DURATION_BASELINE}s, no_feedback=${DURATION_NO_FEEDBACK}s, full_stack=${DURATION_FULL_STACK}s"
echo "  Slow Loris: ${SLOWLORIS_SOCKETS} sockets, sleep=${SLOWLORIS_SLEEP}s"
echo "  Output CSV: $CSV_OUTPUT"
echo ""
read -r -p "Nhấn Enter để bắt đầu (Ctrl+C để hủy)..."

# =============================================================================
# PHASE 1: BASELINE
# =============================================================================
echo ""
log "━━━━ PHASE 1: BASELINE (${DURATION_BASELINE}s) ━━━━"
log "Đo trạng thái bình thường — không có tấn công."
start_monitor "baseline" "$CSV_OUTPUT"
sleep "$DURATION_BASELINE"
stop_monitor
log "Phase baseline hoàn tất."

log "Nghỉ cooldown ${COOLDOWN}s..."
sleep "$COOLDOWN"

# =============================================================================
# PHASE 2: NO FEEDBACK (Slow Loris, không có watcher)
# =============================================================================
echo ""
log "━━━━ PHASE 2: NO_FEEDBACK (${DURATION_NO_FEEDBACK}s) ━━━━"
log "Slow Loris tấn công. Suricata chạy NHƯNG watcher.py KHÔNG chạy."
log "Mục đích: chứng minh nếu không có feedback loop, nginx vẫn bị ảnh hưởng."

start_monitor "no_feedback" "$CSV_OUTPUT" "--append"
sleep 3   # Để monitor lấy vài mẫu baseline trước
start_slowloris

log "Đang đo trong ${DURATION_NO_FEEDBACK}s..."
sleep "$DURATION_NO_FEEDBACK"

stop_slowloris
stop_monitor
log "Phase no_feedback hoàn tất."

log "Nghỉ cooldown ${COOLDOWN}s — để connection cũ đóng hết..."
sleep "$COOLDOWN"

# =============================================================================
# PHASE 3: FULL STACK (Slow Loris + Suricata + watcher + XDP)
# =============================================================================
echo ""
log "━━━━ PHASE 3: FULL_STACK (${DURATION_FULL_STACK}s) ━━━━"
log "Reset XDP rules, bật watcher.py, chạy lại Slow Loris."
log "Mục đích: feedback loop hoạt động đầy đủ — đo detection latency."

# Reset XDP rules từ phase trước (nếu có)
clear_xdp_rules

# Khởi động feedback loop
start_watcher

# Chờ watcher sẵn sàng
sleep 2

start_monitor "full_stack" "$CSV_OUTPUT" "--append"
sleep 3   # Để monitor lấy vài mẫu trước khi tấn công bắt đầu
start_slowloris

log "Đang đo trong ${DURATION_FULL_STACK}s..."
log "(Theo dõi feedback_loop_1b.log để thấy detection latency realtime)"
sleep "$DURATION_FULL_STACK"

stop_slowloris
stop_monitor
stop_watcher

# =============================================================================
# KẾT QUẢ
# =============================================================================
echo ""
log "Tất cả phase hoàn tất!"
print_summary "$CSV_OUTPUT"
