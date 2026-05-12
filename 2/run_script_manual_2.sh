#!/usr/bin/env bash
# =============================================================================
# run_script_manual_2.sh — Kịch bản 2 (GeoIP) - MANUAL
# So sánh hiệu năng XDP BPF LPM Trie vs Iptables/ipset khi ruleset GeoIP
# tăng dần từ 100 → 500 → 1000 → 5000 → 10000 CIDR entries.
#
# Chạy trên: Firewall VM, với quyền root.
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────
# THAM SỐ MẶC ĐỊNH
# ─────────────────────────────────────────
BLOCKS_FILE=""
LOCATIONS_FILE=""
COUNTRY="CN"
VICTIM_IP="10.10.2.2"
NS50_IP="10.10.1.50"        # Legitimate user probe — không bao giờ bị block
FAKE_ATTACKER_IP="1.180.1.1" # IP giả mạo trong dải GeoIP bị block (China Unicom)
IFACE="enp0s8"                  # Interface hướng về Attacker

RULESET_LEVELS=(100 500 1000 5000 10000)
MEASURE_DURATION=60

WRK_THREADS=4
WRK_CONNECTIONS=10
WRK_DURATION=30s
WRK_DURATION_SECS=30
WRK_TARGET="http://$VICTIM_IP/"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
MONITOR_PID_FILE="/tmp/monitor_2.pid"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --blocks)    BLOCKS_FILE="$2";    shift 2 ;;
        --locations) LOCATIONS_FILE="$2"; shift 2 ;;
        --country)   COUNTRY="$2";        shift 2 ;;
        --levels)    IFS=',' read -ra RULESET_LEVELS <<< "$2"; shift 2 ;;
        --duration)  MEASURE_DURATION="$2"; shift 2 ;;
        *) echo "Tham số không hợp lệ: $1"; exit 1 ;;
    esac
done

if [[ -z "$BLOCKS_FILE" || -z "$LOCATIONS_FILE" ]]; then
    echo "Cần chỉ định --blocks và --locations. Ví dụ:"
    echo "  sudo bash run_script_manual_2.sh \\"
    echo "      --blocks  GeoLite2-Country-Blocks-IPv4.csv \\"
    echo "      --locations GeoLite2-Country-Locations-en.csv"
    exit 1
fi

log() { echo "[$(date '+%H:%M:%S')] $*"; }

start_monitor() {
    local phase="$1" output="$2" append="${3:-}"
    python3 "$SCRIPT_DIR/../monitor.py" \
        --phase "$phase" --output "$output" $append &
    echo $! > "$MONITOR_PID_FILE"
    sleep 1
}

stop_monitor() {
    [[ -f "$MONITOR_PID_FILE" ]] && {
        kill "$(cat "$MONITOR_PID_FILE")" 2>/dev/null || true
        rm -f "$MONITOR_PID_FILE"
        sleep 1
    }
}

check_false_positive() {
    local round_name="$1"
    echo "" >&2
    echo "┌──────────────────────────────────────────────────────────┐" >&2
    echo "│  [MANUAL] Kiểm tra False Positive từ Attacker VM:        │" >&2
    echo "│  Chạy lệnh sau trên Attacker VM:                         │" >&2
    echo "│  sudo ip netns exec ns_50 curl -sf --max-time 5 http://$VICTIM_IP/ │" >&2
    echo "│                                                          │" >&2
    echo "│  Lệnh trên có trả về nội dung web thành công không?      │" >&2
    echo "└──────────────────────────────────────────────────────────┘" >&2
    local ans
    read -r -p ">> Nhập y (có, ns_50 OK) hoặc n (không, ns_50 BỊ BLOCK): " ans < /dev/tty
    if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
        log "[FP-CHECK] $round_name: ns_50 OK (không bị block nhầm). false_positive=0" >&2
        echo "0"
    else
        log "[FP-CHECK] $round_name: ns_50 BỊ BLOCK NHẦM! false_positive=1" >&2
        echo "1"
    fi
}

run_wrk_from_ns50() {
    local label="$1"
    echo "" >&2
    echo "┌──────────────────────────────────────────────────────────┐" >&2
    echo "│  [MANUAL] Đo latency bằng wrk trên Attacker VM:          │" >&2
    echo "│  Chạy lệnh sau trên Attacker VM:                         │" >&2
    echo "│  sudo ip netns exec ns_50 wrk -t $WRK_THREADS -c $WRK_CONNECTIONS -d $WRK_DURATION --latency http://$VICTIM_IP/ │" >&2
    echo "│                                                          │" >&2
    echo "│  Sau khi chạy xong (30s), hãy nhập các kết quả sau:      │" >&2
    echo "└──────────────────────────────────────────────────────────┘" >&2
    
    local p50 p95 p99 reqsec
    read -r -p ">> Nhập p50 (ví dụ 1.23ms): " p50 < /dev/tty
    read -r -p ">> Nhập p95 (chỉ có p75/p90/p99 ở output wrk chuẩn? Nếu ko có thì nhập N/A): " p95 < /dev/tty
    read -r -p ">> Nhập p99 (ví dụ 5.67ms): " p99 < /dev/tty
    read -r -p ">> Nhập Requests/sec (ví dụ 1234.56): " reqsec < /dev/tty

    log "  wrk kết quả ($label): p50=$p50  p99=$p99  req/s=$reqsec" >&2
    echo "$p50 $p95 $p99 $reqsec"
}

start_attacker() {
    echo ""
    echo "┌──────────────────────────────────────────────────────────┐"
    echo "│  [MANUAL] Bắt đầu SYN flood từ Attacker VM               │"
    echo "│  Chạy lệnh sau trên Attacker VM:                         │"
    echo "│  sudo hping3 -S -p 80 --flood $VICTIM_IP                 │"
    echo "│  (SNAT đã setup sẽ tự đổi source → $FAKE_ATTACKER_IP)    │"
    echo "└──────────────────────────────────────────────────────────┘"
    read -r -p ">> Nhấn Enter sau khi lệnh đã chạy: "
}

stop_attacker() {
    echo ""
    echo "┌──────────────────────────────────────────────────────────┐"
    echo "│  [MANUAL] Dừng hping3 trên Attacker VM!                  │"
    echo "│  (Nhấn Ctrl+C ở terminal bên kia hoặc chạy lệnh:)        │"
    echo "│  sudo pkill -9 -f hping3                                 │"
    echo "└──────────────────────────────────────────────────────────┘"
    read -r -p ">> Nhấn Enter để xác nhận đã dừng tấn công: "
}

clear_xdp_rules() {
    local rules
    rules=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null || echo "[]")
    local count
    count=$(echo "$rules" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get('rules',[])))" \
        2>/dev/null || echo "0")
    if [[ "$count" -gt 0 ]]; then
        log "  Xóa $count XDP rules..."
        echo "$rules" | python3 << 'EOF'
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
    try: urllib.request.urlopen(req, timeout=5)
    except: pass
EOF
    fi
}

clear_iptables_ipset() {
    iptables -D FORWARD -m set --match-set geoip_block src -j DROP 2>/dev/null || true
    ipset destroy geoip_block 2>/dev/null || true
}

SUMMARY_CSV=""
write_summary_row() {
    local impl="$1" level="$2" p50="$3" p95="$4" p99="$5" reqsec="$6" fp="$7" cpu="$8"
    echo "$impl,$level,$p50,$p95,$p99,$reqsec,$fp,$cpu" >> "$SUMMARY_CSV"
}

# ─────────────────────────────────────────
# PREREQUISITES CHECK
# ─────────────────────────────────────────
log "Kiểm tra điều kiện tiên quyết..."
[[ ! -f "$BLOCKS_FILE" ]]    && { log "[ERROR] Không tìm thấy $BLOCKS_FILE";    exit 1; }
[[ ! -f "$LOCATIONS_FILE" ]] && { log "[ERROR] Không tìm thấy $LOCATIONS_FILE"; exit 1; }
curl -sf http://127.0.0.1:8080/health > /dev/null || { log "[ERROR] XDP API không phản hồi"; exit 1; }
command -v ipset > /dev/null || { log "[ERROR] ipset chưa cài. Chạy setup_rules_2.sh trước."; exit 1; }
log "[OK] Tất cả điều kiện đã đủ."

log "[CLEAN] Kiểm tra process thừa..."
for proc in watcher.py feedback_loop_iptables.py monitor.py; do
    if pgrep -f "$proc" > /dev/null 2>&1; then
        pkill -f "$proc" 2>/dev/null || true; sleep 1
        log "[CLEAN][WARN] Đã kill process thừa: $proc"
    else
        log "[CLEAN][OK] Không có process thừa: $proc"
    fi
done

XDP_C=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo 0)
if [[ "$XDP_C" != "0" ]]; then
    log "[CLEAN][WARN] Còn $XDP_C XDP rule — đang xóa..."
    curl -sf http://127.0.0.1:8080/rules | python3 -c "import sys,json,urllib.request
[urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8080/rules',json.dumps(r).encode(),{'Content-Type':'application/json'},'DELETE'),timeout=3) for r in (json.load(sys.stdin) or [])]
" 2>/dev/null || true
    log "[CLEAN] Xóa xong."
fi

# ─────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DETAIL_CSV="$RESULTS_DIR/exp_2_manual_detail_${TIMESTAMP}.csv"
SUMMARY_CSV="$RESULTS_DIR/exp_2_manual_summary_${TIMESTAMP}.csv"

echo "implementation,ruleset_size,latency_p50,latency_p95,latency_p99,req_per_sec,false_positive,cpu_avg" \
    > "$SUMMARY_CSV"

echo ""
echo "============================================================"
echo " run_script_manual_2.sh — Kịch bản GeoIP (Manual)"
echo " Ruleset levels: ${RULESET_LEVELS[*]}"
echo " Thời gian đo mỗi round: ${MEASURE_DURATION}s"
echo " Output: $SUMMARY_CSV"
echo "============================================================"
read -r -p "Nhấn Enter để bắt đầu (Ctrl+C để hủy)..."

for LEVEL in "${RULESET_LEVELS[@]}"; do

    echo ""
    log "════════════════════════════════════════════════"
    log "BẮT ĐẦU MỨC RULESET: $LEVEL CIDR"
    log "════════════════════════════════════════════════"

    log "── Round A: XDP (${LEVEL} CIDR) ──"
    log "  Nạp $LEVEL CIDR vào XDP BPF Map..."
    python3 "$SCRIPT_DIR/load_geoip_xdp.py" \
        --blocks    "$BLOCKS_FILE" \
        --locations "$LOCATIONS_FILE" \
        --country   "$COUNTRY" \
        --limit     "$LEVEL" \
        --clear-first

    ACTUAL_XDP_RULES=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); rules=d if isinstance(d,list) else d.get('rules',[]); print(len(rules))" \
        2>/dev/null || echo "0")
    log "  BPF Map hiện có: $ACTUAL_XDP_RULES rules"

    FP_XDP=$(check_false_positive "xdp_${LEVEL}")

    start_monitor "xdp_${LEVEL}" "$DETAIL_CSV" "--append"
    start_attacker

    log "  Flood đang chạy, đồng thời đo wrk latency từ ns_50..."
    WRK_RESULT=$(run_wrk_from_ns50 "xdp_${LEVEL}")
    read -r P50_XDP P95_XDP P99_XDP REQSEC_XDP <<< "$WRK_RESULT"

    REMAINING=$((MEASURE_DURATION - WRK_DURATION_SECS))
    if [[ $REMAINING -gt 0 ]]; then
        log "  Chờ thêm ${REMAINING}s cho monitor.py thu thập đủ dữ liệu..."
        sleep "$REMAINING"
    fi

    stop_attacker
    stop_monitor

    CPU_XDP=$(python3 << PYEOF
import csv
rows = []
try:
    with open("$DETAIL_CSV") as f:
        for row in csv.DictReader(f):
            if row.get("phase") == "xdp_${LEVEL}":
                try: rows.append(float(row["cpu_percent"]))
                except: pass
except: pass
print(f"{sum(rows)/len(rows):.1f}" if rows else "N/A")
PYEOF
)
    log "  CPU avg (xdp_${LEVEL}): $CPU_XDP%"
    write_summary_row "xdp" "$LEVEL" "$P50_XDP" "$P95_XDP" "$P99_XDP" "$REQSEC_XDP" "$FP_XDP" "$CPU_XDP"

    clear_xdp_rules
    log "  Xóa XDP rules xong. Nghỉ 10s..."
    sleep 10

    log "── Round B: Iptables/ipset (${LEVEL} CIDR) ──"
    log "  Nạp $LEVEL CIDR vào ipset..."
    bash "$SCRIPT_DIR/load_geoip_iptables.sh" \
        --blocks    "$BLOCKS_FILE" \
        --locations "$LOCATIONS_FILE" \
        --country   "$COUNTRY" \
        --limit     "$LEVEL" \
        --clear-first

    FP_IPT=$(check_false_positive "iptables_${LEVEL}")

    start_monitor "iptables_${LEVEL}" "$DETAIL_CSV" "--append"
    start_attacker

    log "  Flood đang chạy, đồng thời đo wrk latency từ ns_50..."
    WRK_RESULT=$(run_wrk_from_ns50 "iptables_${LEVEL}")
    read -r P50_IPT P95_IPT P99_IPT REQSEC_IPT <<< "$WRK_RESULT"

    REMAINING=$((MEASURE_DURATION - WRK_DURATION_SECS))
    if [[ $REMAINING -gt 0 ]]; then
        log "  Chờ thêm ${REMAINING}s cho monitor.py thu thập đủ dữ liệu..."
        sleep "$REMAINING"
    fi

    stop_attacker
    stop_monitor

    CPU_IPT=$(python3 << PYEOF
import csv
rows = []
try:
    with open("$DETAIL_CSV") as f:
        for row in csv.DictReader(f):
            if row.get("phase") == "iptables_${LEVEL}":
                try: rows.append(float(row["cpu_percent"]))
                except: pass
except: pass
print(f"{sum(rows)/len(rows):.1f}" if rows else "N/A")
PYEOF
)
    log "  CPU avg (iptables_${LEVEL}): $CPU_IPT%"
    write_summary_row "iptables" "$LEVEL" "$P50_IPT" "$P95_IPT" "$P99_IPT" "$REQSEC_IPT" "$FP_IPT" "$CPU_IPT"

    clear_iptables_ipset
    log "  Xóa ipset xong. Nghỉ 10s trước mức tiếp theo..."
    sleep 10

done

echo ""
echo "============================================================"
echo " TÓM TẮT KẾT QUẢ — Kịch bản 2 (GeoIP) MANUAL"
echo "============================================================"
python3 << PYEOF
import csv

filepath = "$SUMMARY_CSV"
print(f"{'Impl':<12} {'Size':>6} {'p50':>8} {'p99':>8} {'req/s':>8} {'FP':>4} {'CPU':>6}")
print("-" * 58)
try:
    with open(filepath) as f:
        for row in csv.DictReader(f):
            fp_flag = "✗ FAIL" if row.get("false_positive","0") == "1" else "OK"
            print(f"{row.get('implementation',''):<12} "
                  f"{row.get('ruleset_size',''):>6} "
                  f"{row.get('latency_p50',''):>8} "
                  f"{row.get('latency_p99',''):>8} "
                  f"{row.get('req_per_sec',''):>8} "
                  f"{fp_flag:>6} "
                  f"{row.get('cpu_avg',''):>6}%")
except FileNotFoundError:
    print(f"  Không tìm thấy {filepath}")
PYEOF
echo ""
echo " Summary CSV: $SUMMARY_CSV"
echo " Detail CSV:  $DETAIL_CSV"
echo "============================================================"
