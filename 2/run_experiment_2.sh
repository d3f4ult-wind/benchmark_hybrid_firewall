#!/usr/bin/env bash
# =============================================================================
# run_experiment_2.sh — Kịch bản 2 (GeoIP)
# So sánh hiệu năng XDP BPF LPM Trie vs Iptables/ipset khi ruleset GeoIP
# tăng dần từ 100 → 500 → 1000 → 5000 → 10000 CIDR entries.
#
# Chạy trên: Firewall VM, với quyền root.
# =============================================================================
#
# THIẾT KẾ THỰC NGHIỆM:
#
# Với mỗi mức ruleset (100/500/1000/5000/10000 CIDR), script chạy:
#
#   Round A — XDP:
#     1. Nạp N CIDR vào BPF Map qua load_geoip_xdp.py
#     2. Attacker gửi SYN flood với source IP giả mạo (trong dải GeoIP bị block)
#     3. wrk đo latency p50/p95/p99 của nginx từ ns_50 (legitimate user)
#     4. monitor.py thu thập CPU, memory, packet drop trong 60 giây
#     5. Xóa toàn bộ XDP rules
#
#   Round B — Iptables/ipset (cùng mức N):
#     1. Nạp N CIDR vào ipset qua load_geoip_iptables.sh
#     2. Attacker gửi SYN flood (tương tự Round A)
#     3. wrk đo latency p50/p95/p99 (cùng tham số với Round A)
#     4. monitor.py thu thập metrics
#     5. Xóa ipset và iptables rule
#
# Sau khi tất cả 10 round hoàn tất, script tạo CSV tổng hợp để vẽ biểu đồ.
#
# ĐIỀU KIỆN THÀNH CÔNG:
#   - false_positive_count = 0 trong mọi round (ns_50 không bao giờ bị block)
#   - XDP latency tăng ít hoặc không tăng khi ruleset tăng lên
#   - Iptables latency tăng rõ hơn XDP khi ruleset lớn
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────
# THAM SỐ MẶC ĐỊNH
# ─────────────────────────────────────────
BLOCKS_FILE=""
LOCATIONS_FILE=""
COUNTRY="CN"
ATTACKER_IP="10.10.1.2"
ATTACKER_USER="user"
VICTIM_IP="10.10.2.2"
NS50_IP="10.10.1.50"        # Legitimate user probe — không bao giờ bị block
FAKE_ATTACKER_IP="1.180.1.1" # IP giả mạo trong dải GeoIP bị block (China Unicom)
IFACE="enp0s3"

# Năm mức ruleset benchmark — có thể override bằng --levels
RULESET_LEVELS=(100 500 1000 5000 10000)

# Thời gian đo cho mỗi round (giây)
MEASURE_DURATION=60

# Tham số wrk: 4 threads, 10 connections đồng thời, đo trong 30 giây từ ns_50
# Chạy trong network namespace ns_50 để source IP là 10.10.1.50
WRK_THREADS=4
WRK_CONNECTIONS=10
WRK_DURATION=30s
WRK_TARGET="http://$VICTIM_IP/"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
MONITOR_PID_FILE="/tmp/monitor_2.pid"
ATTACKER_PID_FILE="/tmp/attacker_2.pid"

# ─────────────────────────────────────────
# XỬ LÝ THAM SỐ
# ─────────────────────────────────────────
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
    echo "  sudo bash run_experiment_2.sh \\"
    echo "      --blocks  GeoLite2-Country-Blocks-IPv4.csv \\"
    echo "      --locations GeoLite2-Country-Locations-en.csv"
    exit 1
fi

# ─────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────
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

# Kiểm tra ns_50 có đang bị block không — điều kiện thành công bắt buộc
check_false_positive() {
    local round_name="$1"
    # Chạy curl từ network namespace ns_50 để source IP là 10.10.1.50
    if ip netns exec ns_50 curl -sf --max-time 5 "http://$VICTIM_IP/" > /dev/null 2>&1; then
        log "[FP-CHECK] $round_name: ns_50 OK (không bị block nhầm). false_positive=0"
        echo "0"
    else
        log "[FP-CHECK] $round_name: ns_50 BỊ BLOCK NHẦM! false_positive=1 — KIỂM TRA NGAY!"
        echo "1"
    fi
}

# Đo latency p50/p95/p99 bằng wrk từ network namespace ns_50
run_wrk_from_ns50() {
    local label="$1"
    log "  Đo latency bằng wrk (từ ns_50, $WRK_DURATION)..."

    # wrk output ví dụ:
    #   Latency   12.34ms  5.67ms  45.00ms   89.00%
    #   Req/Sec   123.00   45.00  234.00    88.00%
    #   Latency Distribution
    #      50%   11.00ms
    #      75%   14.00ms
    #      90%   18.00ms
    #      99%   45.00ms
    WRK_OUTPUT=$(ip netns exec ns_50 wrk \
        -t "$WRK_THREADS" \
        -c "$WRK_CONNECTIONS" \
        -d "$WRK_DURATION" \
        --latency \
        "$WRK_TARGET" 2>&1 || true)

    # Parse percentile từ output wrk
    P50=$(echo "$WRK_OUTPUT" | grep -E "^\s+50%" | awk '{print $2}' || echo "N/A")
    P95=$(echo "$WRK_OUTPUT" | grep -E "^\s+75%|^\s+95%" | tail -1 | awk '{print $2}' || echo "N/A")
    P99=$(echo "$WRK_OUTPUT" | grep -E "^\s+99%" | awk '{print $2}' || echo "N/A")
    REQSEC=$(echo "$WRK_OUTPUT" | grep "Requests/sec" | awk '{print $2}' || echo "N/A")

    log "  wrk kết quả ($label): p50=$P50  p99=$P99  req/s=$REQSEC"
    echo "$P50 $P95 $P99 $REQSEC"
}

# Bắt đầu SYN flood từ Attacker VM với IP giả mạo (SNAT đã setup)
start_attacker() {
    log "  Bắt đầu SYN flood từ Attacker VM (source IP giả mạo: $FAKE_ATTACKER_IP)..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes \
            "${ATTACKER_USER}@${ATTACKER_IP}" \
            "nohup hping3 -S -p 80 --flood $VICTIM_IP > /tmp/hping3_geo.log 2>&1 & echo \$!" \
            > "$ATTACKER_PID_FILE" 2>/dev/null; then
        log "  [AUTO] Attacker đang flood (PID: $(cat "$ATTACKER_PID_FILE" 2>/dev/null || echo '?'))"
    else
        echo ""
        echo "  ┌──────────────────────────────────────────────────────┐"
        echo "  │ [MANUAL] Trên Attacker VM, chạy lệnh sau:            │"
        echo "  │   sudo hping3 -S -p 80 --flood $VICTIM_IP            │"
        echo "  │ (SNAT đã setup sẽ tự đổi source → $FAKE_ATTACKER_IP) │"
        echo "  │ Nhấn Enter ở đây khi lệnh đã chạy.                   │"
        echo "  └──────────────────────────────────────────────────────┘"
        read -r -p "  >> Nhấn Enter: "
    fi
}

stop_attacker() {
    ssh -o ConnectTimeout=5 -o BatchMode=yes \
        "${ATTACKER_USER}@${ATTACKER_IP}" \
        "pkill -f hping3 || true" 2>/dev/null || {
        echo "  [MANUAL] Dừng hping3 trên Attacker VM rồi nhấn Enter."
        read -r -p "  >> Nhấn Enter: "
    }
    rm -f "$ATTACKER_PID_FILE"
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

# Ghi một dòng vào CSV tổng hợp
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
command -v wrk > /dev/null   || { log "[ERROR] wrk chưa cài. Chạy setup_rules_2.sh trước."; exit 1; }
command -v ipset > /dev/null || { log "[ERROR] ipset chưa cài. Chạy setup_rules_2.sh trước."; exit 1; }
ip netns list | grep -q "ns_50" || { log "[ERROR] Network namespace ns_50 không tồn tại!"; exit 1; }
log "[OK] Tất cả điều kiện đã đủ."

# ─────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DETAIL_CSV="$RESULTS_DIR/exp_2_detail_${TIMESTAMP}.csv"
SUMMARY_CSV="$RESULTS_DIR/exp_2_summary_${TIMESTAMP}.csv"

# Header cho CSV tổng hợp — đây là file chính để vẽ biểu đồ so sánh
echo "implementation,ruleset_size,latency_p50,latency_p95,latency_p99,req_per_sec,false_positive,cpu_avg" \
    > "$SUMMARY_CSV"

echo ""
echo "============================================================"
echo " run_experiment_2.sh — Kịch bản GeoIP"
echo " Ruleset levels: ${RULESET_LEVELS[*]}"
echo " Thời gian đo mỗi round: ${MEASURE_DURATION}s"
echo " Output: $SUMMARY_CSV"
echo "============================================================"
read -r -p "Nhấn Enter để bắt đầu (Ctrl+C để hủy)..."

# ─────────────────────────────────────────
# VÒNG LẶP CHÍNH: 5 mức × 2 implementation = 10 round
# ─────────────────────────────────────────
for LEVEL in "${RULESET_LEVELS[@]}"; do

    echo ""
    log "════════════════════════════════════════════════"
    log "BẮT ĐẦU MỨC RULESET: $LEVEL CIDR"
    log "════════════════════════════════════════════════"

    # ─────────────────────────────────────
    # ROUND A: XDP BPF LPM Trie
    # ─────────────────────────────────────
    log "── Round A: XDP (${LEVEL} CIDR) ──"

    log "  Nạp $LEVEL CIDR vào XDP BPF Map..."
    python3 "$SCRIPT_DIR/load_geoip_xdp.py" \
        --blocks    "$BLOCKS_FILE" \
        --locations "$LOCATIONS_FILE" \
        --country   "$COUNTRY" \
        --limit     "$LEVEL" \
        --clear-first

    # Verify số rule thực tế trong BPF Map
    ACTUAL_XDP_RULES=$(curl -sf http://127.0.0.1:8080/rules 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); rules=d if isinstance(d,list) else d.get('rules',[]); print(len(rules))" \
        2>/dev/null || echo "0")
    log "  BPF Map hiện có: $ACTUAL_XDP_RULES rules (mỗi CIDR = 2 rules: TCP+ICMP)"

    # Kiểm tra false positive TRƯỚC khi bắt đầu flood
    FP_XDP=$(check_false_positive "xdp_${LEVEL}")

    # Bắt đầu flood + monitor song song
    start_monitor "xdp_${LEVEL}" "$DETAIL_CSV" "--append"
    start_attacker

    # Đo wrk trong khi flood đang diễn ra — đây là điều kiện thực tế nhất
    log "  Flood đang chạy, đồng thời đo wrk latency từ ns_50..."
    WRK_RESULT=$(run_wrk_from_ns50 "xdp_${LEVEL}")
    read -r P50_XDP P95_XDP P99_XDP REQSEC_XDP <<< "$WRK_RESULT"

    # Đợi đủ thời gian đo cho monitor.py
    REMAINING=$((MEASURE_DURATION - WRK_DURATION_SECS))
    WRK_DURATION_SECS=$(echo "$WRK_DURATION" | sed 's/s//')
    REMAINING=$((MEASURE_DURATION - WRK_DURATION_SECS))
    if [[ $REMAINING -gt 0 ]]; then
        log "  Chờ thêm ${REMAINING}s cho monitor.py..."
        sleep "$REMAINING"
    fi

    stop_attacker
    stop_monitor

    # Đọc CPU average từ CSV detail
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

    # Xóa XDP rules trước Round B
    clear_xdp_rules
    log "  Xóa XDP rules xong. Nghỉ 10s..."
    sleep 10

    # ─────────────────────────────────────
    # ROUND B: Iptables / ipset
    # ─────────────────────────────────────
    log "── Round B: Iptables/ipset (${LEVEL} CIDR) ──"

    log "  Nạp $LEVEL CIDR vào ipset..."
    bash "$SCRIPT_DIR/load_geoip_iptables.sh" \
        --blocks    "$BLOCKS_FILE" \
        --locations "$LOCATIONS_FILE" \
        --country   "$COUNTRY" \
        --limit     "$LEVEL" \
        --clear-first

    # Kiểm tra false positive
    FP_IPT=$(check_false_positive "iptables_${LEVEL}")

    start_monitor "iptables_${LEVEL}" "$DETAIL_CSV" "--append"
    start_attacker

    log "  Flood đang chạy, đồng thời đo wrk latency từ ns_50..."
    WRK_RESULT=$(run_wrk_from_ns50 "iptables_${LEVEL}")
    read -r P50_IPT P95_IPT P99_IPT REQSEC_IPT <<< "$WRK_RESULT"

    REMAINING=$((MEASURE_DURATION - WRK_DURATION_SECS))
    if [[ $REMAINING -gt 0 ]]; then
        log "  Chờ thêm ${REMAINING}s cho monitor.py..."
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

# ─────────────────────────────────────────
# TÓM TẮT KẾT QUẢ
# ─────────────────────────────────────────
echo ""
echo "============================================================"
echo " TÓM TẮT KẾT QUẢ — Kịch bản 2 (GeoIP)"
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