#!/usr/bin/env bash
# =============================================================================
# setup_rules_2.sh — Kịch bản 2 (GeoIP)
# Kiểm tra điều kiện môi trường, cài công cụ cần thiết, chuẩn bị SNAT
# trên Attacker VM để giả lập traffic từ IP thuộc dải GeoIP bị block.
# Chạy MỘT LẦN trước khi bắt đầu thực nghiệm.
# Chạy trên: Firewall VM (với quyền root) + hướng dẫn thủ công cho Attacker VM.
# =============================================================================
set -euo pipefail

IFACE_ATTACKER="enp0s8"       # Interface hướng về Attacker
IFACE_VICTIM="enp0s9"         # Interface hướng về Victim
ATTACKER_IP="10.10.1.2"
VICTIM_IP="10.10.2.2"
ATTACKER_USER="kali"

# IP giả mạo dùng trong benchmark — phải nằm trong dải GeoIP bị block (CN).
# Đây là một IP public thuộc dải Trung Quốc, dễ nhớ, dùng nhất quán
# trong toàn bộ benchmark để kết quả có thể tái lập.
# Confirm: 1.180.0.0/14 thuộc China Unicom, có trong GeoLite2-CN.
FAKE_ATTACKER_IP="1.180.1.1"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

echo "============================================================"
echo " setup_rules_2.sh — Kịch bản GeoIP"
echo "============================================================"

# ─────────────────────────────────────────
# BƯỚC 1: Kiểm tra các công cụ trên Firewall VM
# ─────────────────────────────────────────
log "Kiểm tra công cụ trên Firewall VM..."

# ipset — cần cho phần benchmark Iptables
if ! command -v ipset &>/dev/null; then
    log "Cài ipset..."
    apt-get install -y -qq ipset
fi
log "[OK] ipset: $(ipset --version | head -1)"

# wrk — HTTP benchmarking tool để đo p50/p95/p99 latency từ ns_50
# Cần biên dịch từ source hoặc dùng apt tùy distro
if ! command -v wrk &>/dev/null; then
    log "Cài wrk (HTTP benchmarking tool)..."
    # Thử apt trước (có trong Ubuntu 22.04+)
    if apt-get install -y -qq wrk 2>/dev/null; then
        log "[OK] wrk đã cài từ apt."
    else
        # Build từ source nếu apt không có
        log "apt không có wrk, build từ source..."
        apt-get install -y -qq build-essential libssl-dev git 2>/dev/null
        git clone --depth=1 https://github.com/wg/wrk.git /tmp/wrk_build
        make -C /tmp/wrk_build -j"$(nproc)"
        cp /tmp/wrk_build/wrk /usr/local/bin/wrk
        rm -rf /tmp/wrk_build
        log "[OK] wrk đã build từ source."
    fi
else
    log "[OK] wrk: $(wrk --version 2>&1 | head -1)"
fi

# hping3 — dùng để gửi SYN flood từ IP giả mạo trong kịch bản này
# (khác kịch bản 1a: ở đây mục đích là tạo traffic bị block, không phải stress test)
if ! command -v hping3 &>/dev/null; then
    log "Cài hping3..."
    apt-get install -y -qq hping3
fi
log "[OK] hping3"

# python3 — kiểm tra có thể chạy load_geoip_xdp.py không
python3 -c "import csv, json, urllib.request" 2>/dev/null || {
    log "[ERROR] python3 thiếu module cần thiết."
    exit 1
}
log "[OK] python3"

# ─────────────────────────────────────────
# BƯỚC 2: Kiểm tra XDP Core API
# ─────────────────────────────────────────
log "Kiểm tra XDP Core API..."
if curl -sf http://127.0.0.1:8080/health > /dev/null; then
    log "[OK] XDP Core API đang chạy."
    curl -sf http://127.0.0.1:8080/health | python3 -m json.tool 2>/dev/null || true
else
    log "[WARN] XDP Core API không phản hồi. Đảm bảo khởi động trước khi chạy thực nghiệm."
fi

# ─────────────────────────────────────────
# BƯỚC 3: Kiểm tra ip_forward
# ─────────────────────────────────────────
log "Kiểm tra ip_forward..."
if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
    log "[OK] ip_forward = 1"
else
    log "Bật ip_forward..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
fi

# ─────────────────────────────────────────
# BƯỚC 4: Kiểm tra Victim nginx
# ─────────────────────────────────────────
log "Kiểm tra nginx trên Victim VM ($VICTIM_IP)..."
if curl -sf --max-time 5 "http://$VICTIM_IP/" > /dev/null; then
    log "[OK] Nginx tại $VICTIM_IP phản hồi."
else
    log "[WARN] Nginx không phản hồi. Kiểm tra Victim VM."
fi

# ─────────────────────────────────────────
# BƯỚC 5: Kiểm tra GeoLite2 CSV file
# ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log "Kiểm tra file GeoLite2 CSV..."

BLOCKS_FILE=""
LOCATIONS_FILE=""

# Tìm file trong thư mục hiện tại và thư mục script
for dir in "$SCRIPT_DIR" "$(pwd)"; do
    if ls "$dir"/GeoLite2-Country-Blocks-IPv4.csv 2>/dev/null; then
        BLOCKS_FILE="$dir/GeoLite2-Country-Blocks-IPv4.csv"
    fi
    if ls "$dir"/GeoLite2-Country-Locations-en.csv 2>/dev/null; then
        LOCATIONS_FILE="$dir/GeoLite2-Country-Locations-en.csv"
    fi
done

if [[ -n "$BLOCKS_FILE" && -n "$LOCATIONS_FILE" ]]; then
    log "[OK] Tìm thấy GeoLite2 CSV:"
    log "     Blocks:    $BLOCKS_FILE ($(wc -l < "$BLOCKS_FILE") dòng)"
    log "     Locations: $LOCATIONS_FILE"
else
    log "[WARN] Chưa tìm thấy file GeoLite2 CSV!"
    echo ""
    echo "  Cần đặt hai file sau vào cùng thư mục với script này:"
    echo "    - GeoLite2-Country-Blocks-IPv4.csv"
    echo "    - GeoLite2-Country-Locations-en.csv"
    echo ""
    echo "  Cách lấy file:"
    echo "    1. Đăng ký miễn phí tại https://www.maxmind.com/en/geolite2/signup"
    echo "    2. Tải GeoLite2 Country (CSV format)"
    echo "    3. Giải nén và đặt 2 file trên vào thư mục này"
fi

# ─────────────────────────────────────────
# BƯỚC 6: Hướng dẫn setup SNAT trên Attacker VM
# ─────────────────────────────────────────
echo ""
echo "============================================================"
echo " HƯỚNG DẪN SETUP SNAT TRÊN ATTACKER VM"
echo "============================================================"
echo ""
echo " Attacker VM cần dùng SNAT để giả mạo source IP thành IP thuộc"
echo " dải GeoIP bị block. Đây là cách benchmark kiểm tra firewall"
echo " có thực sự block traffic từ IP trong GeoIP dataset không."
echo ""
echo " Trên Attacker VM (10.10.1.2), chạy lệnh sau MỘT LẦN:"
echo ""
echo "   sudo iptables -t nat -A POSTROUTING -o eth0 \\"
echo "       -j SNAT --to-source $FAKE_ATTACKER_IP"
echo ""
echo " Giải thích: Khi hping3 gửi packet từ Attacker VM, iptables SNAT"
echo " sẽ thay source IP thật (10.10.1.2) bằng $FAKE_ATTACKER_IP —"
echo " một IP thuộc dải GeoIP Trung Quốc. Firewall VM nhận packet với"
echo " source IP $FAKE_ATTACKER_IP và áp dụng GeoIP block."
echo ""
echo " Để HỦY SNAT sau khi benchmark xong:"
echo "   sudo iptables -t nat -D POSTROUTING -o eth0 \\"
echo "       -j SNAT --to-source $FAKE_ATTACKER_IP"
echo ""
echo " LƯU Ý QUAN TRỌNG:"
echo "   - ns_50 (10.10.1.50) KHÔNG bị SNAT vì nó dùng namespace riêng"
echo "     với interface riêng, không đi qua eth0 của Attacker VM."
echo "   - SNAT không ảnh hưởng đến SSH từ Attacker về Firewall vì SSH"
echo "     dùng IP đích 10.10.1.1 (local network), không qua eth0."
echo "============================================================"
echo ""
read -r -p "Nhấn Enter sau khi đã setup SNAT trên Attacker VM (hoặc bỏ qua nếu dùng manual mode)..."

# ─────────────────────────────────────────
# TỔNG KẾT
# ─────────────────────────────────────────
echo ""
echo "============================================================"
echo " SETUP HOÀN TẤT"
echo "============================================================"
echo " Bước tiếp theo:"
echo "   sudo bash run_experiment_2.sh \\"
echo "       --blocks  GeoLite2-Country-Blocks-IPv4.csv \\"
echo "       --locations GeoLite2-Country-Locations-en.csv"
echo "============================================================"