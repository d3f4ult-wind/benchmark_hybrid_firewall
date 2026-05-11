#!/usr/bin/env bash
# =============================================================================
# setup_rules_1b.sh — Kịch bản 1b (Slow Loris)
# Cài đặt Suricata, cấu hình tối giản, nạp rule phát hiện Slow Loris.
# Chạy MỘT LẦN trước khi bắt đầu thực nghiệm.
# Chạy trên: Firewall VM, với quyền root.
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────
# BIẾN CẤU HÌNH — chỉnh ở đây nếu cần
# ─────────────────────────────────────────
IFACE="enp0s3"                    # Interface hướng về Attacker — XDP đã attach ở đây
RULES_DIR="/etc/suricata/rules"
RULE_FILE="$RULES_DIR/slowloris.rules"
SURICATA_CONF="/etc/suricata/suricata.yaml"
EVE_LOG="/var/log/suricata/eve.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo " setup_rules_1b.sh — Kịch bản Slow Loris"
echo "============================================================"

# ─────────────────────────────────────────
# BƯỚC 1: Cài Suricata
# ─────────────────────────────────────────
if ! command -v suricata &>/dev/null; then
    echo "[*] Cài đặt Suricata từ apt..."
    apt-get update -qq
    apt-get install -y -qq suricata
    echo "[+] Suricata đã cài xong."
else
    echo "[+] Suricata đã có sẵn: $(suricata --build-info | grep 'Version' | head -1)"
fi

# ─────────────────────────────────────────
# BƯỚC 2: Cấu hình Suricata tối giản
# =============================================================================
# Chiến lược: Chúng ta KHÔNG dùng suricata.yaml mặc định vì nó rất phức tạp
# (hàng trăm dòng, nhiều rule set, nhiều output). Thay vào đó, ta override
# chỉ những phần quan trọng:
#   - Lắng nghe enp0s3 (mặt hướng Attacker)
#   - Chỉ load rule file của mình
#   - Output EVE JSON để watcher.py đọc
#   - Tắt hầu hết output khác để giảm I/O overhead
# =============================================================================
echo "[*] Ghi cấu hình Suricata tối giản..."

# Backup config gốc nếu chưa backup
if [[ ! -f "${SURICATA_CONF}.orig" ]]; then
    cp "$SURICATA_CONF" "${SURICATA_CONF}.orig"
    echo "[i] Đã backup config gốc → ${SURICATA_CONF}.orig"
fi

cat > "$SURICATA_CONF" << YAML
%YAML 1.1
---
# Suricata config tối giản cho kịch bản 1b Slow Loris
# Chỉ những gì cần thiết — tránh overhead không cần thiết trong benchmark

vars:
  address-groups:
    HOME_NET: "[10.10.1.0/24, 10.10.2.0/24]"
    EXTERNAL_NET: "!\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"

default-log-dir: /var/log/suricata/

# Output: chỉ EVE JSON — đây là output duy nhất watcher.py cần đọc.
# Tắt fast.log, stats.log để giảm I/O ảnh hưởng benchmark.
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      # Chỉ log alert — không log http, dns, flow... để file gọn
      types:
        - alert:
            payload: no
            metadata: yes

# Chỉ load rule file của dự án, không load emerging threats hay rule mặc định
# (các rule đó có thể gây false positive và tăng CPU không cần thiết)
default-rule-path: $RULES_DIR
rule-files:
  - slowloris.rules

# Cấu hình capture: lắng nghe enp0s3 — mặt nhìn về Attacker VM
# Suricata dùng af-packet (Linux native, hiệu năng tốt hơn pcap)
af-packet:
  - interface: $IFACE
    # threads: auto — để Suricata tự chọn số thread phù hợp với CPU
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Tắt engine thống kê để giảm CPU overhead trong khi benchmark
stats:
  enabled: no

# Threading tối giản
threading:
  set-cpu-affinity: no

# App layer protocols — chỉ enable HTTP vì ta chỉ quan tâm Slow Loris
app-layer:
  protocols:
    http:
      enabled: yes
    tls:
      enabled: no
    dns:
      enabled: no
    smtp:
      enabled: no
    ssh:
      enabled: no
    ftp:
      enabled: no
    dnp3:
      enabled: no
    modbus:
      enabled: no
YAML

echo "[+] Đã ghi $SURICATA_CONF"

# ─────────────────────────────────────────
# BƯỚC 3: Nạp rule file
# ─────────────────────────────────────────
echo "[*] Nạp rule Slow Loris..."
mkdir -p "$RULES_DIR"
cp "$SCRIPT_DIR/suricata_slowloris.rules" "$RULE_FILE"
echo "[+] Rule file → $RULE_FILE"
echo "    Số rule: $(grep -c '^alert' "$RULE_FILE")"

# ─────────────────────────────────────────
# BƯỚC 4: Validate config trước khi khởi động
# ─────────────────────────────────────────
echo "[*] Kiểm tra cú pháp config và rule..."
if suricata -T -c "$SURICATA_CONF" -l /var/log/suricata/ 2>&1 | grep -q "Configuration provided was successfully loaded"; then
    echo "[+] Config hợp lệ."
else
    # Suricata in thông báo thành công ra stderr, thử cách khác
    RESULT=$(suricata -T -c "$SURICATA_CONF" -l /var/log/suricata/ 2>&1 || true)
    if echo "$RESULT" | grep -qiE "error|failed"; then
        echo "[-] LỖI trong config hoặc rule:"
        echo "$RESULT"
        exit 1
    else
        echo "[+] Không phát hiện lỗi trong config."
    fi
fi

# ─────────────────────────────────────────
# BƯỚC 5: Khởi động Suricata service
# ─────────────────────────────────────────
echo "[*] Khởi động Suricata..."

# Systemd service của Suricata mặc định đọc interface từ /etc/default/suricata
# Ta override bằng cách chỉ định interface trong suricata.yaml (đã làm ở trên)
# và dùng systemctl
systemctl enable suricata 2>/dev/null || true
systemctl restart suricata

# Chờ Suricata khởi động hoàn toàn
echo -n "[*] Chờ Suricata sẵn sàng"
for i in $(seq 1 15); do
    sleep 1
    echo -n "."
    if systemctl is-active --quiet suricata; then
        # Kiểm tra thêm: file eve.json đã được tạo chưa
        if [[ -f "$EVE_LOG" ]]; then
            echo ""
            echo "[+] Suricata đang chạy và đã tạo $EVE_LOG"
            break
        fi
    fi
done

if ! systemctl is-active --quiet suricata; then
    echo ""
    echo "[-] LỖI: Suricata không khởi động được. Xem log:"
    journalctl -u suricata --no-pager -n 30
    exit 1
fi

# ─────────────────────────────────────────
# BƯỚC 6: Kiểm tra XDP Core API
# ─────────────────────────────────────────
echo "[*] Kiểm tra XDP Core API..."
if curl -sf http://127.0.0.1:8080/health > /dev/null; then
    echo "[+] XDP Core API đang chạy."
    curl -sf http://127.0.0.1:8080/health | python3 -m json.tool 2>/dev/null || true
else
    echo "[!] CẢNH BÁO: XDP Core API không phản hồi trên port 8080."
    echo "    Đảm bảo XDP service đã được khởi động trước khi chạy thực nghiệm."
fi

# ─────────────────────────────────────────
# TỔNG KẾT
# ─────────────────────────────────────────
echo ""
echo "============================================================"
echo " SETUP HOÀN TẤT"
echo "============================================================"
echo " Suricata:      $(systemctl is-active suricata)"
echo " Interface:     $IFACE"
echo " EVE log:       $EVE_LOG"
echo " Rule file:     $RULE_FILE"
echo ""
echo " Bước tiếp theo:"
echo "   1. Chạy thực nghiệm: sudo bash run_experiment_1b.sh"
echo "   2. Sau khi xong:     sudo bash teardown_rules_1b.sh"
echo "============================================================"