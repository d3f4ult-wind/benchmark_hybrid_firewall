#!/bin/bash
# setup_rules_1a.sh — Nạp Iptables rules cho Kịch bản 1a
# =========================================================
# Script này làm hai việc chính:
#   1. Cấu hình Iptables để phát hiện và chặn SYN Flood
#   2. LOG các IP bị phát hiện với prefix "XDP_CANDIDATE: " để
#      feedback_loop_iptables.py có thể đọc và đẩy xuống XDP
#
# Chạy script này MỘT LẦN trước khi bắt đầu thực nghiệm.
# Để dọn dẹp sau thực nghiệm, chạy teardown_rules_1a.sh
#
# Yêu cầu: chạy với quyền root (sudo)
# Môi trường: Firewall VM, Ubuntu
#
# Cách dùng:
#   sudo bash setup_rules_1a.sh
#   sudo bash setup_rules_1a.sh --phase2-only   # Chỉ setup cho Phase 2 (Iptables-only)
#   sudo bash setup_rules_1a.sh --phase3         # Setup thêm LOG rule cho feedback loop

set -e  # Dừng ngay nếu có lệnh nào lỗi

# ---------------------------------------------------------------------------
# CẤU HÌNH — Chỉnh sửa nếu cần
# ---------------------------------------------------------------------------

# Interface nhận traffic từ Attacker — SỬA LẠI ĐÚNG TÊN INTERFACE!
IFACE_IN="enp0s8"          # Interface hướng về Attacker (10.10.1.x)
IFACE_OUT="enp0s9"         # Interface hướng về Victim (10.10.2.x)
                            # Nếu máy mạnh hơn và dùng dedicated NIC: đổi tên cho đúng

# Địa chỉ Victim (nginx)
VICTIM_IP="10.10.2.2"
VICTIM_PORT="80"

# Prefix cho Iptables LOG — phải khớp với IPTABLES_LOG_PREFIX trong feedback_loop_iptables.py
LOG_PREFIX="XDP_CANDIDATE: "

# Ngưỡng SYN rate để coi là flood (packets/giây từ một IP)
# Máy yếu (VirtualBox): 100/s là đủ nhạy để phát hiện hping3 --flood
# Nếu máy mạnh hơn (bare metal): có thể tăng lên 500/s hoặc 1000/s để tránh false positive
SYN_RATE="100/s"
SYN_BURST="200"  # Cho phép burst ngắn trước khi trigger rule

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

# ---------------------------------------------------------------------------
# BƯỚC 0: Kiểm tra môi trường
# ---------------------------------------------------------------------------

check_root
log "=== Setup Iptables rules cho Kịch bản 1a ==="
log "Interface IN (Attacker side): $IFACE_IN"
log "Interface OUT (Victim side):  $IFACE_OUT"
log "Victim: $VICTIM_IP:$VICTIM_PORT"
log "SYN rate threshold: $SYN_RATE (burst: $SYN_BURST)"

# Kiểm tra iptables có cài không
if ! command -v iptables &> /dev/null; then
    log "LỖI: iptables chưa được cài đặt"
    exit 1
fi

# Kiểm tra ip_forward đã bật chưa — bắt buộc để Firewall VM forward packet
FORWARD_STATUS=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$FORWARD_STATUS" != "1" ]; then
    log "CẢNH BÁO: ip_forward chưa được bật. Đang bật..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    log "ip_forward đã được bật."
else
    log "ip_forward: OK (đã bật)"
fi

# ---------------------------------------------------------------------------
# BƯỚC 1: Xóa sạch rules cũ để bắt đầu từ trạng thái sạch
# ---------------------------------------------------------------------------

log "Đang xóa rules cũ..."
iptables -F          # Flush tất cả rules trong tất cả chains
iptables -X          # Xóa các chain tùy chỉnh
iptables -Z          # Reset tất cả counters về 0 (quan trọng cho đo lường!)
log "Đã xóa rules cũ và reset counters."

# ---------------------------------------------------------------------------
# BƯỚC 2: Policy mặc định — ACCEPT tất cả (không chặn gì cả mặc định)
# ---------------------------------------------------------------------------
# Trong lab test, ta dùng whitelist approach: chặn cụ thể, còn lại cho qua.
# Đây phù hợp hơn DROP mặc định để tránh lock out SSH trong quá trình test.

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
log "Policy mặc định: ACCEPT (whitelist mode)"

# ---------------------------------------------------------------------------
# BƯỚC 3: Rules nền tảng — cho phép các kết nối cần thiết
# ---------------------------------------------------------------------------

# Cho phép loopback
iptables -A INPUT -i lo -j ACCEPT

# Cho phép các kết nối đã được ESTABLISHED trước đó
# QUAN TRỌNG: Rule này phải ở trước SYN flood rule để không block response packets
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Cho phép SSH (để không bị lock out khi đang thực nghiệm)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Cho phép traffic từ ns_50 (legitimate user) — IP này KHÔNG BAO GIỜ bị block
# Đây là guarantee cho success criterion của kịch bản
iptables -A FORWARD -s 10.10.1.50 -j ACCEPT
iptables -A FORWARD -d 10.10.1.50 -j ACCEPT
log "Rules nền tảng: loopback, ESTABLISHED, SSH, ns_50 whitelist — OK"

# ---------------------------------------------------------------------------
# BƯỚC 4: Chain tùy chỉnh để phát hiện SYN Flood
# ---------------------------------------------------------------------------
# Tạo một chain riêng cho SYN flood detection — dễ quản lý và debug hơn
# so với nhét tất cả vào chain FORWARD.

iptables -N SYN_FLOOD_DETECT 2>/dev/null || iptables -F SYN_FLOOD_DETECT

# Rule trong chain SYN_FLOOD_DETECT:
# Nếu SYN rate từ một IP vượt ngưỡng → LOG với prefix XDP_CANDIDATE rồi DROP
# hashlimit-mode srcip: theo dõi rate per source IP (không phải tổng)
# hashlimit-htable-expire: entry trong hash table hết hạn sau 10 giây không có packet

iptables -A SYN_FLOOD_DETECT \
    -p tcp --syn \
    -m hashlimit \
        --hashlimit-name syn_flood \
        --hashlimit-above "$SYN_RATE" \
        --hashlimit-burst "$SYN_BURST" \
        --hashlimit-mode srcip \
        --hashlimit-htable-expire 10000 \
    -j LOG \
        --log-prefix "$LOG_PREFIX" \
        --log-level 4 \
        --log-ip-options

# Sau khi LOG, DROP luôn gói tin đó
iptables -A SYN_FLOOD_DETECT \
    -p tcp --syn \
    -m hashlimit \
        --hashlimit-name syn_flood \
        --hashlimit-above "$SYN_RATE" \
        --hashlimit-burst "$SYN_BURST" \
        --hashlimit-mode srcip \
        --hashlimit-htable-expire 10000 \
    -j DROP

# Các gói tin không vượt ngưỡng → RETURN về chain cha (FORWARD) để tiếp tục xử lý
iptables -A SYN_FLOOD_DETECT -j RETURN

log "Chain SYN_FLOOD_DETECT đã được tạo (threshold: $SYN_RATE, burst: $SYN_BURST)"

# ---------------------------------------------------------------------------
# BƯỚC 5: Đưa traffic vào chain phát hiện
# ---------------------------------------------------------------------------
# Chỉ forward traffic đến Victim (nginx) qua chain phát hiện SYN Flood.
# Traffic từ Attacker interface đến Victim port 80.

iptables -A FORWARD \
    -i "$IFACE_IN" \
    -d "$VICTIM_IP" \
    -p tcp \
    --dport "$VICTIM_PORT" \
    -j SYN_FLOOD_DETECT

log "FORWARD rule → SYN_FLOOD_DETECT chain đã được gắn vào $IFACE_IN → $VICTIM_IP:$VICTIM_PORT"

# ---------------------------------------------------------------------------
# BƯỚC 6: Giới hạn tốc độ LOG để tránh spam kernel log quá nhiều
# ---------------------------------------------------------------------------
# Nếu Attacker gửi 10,000 pps, không nên log 10,000 dòng/giây vào kernel log.
# Rule LOG ở trên đã có hashlimit nên thực tế chỉ log khi vượt ngưỡng.
# Thêm một limit tổng thể ở đây phòng trường hợp nhiều attacker IP.

# Giới hạn: tối đa 10 LOG entries/giây cho prefix XDP_CANDIDATE
# Điều này không ảnh hưởng đến DROP — chỉ giới hạn số dòng LOG ghi vào file
# Máy mạnh hơn: có thể tăng lên 50/s hoặc 100/s nếu muốn log nhiều IP hơn
iptables -A FORWARD \
    -p tcp --syn \
    -m limit --limit 10/s --limit-burst 20 \
    -j LOG \
    --log-prefix "XDP_RATE_LIMITED: " \
    --log-level 6

log "LOG rate limiting: tối đa 10 entries/giây"

# ---------------------------------------------------------------------------
# BƯỚC 7: Cho phép tất cả traffic khác qua Firewall (forwarding)
# ---------------------------------------------------------------------------

iptables -A FORWARD -j ACCEPT
log "Catch-all FORWARD ACCEPT rule added."

# ---------------------------------------------------------------------------
# BƯỚC 8: Xác nhận và in ra danh sách rules đã cài
# ---------------------------------------------------------------------------

log ""
log "=== Danh sách rules hiện tại ==="
iptables -nvL --line-numbers
log ""
log "=== Setup hoàn tất ==="
log "Để bắt đầu Phase 3 (Feedback Loop), chạy:"
log "  sudo python3 feedback_loop_iptables.py --use-journald"
log "Hoặc nếu có /var/log/kern.log:"
log "  sudo python3 feedback_loop_iptables.py --log-file /var/log/kern.log"
log ""
log "Để dọn dẹp sau thực nghiệm, chạy:"
log "  sudo bash teardown_rules_1a.sh"
