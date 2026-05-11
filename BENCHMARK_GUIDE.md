# BENCHMARK_GUIDE.md — Hướng dẫn chạy thực nghiệm

> Tài liệu này mô tả thứ tự thao tác cụ thể trên **Firewall VM** và **Attacker VM**
> cho từng kịch bản. Đọc kỹ **trước khi chạy** để tránh bỏ lỡ bước nào.

---

## Yêu cầu chung (kiểm tra trước tất cả kịch bản)

### Trên Firewall VM
- XDP Core API đang chạy tại `http://127.0.0.1:8080`
  - Kiểm tra: `curl http://127.0.0.1:8080/health`
- `ip_forward` đã bật: `cat /proc/sys/net/ipv4/ip_forward` → phải ra `1`

### Trên Attacker VM
- Network namespace **`ns_10`** (IP `10.10.1.10`) — dùng cho kịch bản **1a**
- Network namespace **`ns_11`** (IP `10.10.1.11`) — dùng cho kịch bản **1b**
- Network namespace **`ns_50`** (IP `10.10.1.50`) — legitimate user, dùng cho kịch bản **2**
- Kiểm tra: `ip netns list` → phải thấy `ns_10`, `ns_11`, `ns_50`
- SSH key từ Firewall VM đã được authorize (kiểm tra: `ssh kali@10.10.1.2 echo ok`)

### Trên Victim VM
- nginx đang chạy, lắng nghe port 80
- Kiểm tra từ Firewall VM: `curl http://10.10.2.2`

### Topology
```
[Attacker VM]                          [Firewall VM]                        [Victim VM]
eth0:  10.10.1.2    ─────────────────► enp0s8: 10.10.1.1                   eth0: 10.10.2.2
ns_10: 10.10.1.10   ─────────────────────────────────────────────────────► nginx:80  (attacker 1a)
ns_11: 10.10.1.11   ─────────────────────────────────────────────────────► nginx:80  (attacker 1b)
ns_50: 10.10.1.50   ─────────────────────────────────────────────────────► nginx:80  (legitimate)
                                        enp0s9: 10.10.2.1 ─────────────────►
```

> **Quan trọng:** Tấn công luôn xuất phát từ **namespace riêng** (`ns_10`/`ns_11`),
> không phải từ `eth0` (10.10.1.2). Điều này đảm bảo khi XDP block IP attacker,
> SSH control plane qua `eth0` vẫn hoạt động bình thường.

---

## Kịch bản 1a — Feedback Loop: Iptables → XDP (SYN Flood)

### Mục tiêu
So sánh 3 trạng thái bảo vệ:
| Phase | Mô tả |
|---|---|
| `baseline` | Không tấn công — đo trạng thái bình thường |
| `iptables_only` | SYN Flood bật, Iptables chặn, XDP transparent |
| `feedback_loop` | Iptables LOG → `feedback_loop_iptables.py` → XDP block tại driver |

**Source IP tấn công:** `10.10.1.10` (ns_10 trên Attacker VM)

### Bước 1 — Chuẩn bị môi trường (chạy 1 lần)

**Trên Firewall VM:**
```bash
cd /path/to/benchmark_hybrid_firewall/1a
sudo bash setup_rules_1a.sh
```
Script sẽ: flush iptables cũ → tạo chain `SYN_FLOOD_DETECT` (ngưỡng 100 SYN/s) →
cài rule LOG prefix `XDP_CANDIDATE:` → whitelist `ns_50` (10.10.1.50).

### Bước 2 — Cấu hình biến trong script (nếu cần)

Mở `run_experiment_1a.sh`, kiểm tra các biến đầu file:
```bash
ATTACKER_IP="10.10.1.2"          # IP SSH đến Attacker VM
ATTACKER_SSH_USER="kali"
ATTACKER_SUDO_PASS="kali"        # Mật khẩu sudo trên Attacker VM
ATTACKER_NS="ns_10"              # Namespace tấn công
ATTACKER_NS_IP="10.10.1.10"
VICTIM_IP="10.10.2.2"
PHASE_DURATION=60                # Giây mỗi phase
```

### Bước 3 — Chạy thực nghiệm

**Trên Firewall VM:**
```bash
sudo bash run_experiment_1a.sh
```

Script tự động:
1. Pre-flight: kill process thừa (`watcher.py`, `feedback_loop`), xóa XDP rules cũ → báo lỗi nếu không về 0
2. **Phase 1** (baseline): chạy `monitor.py`, không tấn công
3. **Phase 2** (iptables_only): SSH sang Attacker, chạy `hping3` trong `ns_10` bằng `sudo`
4. **Phase 3** (feedback_loop): khởi động `feedback_loop_iptables.py`, chạy lại hping3

> Script tự SSH sang Attacker VM. Nếu SSH thất bại sẽ in lệnh để chạy thủ công.

### Thao tác thủ công trên Attacker VM (nếu SSH không tự động)

```bash
# hping3 cần sudo vì dùng raw socket
echo 'kali' | sudo -S ip netns exec ns_10 hping3 -S -p 80 --flood 10.10.2.2
```
Dừng: `echo 'kali' | sudo -S pkill -9 -f hping3`

### Theo dõi realtime (terminal riêng trên Firewall VM)

```bash
# Log feedback loop:
tail -f /tmp/feedback_loop_1a.log   # hoặc xem stdout của script

# XDP rules đang active:
curl -s http://127.0.0.1:8080/rules | python3 -m json.tool

# Kernel log — xác nhận iptables LOG đang hoạt động:
sudo dmesg | grep XDP_CANDIDATE | tail -20
```

### Bước 4 — Dọn dẹp

**Trên Firewall VM:**
```bash
sudo bash teardown_rules_1a.sh
```

### Output kịch bản 1a

- **CSV:** `1a/results/exp1a_YYYYMMDD_HHMMSS.csv`
- Cột quan trọng: `phase`, `cpu_percent`, `nginx_latency_ms`, `legitimate_user_ok`, `xdp_rules_count`, `iptables_drops_total`
- **Kết quả kỳ vọng:** CPU giảm mạnh ở phase `feedback_loop` (XDP drop tại driver, bypass iptables), `legitimate_user_ok = 1` suốt

---

## Kịch bản 1b — Slow Loris: Suricata → watcher → XDP

### Mục tiêu
| Phase | Mô tả |
|---|---|
| `baseline` | Không tấn công |
| `no_feedback` | Slow Loris bật, Suricata phát hiện nhưng **không** có watcher → XDP không được báo |
| `full_stack` | Suricata → `watcher.py` → XDP block IP tấn công |

**Source IP tấn công:** `10.10.1.11` (ns_11 trên Attacker VM)

### Bước 1 — Cài đặt Suricata (chạy 1 lần)

**Trên Firewall VM:**
```bash
cd /path/to/benchmark_hybrid_firewall/1b
sudo bash setup_rules_1b.sh
```
Script sẽ: cài Suricata → ghi config tối giản → cài 3 rule Slow Loris →
khởi động Suricata service → verify EVE JSON log tại `/var/log/suricata/eve.json`.

### Bước 2 — Cài slowloris trên Attacker VM

```bash
# Trên Attacker VM:
pip install slowloris
# Kiểm tra:
slowloris --help
```

### Bước 3 — Cấu hình biến trong script (nếu cần)

```bash
ATTACKER_IP="10.10.1.2"
ATTACKER_USER="kali"
ATTACKER_NS="ns_11"              # Namespace tấn công
ATTACKER_SUDO_PASS="kali"        # sudo để dùng ip netns exec
SLOWLORIS_SOCKETS=150            # Số socket (tăng lên 300-500 nếu máy bare metal)
SLOWLORIS_SLEEP=10
```

### Bước 4 — Chạy thực nghiệm

**Trên Firewall VM:**
```bash
sudo bash run_experiment_1b.sh
```

Script tự động:
1. Pre-flight: kill process thừa, xóa XDP rules cũ
2. **Phase baseline** (60s): monitor, không tấn công
3. **Phase no_feedback** (120s): SSH → Slow Loris trong ns_11, Suricata chạy nhưng watcher KHÔNG chạy
4. **Phase full_stack** (120s): reset XDP, khởi động `watcher.py`, chạy lại Slow Loris

### Thao tác thủ công trên Attacker VM (nếu SSH không tự động)

```bash
# ip netns exec cần sudo
echo 'kali' | sudo -S ip netns exec ns_11 slowloris 10.10.2.2 --port 80 \
    --socket-count 150 --sleeptime 10
```
Dừng: `echo 'kali' | sudo -S pkill -9 -f slowloris`

### Theo dõi realtime trên Firewall VM

```bash
# Suricata có detect không:
sudo tail -f /var/log/suricata/eve.json | grep -E '"alert"|"src_ip"'

# watcher.py đã push XDP rule chưa:
curl -s http://127.0.0.1:8080/rules | python3 -m json.tool

# Số connection đến nginx (tăng cao = Slow Loris đang hoạt động):
watch -n1 "ss -tn state established '( dport = :80 )' | wc -l"
```

### Điều chỉnh nếu Suricata không alert

```bash
# Tăng socket count (trên Attacker VM):
echo 'kali' | sudo -S ip netns exec ns_11 slowloris 10.10.2.2 --port 80 \
    --socket-count 300 --sleeptime 10

# Hoặc giảm ngưỡng rule trong suricata_slowloris.rules:
# "count 20, seconds 10" → "count 10, seconds 10"
sudo systemctl reload suricata
```

### Bước 5 — Dọn dẹp

**Trên Firewall VM:**
```bash
sudo bash teardown_rules_1b.sh
```
Script dừng Suricata, xóa XDP rules, khôi phục config Suricata gốc.

### Output kịch bản 1b

- **CSV:** `1b/results/exp_1b_YYYYMMDD_HHMMSS.csv`
- **Log watcher:** `1b/results/feedback_loop_1b.log` — thời điểm chính xác block từng IP
- **Kết quả kỳ vọng:**
  - `nginx_conn_established` tăng cao ở `no_feedback` → giảm về 0 ở `full_stack`
  - `xdp_rules_count >= 1` trong `full_stack`
  - `legitimate_user_ok = 1` cuối `full_stack`

---

## Kịch bản 2 — GeoIP: XDP BPF LPM Trie vs Iptables/ipset

### Mục tiêu
So sánh latency p50/p95/p99 khi ruleset GeoIP tăng từ **100 → 10.000 CIDR**,
giữa XDP (BPF LPM Trie — O(log n) tối ưu cao) và Iptables/ipset.

**Đo latency từ:** `ns_50` (10.10.1.50) trên **Attacker VM** dùng `wrk`
**Attack traffic:** từ `eth0` Attacker VM với SNAT → source IP `1.180.1.1` (China Unicom)

### Bước 1 — Lấy dữ liệu GeoLite2

1. Đăng ký miễn phí tại: https://www.maxmind.com/en/geolite2/signup
2. Tải **GeoLite2 Country (CSV format)**
3. Giải nén, lấy 2 file:
   - `GeoLite2-Country-Blocks-IPv4.csv`
   - `GeoLite2-Country-Locations-en.csv`
4. Đặt **2 file vào thư mục `2/`** (cạnh các script)

### Bước 2 — Cài đặt SNAT trên Attacker VM (1 lần)

```bash
# Trên Attacker VM — đổi source IP thành 1.180.1.1 (CN Unicom, có trong GeoLite2)
sudo iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 1.180.1.1

# Xác nhận:
sudo iptables -t nat -L POSTROUTING -n -v
```

> `ns_50` (10.10.1.50) **không** bị SNAT vì nó dùng interface riêng trong namespace.

### Bước 3 — Cài đặt môi trường trên Firewall VM

```bash
cd /path/to/benchmark_hybrid_firewall/2
sudo bash setup_rules_2.sh
```
Script cài: `ipset`, `wrk`, `hping3`, kiểm tra XDP API và GeoLite2 CSV.

### Bước 4 — Cài wrk trong ns_50 trên Attacker VM

```bash
# Trên Attacker VM:
sudo apt-get install -y wrk

# Xác nhận wrk chạy được trong ns_50:
sudo ip netns exec ns_50 wrk --version
```

### Bước 5 — Chạy thực nghiệm

**Trên Firewall VM:**
```bash
sudo bash run_experiment_2.sh \
    --blocks    GeoLite2-Country-Blocks-IPv4.csv \
    --locations GeoLite2-Country-Locations-en.csv

# Tùy chọn:
#   --country CN          (mặc định CN)
#   --levels 100,1000     (chỉ chạy 2 mức)
#   --duration 30         (giảm thời gian đo)
```

Script tự động chạy **10 round** (5 mức × 2 implementation):
```
Mức 100   → Round A: XDP  → Round B: Iptables/ipset
Mức 500   → Round A: XDP  → Round B: Iptables/ipset
Mức 1000  → Round A: XDP  → Round B: Iptables/ipset
Mức 5000  → Round A: XDP  → Round B: Iptables/ipset
Mức 10000 → Round A: XDP  → Round B: Iptables/ipset
```

Mỗi round: nạp CIDR → bật SYN flood (source 1.180.1.1) → đo latency bằng `wrk` từ `ns_50` trên Attacker VM → thu thập monitor.py → xóa rules → nghỉ 10s.

### Thao tác thủ công trên Attacker VM (nếu SSH không tự động)

```bash
# Flood từ eth0 — SNAT sẽ đổi source thành 1.180.1.1 tự động
sudo hping3 -S -p 80 --flood 10.10.2.2
```
Dừng: `sudo pkill -9 -f hping3`

### Bước 6 — Dọn dẹp

**Trên Firewall VM:**
```bash
sudo bash teardown_rules_2.sh
```

**Trên Attacker VM — hủy SNAT:**
```bash
sudo iptables -t nat -D POSTROUTING -o eth0 -j SNAT --to-source 1.180.1.1
```

### Output kịch bản 2

- **`2/results/exp_2_summary_TIMESTAMP.csv`** — file chính để vẽ biểu đồ
  - Cột: `implementation`, `ruleset_size`, `latency_p50`, `latency_p95`, `latency_p99`, `req_per_sec`, `false_positive`, `cpu_avg`
- **`2/results/exp_2_detail_TIMESTAMP.csv`** — raw data từng giây

> **`false_positive` phải luôn = 0** — nếu không, ns_50 bị block nhầm, kịch bản thất bại.

### Vẽ biểu đồ

```bash
python3 plot_results.py \
    --scenario 2 \
    --csv 2/results/exp_2_summary_*.csv \
    --output 2/results/charts/
```

---

## Vẽ biểu đồ cho 1a và 1b

```bash
pip install matplotlib pandas

# Kịch bản 1a:
python3 plot_results.py --scenario 1a --csv 1a/results/exp1a_*.csv --output charts/

# Kịch bản 1b:
python3 plot_results.py --scenario 1b --csv 1b/results/exp_1b_*.csv --output charts/
```

---

## Tổng hợp thứ tự chạy nhanh

| Kịch bản | Firewall VM | Attacker VM |
|----------|------------|-------------|
| **1a** | `setup_rules_1a.sh` → `run_experiment_1a.sh` → `teardown_rules_1a.sh` | Script tự SSH. Nếu thủ công: `sudo ip netns exec ns_10 hping3 -S -p 80 --flood 10.10.2.2` |
| **1b** | `setup_rules_1b.sh` → `run_experiment_1b.sh` → `teardown_rules_1b.sh` | Cài `slowloris`. Script tự SSH. Nếu thủ công: `sudo ip netns exec ns_11 slowloris 10.10.2.2 --port 80 --socket-count 150` |
| **2** | Đặt GeoLite2 CSV vào `2/` → `setup_rules_2.sh` → `run_experiment_2.sh` → `teardown_rules_2.sh` | Setup SNAT 1 lần. Cài `wrk` trong `ns_50`. Script tự SSH. Dọn SNAT sau. |

---

## Debug thường gặp

| Triệu chứng | Nguyên nhân có thể | Kiểm tra |
|-------------|-------------------|----------|
| XDP rules ≠ 0 trước khi bắt đầu | Process thừa từ lần chạy trước | Script tự dọn; nếu vẫn còn: `curl -s http://127.0.0.1:8080/rules` |
| XDP API không phản hồi | XDP Core chưa chạy | Khởi động XDP Core trước |
| hping3: operation not permitted | Thiếu sudo / raw socket | Dùng `sudo -S` với password, đã sửa trong script |
| Suricata không alert | Socket count thấp / rule threshold cao | Tăng `--socket-count` hoặc giảm ngưỡng rule |
| ns_50 bị block nhầm (false_positive=1) | CIDR GeoIP overlap với dải lab | Kiểm tra whitelist trong `load_geoip_xdp.py` |
| `stop_attack` WARN | Process chưa chết kịp trước khi check | Đã dùng `pkill -9` + `sleep 2`; thường là OK |
| Terminal treo sau khi script kết thúc | `feedback_loop` hoặc `watcher` không thoát | Đã sửa: SIGTERM handler + `select()` timeout |
| IPT DROP = 0 suốt | Bug cũ `--line-numbers` | Đã sửa trong `monitor.py` |
