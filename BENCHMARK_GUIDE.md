# BENCHMARK_GUIDE.md — Hướng dẫn chạy thực nghiệm

> Tài liệu này mô tả thứ tự thao tác cụ thể trên **Firewall VM** và **Attacker VM**  
> cho từng kịch bản. Đọc kỹ **trước khi chạy** để tránh bỏ lỡ bước nào.

---

## Yêu cầu chung (kiểm tra trước tất cả kịch bản)

### Trên Firewall VM
- XDP Core API đang chạy và lắng nghe tại `http://127.0.0.1:8080`
- Kiểm tra: `curl http://127.0.0.1:8080/health`
- `ip_forward` đã bật: `cat /proc/sys/net/ipv4/ip_forward` → phải ra `1`

### Trên Attacker VM
- Network namespace `ns_50` đã tạo với IP `10.10.1.50`
- Kiểm tra: `ip netns list | grep ns_50`
- `wrk` đã cài và dùng được trong ns_50: `ip netns exec ns_50 wrk --version`

### Trên Victim VM
- nginx đang chạy, lắng nghe port 80
- Kiểm tra: `curl http://10.10.2.2`  → phải trả về `"Victim Server - Benchmark Target"`

### Topology nhắc nhở
```
[Attacker VM]                          [Firewall VM]                        [Victim VM]
eth0:  10.10.1.2    ─────────────────► enp0s8: 10.10.1.1                   eth0: 10.10.2.2
ns_50: 10.10.1.50   ──────────────────────────────────────────────────────► nginx:80
                                        enp0s9: 10.10.2.1 ─────────────────►
```
> **Lưu ý:** `ns_50` (10.10.1.50) nằm trên **Attacker VM**, không phải Firewall VM.

---

## Kịch bản 1a — Feedback Loop: Iptables → XDP (chặn SYN Flood)

### Mục tiêu
So sánh 3 trạng thái:
1. Baseline (không tấn công)
2. Iptables-only chặn SYN Flood (không có XDP)
3. Iptables LOG → feedback loop → XDP block tại driver

### Bước 1 — Chuẩn bị (chạy 1 lần duy nhất)

**Trên Firewall VM:**
```bash
cd /path/to/benchmark_hybrid_firewall/1a
sudo bash setup_rules_1a.sh
```
Script sẽ:
- Flush toàn bộ iptables rules cũ
- Tạo chain `SYN_FLOOD_DETECT` với ngưỡng `100/s` burst `200`
- Cài rule LOG với prefix `XDP_CANDIDATE:` khi phát hiện SYN flood
- Cho phép ns_50 (10.10.1.50) luôn đi qua

### Bước 2 — Chạy thực nghiệm tự động

**Trên Firewall VM** (script tự orchestrate 3 phase):
```bash
sudo bash run_experiment_1a.sh
# Hoặc tùy chỉnh:
sudo bash run_experiment_1a.sh --duration=120 --attacker-user=kali
```

Script tự động:
- Phase 1 (baseline, 60s): Chạy monitor.py, không tấn công
- Phase 2 (iptables_only, 60s): SSH sang Attacker VM, kích hoạt hping3, monitor.py đo
- Phase 3 (feedback_loop, 60s): Khởi động feedback_loop_iptables.py, kích hoạt lại hping3

> **Nếu không có SSH tự động:** Script sẽ dừng và hỏi bạn tự chạy lệnh trên Attacker VM.

### Thao tác thủ công trên Attacker VM (nếu cần)

**Phase 2 — SYN Flood không có feedback loop:**
```bash
# Trên Attacker VM, chạy khi script 1a yêu cầu:
sudo hping3 -S -p 80 --flood 10.10.2.2
```

**Phase 3 — SYN Flood với feedback loop đang hoạt động:**
```bash
# Trên Attacker VM, chạy lại khi script 1a yêu cầu:
sudo hping3 -S -p 80 --flood 10.10.2.2
```

> **Dừng tấn công:** Nhấn `Ctrl+C` trong terminal hping3, hoặc `pkill -f hping3`

### Theo dõi feedback loop (terminal riêng trên Firewall VM)

```bash
# Xem log feedback loop realtime:
tail -f 1a/feedback_loop_1a.log

# Xác nhận XDP đã nhận rule:
curl http://127.0.0.1:8080/rules | python3 -m json.tool
```

### Bước 3 — Dọn dẹp sau thực nghiệm

**Trên Firewall VM:**
```bash
sudo bash teardown_rules_1a.sh
```

### Output

File CSV tại `1a/results/exp1a_YYYYMMDD_HHMMSS.csv`  
Các cột quan trọng cần xem: `phase`, `cpu_percent`, `nginx_latency_ms`, `legitimate_user_ok`, `xdp_rules_count`

---

## Kịch bản 1b — Slow Loris: Suricata → watcher → XDP

### Mục tiêu
Chứng minh giới hạn khi không có feedback loop (Suricata phát hiện nhưng không ai xử lý),  
và hiệu quả khi có feedback loop hoàn chỉnh (Suricata → watcher.py → XDP).  
Metric chính: **detection + response latency**.

### Bước 1 — Cài đặt Suricata (chạy 1 lần duy nhất)

**Trên Firewall VM:**
```bash
cd /path/to/benchmark_hybrid_firewall/1b
sudo bash setup_rules_1b.sh
```
Script sẽ:
- Cài Suricata từ apt (nếu chưa có)
- Ghi file `/etc/suricata/suricata.yaml` tối giản (backup gốc vào `.orig`)
- Cài 3 rule phát hiện Slow Loris vào `/etc/suricata/rules/slowloris.rules`
- Khởi động Suricata service, verify EVE JSON log tại `/var/log/suricata/eve.json`
- Kiểm tra XDP Core API

### Bước 2 — Chuẩn bị trên Attacker VM

**Trên Attacker VM, cài slowloris (nếu chưa có):**
```bash
pip install slowloris
# Kiểm tra:
slowloris --help
```

### Bước 3 — Chạy thực nghiệm tự động

**Trên Firewall VM:**
```bash
sudo bash run_experiment_1b.sh
```

Script tự động chạy 3 phase:

| Phase | Thời gian | Mô tả |
|---|---|---|
| `baseline` | 60s | Không tấn công, đo trạng thái bình thường |
| `no_feedback` | 120s | Slow Loris tấn công, Suricata chạy nhưng watcher.py KHÔNG chạy |
| `full_stack` | 120s | Reset XDP, bật watcher.py, Slow Loris tấn công lại |

### Thao tác thủ công trên Attacker VM (nếu SSH không thành công)

**Phase 2 & 3 — Slow Loris attack:**
```bash
# Trên Attacker VM, chạy khi script 1b yêu cầu:
slowloris 10.10.2.2 --port 80 --socket-count 150 --sleeptime 10

# Nếu muốn mạnh hơn (bare metal):
slowloris 10.10.2.2 --port 80 --socket-count 500 --sleeptime 10
```

> **Dừng tấn công:** Nhấn `Ctrl+C` trong terminal slowloris, hoặc `pkill -f slowloris`

### Theo dõi realtime trên Firewall VM

```bash
# Theo dõi Suricata có detect được không:
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool

# Theo dõi feedback loop (phase 3):
tail -f 1b/results/feedback_loop_1b.log

# Kiểm tra XDP rules đã được push:
curl http://127.0.0.1:8080/rules | python3 -m json.tool

# Theo dõi nginx connections (chỉ số quan trọng cho Slow Loris):
watch -n1 "ss -tn state established dport :80 | wc -l"
```

### Điều chỉnh nếu Suricata không phát hiện (phase no_feedback kết thúc mà EVE log trống)

```bash
# Tăng số socket (trên Attacker VM):
slowloris 10.10.2.2 --port 80 --socket-count 300 --sleeptime 10

# Hoặc giảm ngưỡng Rule 1 trong suricata_slowloris.rules:
# Đổi "count 20, seconds 10" thành "count 10, seconds 10"
# Sau đó reload Suricata:
sudo systemctl reload suricata
```

### Bước 4 — Dọn dẹp

**Trên Firewall VM:**
```bash
sudo bash teardown_rules_1b.sh
```
Script sẽ: dừng Suricata, xóa XDP rules, xóa iptables rules, khôi phục Suricata config.

### Output

- CSV chi tiết: `1b/results/exp_1b_YYYYMMDD_HHMMSS.csv`
- Log feedback loop: `1b/results/feedback_loop_1b.log` ← ghi lại chính xác thời điểm block từng IP

**Metrics cần kiểm tra:**
- `nginx_conn_established` tăng cao ở phase `no_feedback` → giảm ở `full_stack`
- `xdp_rules_count` ≥ 1 ở phase `full_stack`
- `legitimate_user_ok = 1` ở cuối phase `full_stack`

---

## Kịch bản 2 — GeoIP: XDP BPF LPM Trie vs Iptables/ipset

### Mục tiêu
So sánh latency p50/p95/p99 của nginx dưới tải khi ruleset GeoIP tăng từ  
100 → 500 → 1.000 → 5.000 → 10.000 CIDR, giữa XDP và Iptables/ipset.

### Bước 1 — Lấy dữ liệu GeoLite2 (thực hiện trước)

1. Đăng ký tài khoản miễn phí tại: https://www.maxmind.com/en/geolite2/signup
2. Tải **GeoLite2 Country (CSV format)**
3. Giải nén, lấy 2 file:
   - `GeoLite2-Country-Blocks-IPv4.csv`
   - `GeoLite2-Country-Locations-en.csv`
4. **Đặt 2 file đó vào thư mục `2/`** (cùng chỗ với các script)

### Bước 2 — Chuẩn bị SNAT trên Attacker VM (chạy 1 lần duy nhất)

**Trên Attacker VM:**
```bash
# Setup SNAT — đổi source IP thành 1.180.1.1 (China Unicom, có trong GeoLite2-CN)
sudo iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 1.180.1.1

# Xác nhận:
sudo iptables -t nat -L POSTROUTING -n -v
```

> **Lưu ý:** ns_50 (10.10.1.50) KHÔNG bị ảnh hưởng bởi SNAT vì nó dùng interface riêng trong network namespace, không đi qua eth0 của Attacker VM.

### Bước 3 — Cài đặt môi trường trên Firewall VM

**Trên Firewall VM:**
```bash
cd /path/to/benchmark_hybrid_firewall/2
sudo bash setup_rules_2.sh
```
Script sẽ cài: `ipset`, `wrk`, `hping3`, kiểm tra XDP API, kiểm tra GeoLite2 CSV, in hướng dẫn SNAT.

### Bước 4 — Chạy thực nghiệm

**Trên Firewall VM:**
```bash
sudo bash run_experiment_2.sh \
    --blocks    GeoLite2-Country-Blocks-IPv4.csv \
    --locations GeoLite2-Country-Locations-en.csv

# Tuỳ chọn thêm:
#   --country CN        (mặc định CN — Trung Quốc, có ~8000-10000 CIDR)
#   --levels 100,1000   (chỉ chạy 2 mức thay vì 5)
#   --duration 30       (giảm thời gian đo mỗi round xuống 30s)
```

Script tự động chạy **10 round** (5 mức × 2 implementation):

```
Mức 100  → Round A: XDP   → Round B: Iptables/ipset
Mức 500  → Round A: XDP   → Round B: Iptables/ipset
Mức 1000 → Round A: XDP   → Round B: Iptables/ipset
Mức 5000 → Round A: XDP   → Round B: Iptables/ipset
Mức 10000→ Round A: XDP   → Round B: Iptables/ipset
```

Mỗi round thực hiện:
1. Nạp N CIDR vào XDP (hoặc ipset)
2. Bắt đầu SYN flood từ Attacker VM (với SNAT → source IP `1.180.1.1`)
3. Đo latency bằng `wrk` từ network namespace `ns_50`
4. Thu thập CPU/memory bằng `monitor.py`
5. Xóa rules, nghỉ 10s

### Thao tác thủ công trên Attacker VM (nếu SSH không thành công)

**Khi script 2 yêu cầu, chạy trên Attacker VM:**
```bash
# (SNAT đã setup sẽ tự đổi source IP → 1.180.1.1)
sudo hping3 -S -p 80 --flood 10.10.2.2
```
> **Dừng tấn công:** Nhấn `Ctrl+C`, hoặc `pkill -f hping3`

### Bước 5 — Dọn dẹp

**Trên Firewall VM:**
```bash
sudo bash teardown_rules_2.sh
```

**Trên Attacker VM — hủy SNAT:**
```bash
sudo iptables -t nat -D POSTROUTING -o eth0 -j SNAT --to-source 1.180.1.1
```

### Output

- **`2/results/exp_2_summary_TIMESTAMP.csv`** — file chính để vẽ biểu đồ  
  Cột: `implementation, ruleset_size, latency_p50, latency_p95, latency_p99, req_per_sec, false_positive, cpu_avg`

- **`2/results/exp_2_detail_TIMESTAMP.csv`** — raw data từng giây của monitor.py

**Cột `false_positive` phải luôn = 0** — nếu không, ns_50 bị block nhầm, kịch bản thất bại.

### Vẽ biểu đồ sau khi có CSV

```bash
python3 plot_results.py \
    --summary 2/results/exp_2_summary_TIMESTAMP.csv \
    --output  2/results/charts/
```

---

## Tổng hợp: Thứ tự chạy nhanh

| Bước | Firewall VM | Attacker VM |
|------|------------|-------------|
| **1a** | `setup_rules_1a.sh` → `run_experiment_1a.sh` → `teardown_rules_1a.sh` | `hping3 -S -p 80 --flood 10.10.2.2` (khi được yêu cầu) |
| **1b** | `setup_rules_1b.sh` → `run_experiment_1b.sh` → `teardown_rules_1b.sh` | `pip install slowloris` → `slowloris 10.10.2.2 --port 80 --socket-count 150 --sleeptime 10` |
| **2** | Đặt GeoLite2 CSV vào `2/` → `setup_rules_2.sh` → `run_experiment_2.sh` → `teardown_rules_2.sh` | Setup SNAT 1 lần → `hping3 -S -p 80 --flood 10.10.2.2` → hủy SNAT |

---

## Ghi chú debug thường gặp

| Triệu chứng | Kiểm tra |
|-------------|----------|
| XDP API không phản hồi | `curl http://127.0.0.1:8080/health` — khởi động XDP Core nếu chưa chạy |
| Iptables không LOG | `dmesg \| grep XDP_CANDIDATE` — kiểm tra kernel log |
| Suricata không alert | `sudo tail /var/log/suricata/eve.json` — tăng socket count hoặc giảm ngưỡng rule |
| ns_50 bị block nhầm | Kiểm tra whitelist trong `watcher.py` và `load_geoip_xdp.py` |
| wrk lỗi "namespace" | Kiểm tra `ip netns list` và `ip netns exec ns_50 ip addr` |
| hping3 không đổi IP | Kiểm tra SNAT: `sudo iptables -t nat -L POSTROUTING -n -v` |
