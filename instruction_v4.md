# instruction.md — Phiên làm việc v4
> Tóm tắt tiến độ đồ án: Hệ thống tường lửa kết hợp thông minh XDP/eBPF  
> Mục đích file này: Làm context đầy đủ cho phiên làm việc tiếp theo.  
> Cập nhật lần: v4 — sau khi hoàn thành code toàn bộ kịch bản 1b và kịch bản 2.  
> Trạng thái: Tất cả code đã viết xong. Chưa chạy thực tế trên lab.  
> Phiên tiếp theo: Debug / chạy thực nghiệm, hoặc sửa lỗi nếu phát sinh.

---

## 1. Tổng quan đồ án

Tên đề tài là "Xây dựng hệ thống tường lửa kết hợp thông minh dựa trên công nghệ XDP/eBPF". Điểm cốt lõi cần chứng minh là: **dù bị tấn công DDoS, dịch vụ hợp lệ (nginx) vẫn phải hoạt động được**. Đây là success criterion bắt buộc cho mọi kịch bản — CPU thấp hay drop rate cao không có giá trị nếu nginx chết và user hợp lệ không truy cập được.

Mã nguồn XDP/eBPF (C/Go) kế thừa từ sinh viên năm trước — đã chứng minh XDP mạnh hơn Iptables/Nftables đơn thuần với ICMP/SYN/UDP Flood. Nhiệm vụ đồ án này là xây dựng kiến trúc **đa tầng thông minh** có feedback loop, không phải làm lại từ đầu.

---

## 2. Kiến trúc hệ thống

Hệ thống có 3 tầng xếp chồng theo thứ tự từ thấp lên cao.

**Tầng 1 — XDP/eBPF** chạy tại network driver, drop gói tin trước khi vào kernel network stack. Đây là tầng nhanh nhất (sub-microsecond), nhưng bị điểm mù ở các tấn công tầng ứng dụng (L7) như Slow Loris vì mỗi packet nhìn hợp lệ về mặt network.

**Tầng 2 — Iptables/Nftables (Netfilter)** xử lý luật stateful và phức tạp hơn. Overhead cao hơn XDP nhưng hiểu được trạng thái connection.

**Tầng 3 — Suricata (IDS/IPS passive mode)** phân tích đến tầng ứng dụng (L7), phát hiện các pattern tấn công mà XDP và Iptables không thấy được.

**Feedback loop** là cơ chế cốt lõi kết nối các tầng: khi Iptables hoặc Suricata xác định được IP xấu, chúng đẩy IP đó xuống XDP qua REST API. Từ đó XDP block ngay tại driver, giải phóng tài nguyên cho tầng trên. REST API chỉ là control plane, chỉ gọi một lần duy nhất per IP — sau đó XDP lookup hoàn toàn trong kernel.

---

## 3. XDP Core API (kế thừa, port 8080)

Các endpoint cần dùng: `POST /rules` để thêm luật block, `DELETE /rules` để xóa, `GET /rules` để lấy danh sách, `GET /health` để lấy CPU%, Memory_MB, xdp_attached.

Payload cho POST/DELETE: `{"subnet": "IP/CIDR", "proto": <số>, "port": <số>, "action": "DROP"}`. Proto dùng số hiệu: TCP=6, UDP=17, ICMP=1.

Cấu trúc BPF Maps: `subnet_map` dùng `BPF_MAP_TYPE_LPM_TRIE` (tối đa 10.000 entries), `rule_map` dùng `BPF_MAP_TYPE_HASH` (tối đa 65.536 entries).

**Lỗi thiết kế quan trọng — BẮT BUỘC ĐỌC KỸ:** `rule_map` dùng exact match 100%, không có wildcard. Khi packet TCP/UDP đến, XDP tra cứu key `{subnet_id, proto, port_thực_tế}`. Nếu rule nạp với `port=0` thì key `{subnet_id, 6, 0}` không match với packet đến port 80 (`{subnet_id, 6, 80}`). Do đó **port=0 không phải wildcard cho TCP/UDP** — phải gọi API riêng cho từng port cụ thể. Ngoại lệ duy nhất: ICMP (proto=1) hardcode `port=0` trong `handle_icmp` nên **bắt buộc** truyền `port=0`. Lỗi này được giữ nguyên tạm thời theo mã nguồn kế thừa, sẽ sửa sau khi thực nghiệm xong.

---

## 4. Topology Lab

```
[Attacker VM]                    [Firewall VM]                         [Victim VM]
 eth0: 10.10.1.2                  enp0s3: 10.10.1.1 (XDP attach)        eth0: 10.10.2.2
 ns_10: 10.10.1.10                enp0s8: 10.10.2.1                     nginx: port 80
 ns_11: 10.10.1.11                XDP Core API: 127.0.0.1:8080          worker_connections: 4096
 ns_50: 10.10.1.50 (legitimate)   Suricata (passive, enp0s3 only)       keepalive_timeout: 0
                                  Iptables/Nftables                     response: "Victim Server - Benchmark Target"
                                  Python Watcher / Feedback scripts
                                  ip_forward = 1
```

Tên interface thực tế là `enp0s3` và `enp0s8`. Tất cả script đều có biến `IFACE` ở đầu file. XDP attach vào `enp0s3` — interface nhận traffic từ Attacker. Suricata chỉ lắng nghe `enp0s3`, không lắng nghe `enp0s8`.

**ns_50 (10.10.1.50) là legitimate user probe** — không bao giờ bị block trong bất kỳ kịch bản nào. Đây là điều kiện thành công bắt buộc.

**Về nginx trên Victim:** `keepalive_timeout 0` và `worker_connections 4096`. Slow Loris vẫn nguy hiểm dù keepalive tắt vì nó tấn công ở giai đoạn gửi header (trước khi request hoàn thành), không phải sau. Tuy nhiên với 4096 connections cần ít nhất 150–500 socket để thấy tác động.

---

## 5. Cấu trúc thư mục dự án (HOÀN CHỈNH)

```
benchmark_hybrid_firewall/
├── instruction.md (v4)             ← File này
├── monitor.py                      ← DÙNG CHUNG cho cả 3 kịch bản (đã viết xong)
├── 1a/                             ← Kịch bản 1a (ĐÃ HOÀN THÀNH)
│   ├── setup_rules_1a.sh
│   ├── feedback_loop_iptables.py
│   ├── run_experiment_1a.sh
│   └── teardown_rules_1a.sh
├── 1b/                             ← Kịch bản 1b (CODE XONG — chưa chạy thực tế)
│   ├── suricata_slowloris.rules    ✓
│   ├── watcher.py                  ✓
│   ├── setup_rules_1b.sh           ✓
│   ├── run_experiment_1b.sh        ✓
│   └── teardown_rules_1b.sh        ✓
└── 2/                              ← Kịch bản 2 (CODE XONG — chưa chạy thực tế)
    ├── load_geoip_xdp.py           ✓
    ├── load_geoip_iptables.sh      ✓
    ├── setup_rules_2.sh            ✓
    ├── run_experiment_2.sh         ✓
    └── teardown_rules_2.sh         ✓
```

---

## 6. Chi tiết kịch bản 1a (ĐÃ HOÀN THÀNH)

### Mục tiêu

So sánh CPU usage, memory, và latency khi chặn SYN Flood hoàn toàn bằng Iptables so với khi có feedback loop về XDP. Chứng minh sau khi feedback loop kích hoạt, tải trên Iptables giảm xuống và nginx phục vụ request hợp lệ ổn định hơn.

### Phase structure: 3 phase

`baseline` (60s) → cooldown → `iptables_only` (60s) → cooldown → `feedback_loop` (60s). Tấn công bằng `hping3 -S -p 80 --flood`. Ngưỡng hashlimit `100/s` burst `200` cho VirtualBox, tăng lên `500/s` cho bare metal.

### feedback_loop_iptables.py

Đọc kernel log, tìm prefix `XDP_CANDIDATE:`, gọi XDP API riêng cho từng port trong `PORTS_TO_BLOCK = [80]`. ICMP gọi riêng với `port=0`. Debounce 5 giây.

---

## 7. Chi tiết kịch bản 1b — Slow Loris (CODE XONG)

### Mục tiêu

Chứng minh giới hạn của kiến trúc thiếu feedback loop (Suricata phát hiện nhưng không ai xử lý), và giá trị của feedback loop hoàn chỉnh (Suricata → watcher → XDP). Metric quan trọng nhất là **detection + response latency** — thời gian từ khi alert xuất hiện trong EVE JSON đến khi XDP rule có hiệu lực.

### Cách chạy

```bash
sudo bash setup_rules_1b.sh          # Cài Suricata, cấu hình, nạp rule — chỉ chạy 1 lần
sudo bash run_experiment_1b.sh       # Chạy 3 phase tự động
sudo bash teardown_rules_1b.sh       # Dọn dẹp
```

### Phase structure: 3 phase

`baseline` (60s): Không có tấn công, đo trạng thái bình thường.

`no_feedback` (120s): Slow Loris tấn công. Suricata chạy passive nhưng `watcher.py` KHÔNG chạy. Mục đích: chứng minh thiếu feedback loop thì nginx bị ảnh hưởng dù Suricata phát hiện.

`full_stack` (120s): Reset XDP rules, khởi động watcher.py, chạy lại Slow Loris. Feedback loop hoạt động đầy đủ.

### Suricata

Chưa cài trên máy — `setup_rules_1b.sh` sẽ cài từ apt và ghi config tối giản vào `/etc/suricata/suricata.yaml` (backup gốc vào `.orig`). Config chỉ enable: af-packet trên `enp0s3`, EVE JSON output (chỉ alert), HTTP app-layer, và rule file của dự án.

3 rule phát hiện Slow Loris: SID 9000001 (20 SYN trong 10s), SID 9000002 (HTTP partial header, payload <50 bytes, 10 lần trong 30s), SID 9000003 safety net (30 SYN trong 60s). Tất cả prefix `SLOWLORIS` trong msg để `watcher.py` dễ lọc.

### watcher.py

Tail `/var/log/suricata/eve.json`, seek đến cuối khi khởi động để chỉ đọc event mới. Filter `event_type == "alert"` và signature chứa keyword `SLOWLORIS`. Ghi timestamp chính xác từ EVE event để tính latency. Whitelist cứng `10.10.1.50`. Debounce 10 giây.

### Điểm cần chú ý khi chạy thực tế

Nếu phase `no_feedback` kết thúc mà EVE log trống (không có alert nào), cần tăng `SLOWLORIS_SOCKETS` từ 150 lên 300–500 trong `run_experiment_1b.sh`, và/hoặc hạ ngưỡng Rule 1 từ 20 xuống 10 trong `suricata_slowloris.rules`. Công cụ `slowloris` phải được cài sẵn trên Attacker VM (`pip install slowloris`).

### Metrics quan trọng

`nginx_conn_established` tăng cao ở phase `no_feedback`, giảm ở `full_stack` sau khi XDP block. `xdp_rules_count` phải tăng lên ≥1 trong `full_stack`. `legitimate_user_ok` phải về 0 cuối phase `no_feedback` và phục hồi về 1 ở `full_stack`.

---

## 8. Chi tiết kịch bản 2 — GeoIP (CODE XONG)

### Mục tiêu

Chứng minh BPF Map LPM Trie lookup là O(1) theo số entries trong khi Iptables/ipset có overhead tăng theo kích thước ruleset. So sánh latency p50/p95/p99 của nginx từ legitimate user khi ruleset tăng từ 100 → 500 → 1.000 → 5.000 → 10.000 CIDR.

### Cách chạy

```bash
# Đặt hai file CSV từ MaxMind vào thư mục 2/ trước
sudo bash setup_rules_2.sh

sudo bash run_experiment_2.sh \
    --blocks    GeoLite2-Country-Blocks-IPv4.csv \
    --locations GeoLite2-Country-Locations-en.csv

sudo bash teardown_rules_2.sh
```

### Nguồn dữ liệu

MaxMind GeoLite2 — đăng ký miễn phí tại https://www.maxmind.com/en/geolite2/signup, tải `GeoLite2 Country (CSV format)`, giải nén lấy hai file: `GeoLite2-Country-Blocks-IPv4.csv` và `GeoLite2-Country-Locations-en.csv`. Dùng quốc gia CN (Trung Quốc) vì có ~8.000–10.000 CIDR, vừa khít giới hạn `max_entries = 10.000` của BPF Map hiện tại.

**Nếu cần vượt 10.000 entries:** Sửa `__uint(max_entries, 10000)` trong `xdp-filter.c` thành `50000` rồi `go generate` để recompile.

### Thiết kế attacker trong kịch bản 2

Attacker VM dùng SNAT để giả mạo source IP thành `1.180.1.1` (dải China Unicom, có trong GeoLite2-CN). Đây là SYN flood một chiều — attacker không cần nhận response vì mục đích chỉ là tạo traffic bị block, không phải thiết lập connection. Firewall tra BPF Map / ipset, thấy source IP nằm trong dải GeoIP → drop ngay. Lệnh setup SNAT trên Attacker VM:

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 1.180.1.1
```

### Thiết kế đo lường

Với mỗi mức ruleset, script chạy Round A (XDP) và Round B (Iptables/ipset). Trong cả hai round, attacker gửi SYN flood song song trong khi `wrk` đo latency từ `ns_50`. Dùng `ip netns exec ns_50 wrk` để đảm bảo source IP của wrk là `10.10.1.50`, không bị SNAT ảnh hưởng.

Tham số wrk: 4 threads, 10 connections, 30 giây, output `--latency` để lấy p50/p99. `monitor.py` chạy song song để thu thập CPU, memory cho cả 60 giây đo.

### Output

Hai file CSV trong `2/results/`: `exp_2_detail_*.csv` (raw từng giây như monitor.py), và `exp_2_summary_*.csv` (một dòng per round, các cột: `implementation, ruleset_size, latency_p50, latency_p95, latency_p99, req_per_sec, false_positive, cpu_avg`). File summary là file chính để vẽ biểu đồ so sánh.

### false_positive_count

Cột này phải luôn bằng 0 trong mọi round. `load_geoip_xdp.py` và `load_geoip_iptables.sh` đều bỏ qua CIDR bắt đầu bằng `10.` để tránh block nhầm dải lab. `run_experiment_2.sh` tự động kiểm tra và ghi kết quả vào CSV.

---

## 9. monitor.py (dùng chung)

Script thu thập metrics mỗi 1 giây, ghi CSV. Chạy trên Firewall VM với quyền root. Chỉ dùng stdlib Python, không cần cài thêm thư viện.

Các cột CSV: `timestamp, phase, cpu_percent, mem_mb, nginx_latency_ms, nginx_http_status, legitimate_user_ok, nginx_conn_established, nginx_conn_close_wait, xdp_cpu_percent, xdp_mem_mb, xdp_attached, xdp_rules_count, iptables_drops_total, iface_rx_packets, iface_rx_drop`.

Cách dùng: `sudo python3 monitor.py --phase <tên_phase> --output results/exp.csv [--append]`. `LATENCY_THRESHOLD_MS = 500` cho VirtualBox, giảm xuống 100–200 nếu chạy bare metal.

---

## 10. Quyết định thiết kế đã chốt (không thay đổi)

Suricata chạy passive (IDS), ủy quyền block cho XDP. Python Watcher được chọn thay vì Lua script vì dễ debug. Mọi kịch bản đo `legitimate_user_ok` song song với firewall metrics — đây là điều kiện thành công bắt buộc. Tham số tấn công có hai mức: nhẹ cho VirtualBox, mạnh hơn cho bare metal, với comment rõ ràng trong mỗi script. Lỗi thiết kế port=0 trong XDP Core được giữ nguyên tạm thời, sẽ sửa source code sau khi thực nghiệm hoàn thành.

---

## 11. Môi trường

Hiện tại: VirtualBox Ubuntu trên Firewall VM và Victim VM. Victim VM đã cài nginx bằng `victim.sh` với `worker_connections 4096` và `keepalive_timeout 0`. Sau khi kịch bản chạy ổn sẽ báo với giảng viên xin máy vật lý để benchmark chính thức.