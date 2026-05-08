# instruction.md — Phiên làm việc v2
> Tóm tắt tiến độ đồ án: Hệ thống tường lửa kết hợp thông minh XDP/eBPF  
> Mục đích file này: Làm context đầy đủ cho phiên làm việc tiếp theo.  
> Cập nhật lần: v2 — sau khi hoàn thành thiết kế kịch bản + toàn bộ code kịch bản 1a.  
> Phiên tiếp theo bắt đầu từ: Kịch bản 1b (Slow Loris)

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

**Feedback loop** là cơ chế cốt lõi kết nối các tầng: khi Iptables hoặc Suricata xác định được IP xấu, chúng đẩy IP đó xuống XDP qua REST API. Từ đó XDP block ngay tại driver, giải phóng tài nguyên cho tầng trên tập trung vào IP chưa được phân loại hoặc xử lí các logic khác. Lưu ý quan trọng về overhead: REST API chỉ là control plane, chỉ gọi một lần duy nhất per IP. Sau khi rule được ghi vào BPF Map thì XDP lookup hoàn toàn trong kernel, không qua API nữa — overhead HTTP call là không đáng kể.

---

## 3. XDP Core API (kế thừa, port 8080)

Các endpoint cần dùng: `POST /rules` để thêm luật block, `DELETE /rules` để xóa, `GET /rules` để lấy danh sách, `GET /health` để lấy CPU%, Memory_MB, xdp_attached.

Payload cho POST/DELETE: `{"subnet": "IP/CIDR", "proto": <số>, "port": <số>, "action": "DROP"}`. Proto dùng số hiệu: TCP=6, UDP=17, ICMP=1.

Cấu trúc BPF Maps trong kernel: `subnet_map` dùng `BPF_MAP_TYPE_LPM_TRIE` (tối đa 10.000 entries, tra cứu CIDR/Subnet cực nhanh, phù hợp GeoIP), `rule_map` dùng `BPF_MAP_TYPE_HASH` (tối đa 65.536 entries, map subnet_id với protocol/port).

**Lưu ý quan trọng cho kịch bản GeoIP:** Nếu cần nạp hơn 10.000 CIDR entries, phải sửa `__uint(max_entries, 10000)` trong file `xdp-filter.c` rồi recompile bằng `go generate`.

### Lỗi thiết kế quan trọng của mã nguồn kế thừa — BẮT BUỘC ĐỌC KỸ

Đây là điểm dễ gây bug nhất trong toàn bộ hệ thống. `rule_map` trong `xdp-filter.c` dùng `BPF_MAP_TYPE_HASH` với key là struct `{subnet_id, proto, port}`. Vì là Hash Map, XDP yêu cầu **exact match 100%** — không có wildcard.

Hệ quả cụ thể: khi packet TCP/UDP đến, XDP extract destination port thực tế từ header (ví dụ port 80) rồi tìm trong Map với key `{subnet_id, 6, 80}`. Nếu bạn đã nạp rule với `port=0` thì key trong Map là `{subnet_id, 6, 0}` — lookup thất bại vì `80 ≠ 0`, packet lọt qua.

Do đó, **port=0 không phải wildcard cho TCP/UDP**. Để block một IP trên TCP port 80, bạn phải gọi API với `port=80`. Nếu muốn block nhiều port, phải gọi API nhiều lần cho mỗi port. Danh sách port cần block trong kịch bản lab hiện tại là `[80]` cho TCP, có thể mở rộng thêm 443 nếu cần.

Ngoại lệ duy nhất là **ICMP (proto=1)**: vì ICMP không có port, tác giả hardcode `port=0` trong hàm `handle_icmp`. Với ICMP, bạn **bắt buộc** phải truyền `port=0` qua API — đây là trường hợp port=0 đúng và bắt buộc.

Lỗi thiết kế này được ghi nhận nhưng **tạm thời giữ nguyên** theo mã nguồn kế thừa. Sẽ sửa source code sau khi toàn bộ thực nghiệm hoàn thành.

---

## 4. Topology Lab

```
[Attacker VM]                    [Firewall VM]                         [Victim VM]
 eth0: 10.10.1.2                  enp0s3: 10.10.1.1 (XDP attach)        eth0: 10.10.2.2
 ns_10: 10.10.1.10                enp0s8: 10.10.2.1                     nginx: port 80
 ns_11: 10.10.1.11                XDP Core API: 127.0.0.1:8080          response: "this is benchmark"
 ns_50: 10.10.1.50 (legitimate)   Suricata (passive, cả 2 interface)
                                  Iptables/Nftables
                                  Python Watcher / Feedback scripts
                                  ip_forward = 1
```
ns: network namespace

Tên interface thực tế là `enp0s3` và `enp0s8` — không phải `eth0` như trong topology trừu tượng. Tất cả script đều có biến `IFACE` ở đầu file để chỉnh một chỗ duy nhất.

XDP attach vào **enp0s3 của Firewall VM** — interface nhận traffic từ Attacker. Đây là điểm drop sớm nhất trong toàn bộ hệ thống.

**ns_50 (10.10.1.50) là legitimate user probe** — không bao giờ bị block trong bất kỳ kịch bản nào. Nếu ns_50 không nhận được HTTP 200 từ nginx thì kịch bản coi như thất bại bất kể metric firewall tốt đến đâu. Đây là điều kiện thành công bắt buộc được ghi vào cột `legitimate_user_ok` trong mọi CSV.

ns_10 và ns_11 dự phòng cho attacker khi IP chính bị block.

Môi trường hiện tại: VirtualBox Ubuntu. Sau khi kịch bản chạy ổn sẽ báo với giảng viên xin các máy vật lý với cấu hình mạnh hơn và benchmark chuẩn hơn.

---

## 5. Suricata — Thiết kế tích hợp

Suricata chạy **passive mode (IDS)**, không chặn trực tiếp. Lý do: Suricata dùng multi-pattern matching engine (Hyperscan/Aho-Corasick), overhead cao hơn XDP nhiều bậc độ lớn. Thiết kế là Suricata phát hiện → ghi EVE JSON log → Python Watcher đọc log → gọi XDP API để block. Suricata ủy quyền cho XDP, không tự chặn.

Python Watcher được chọn thay vì Lua script vì dễ debug và tích hợp tự nhiên với monitoring pipeline đã có. Watcher đọc `/var/log/suricata/eve.json` theo dạng tail realtime, extract `src_ip` từ alert, gọi `POST /rules`.

Suricata sẽ log thông báo dạng: "Đã phát hiện IP X tấn công [tên tấn công]. Đã đẩy IP X xuống XDP để block. Không chặn tại IDPS."

---

## 6. Cấu trúc thư mục dự án

```
benchmark_hybrid_firewall/
├── benchmark_instruction.md        ← Tài liệu về dự án
├── monitor.py                      ← DÙNG CHUNG cho cả 3 kịch bản (đã viết xong)
├── 1a/                             ← Kịch bản 1a (ĐÃ HOÀN THÀNH)
│   ├── setup_rules_1a.sh           ← chạy 1 lần trước thực nghiệm
│   ├── feedback_loop_iptables.py   ← feedback loop chính
│   ├── run_experiment_1a.sh        ← orchestrate toàn bộ 3 phase
│   └── teardown_rules_1a.sh        ← dọn dẹp sau thực nghiệm
├── 1b/                             ← Kịch bản 1b (CHƯA LÀM — bắt đầu phiên tiếp theo)
│   ├── suricata_slowloris.rules    (cần viết)
│   ├── watcher.py                  (cần viết)
│   ├── setup_rules_1b.sh           (cần viết)
│   ├── run_experiment_1b.sh        (cần viết)
│   └── teardown_rules_1b.sh        (cần viết)
└── 2/                              ← Kịch bản GeoIP (CHƯA LÀM)
    ├── load_geoip_xdp.py           (cần viết)
    ├── load_geoip_iptables.sh      (cần viết)
    ├── setup_rules_2.sh            (cần viết)
    ├── run_experiment_2.sh         (cần viết)
    └── teardown_rules_2.sh         (cần viết)
```

---

## 7. Chi tiết các file đã viết

### monitor.py (dùng chung)

Script thu thập metrics mỗi 1 giây, ghi CSV. Chạy trên Firewall VM với quyền root. Các cột CSV gồm: `timestamp, phase, cpu_percent, mem_mb, nginx_latency_ms, nginx_http_status, legitimate_user_ok, nginx_conn_established, nginx_conn_close_wait, xdp_cpu_percent, xdp_mem_mb, xdp_attached, xdp_rules_count, iptables_drops_total, iface_rx_packets, iface_rx_drop`.

Cách dùng: `sudo python3 monitor.py --phase <tên_phase> --output results/exp.csv [--append]`. Không cần cài thêm thư viện ngoài — chỉ dùng stdlib Python. Biến `LATENCY_THRESHOLD_MS = 500` cho VirtualBox, giảm xuống 100-200 nếu chạy bare metal.

### feedback_loop_iptables.py (kịch bản 1a)

Đọc kernel log realtime (file hoặc journald), tìm dòng có prefix `XDP_CANDIDATE: ` do Iptables LOG target ghi ra, parse src_ip, gọi XDP API. Có debounce 5 giây để tránh gọi API nhiều lần cho cùng một IP. Sau mỗi lần push rule, gọi `GET /rules` để verify rule đã vào BPF Map. Ghi evidence log ra `feedback_loop_1a.log`.

Lưu ý port: do lỗi thiết kế exact-match, script gọi API **riêng cho từng port** trong danh sách `PORTS_TO_BLOCK = [80]`. Với ICMP gọi riêng với `port=0`. Để block thêm port khác thì thêm vào list `PORTS_TO_BLOCK`.

Cách dùng: `sudo python3 feedback_loop_iptables.py --use-journald` (hoặc `--log-file /var/log/kern.log`).

### setup_rules_1a.sh (kịch bản 1a)

Tạo Iptables chain `SYN_FLOOD_DETECT` với `hashlimit` để phát hiện SYN Flood. Ngưỡng mặc định `100/s` burst `200` cho VirtualBox — tăng lên `500/s` hoặc `1000/s` nếu chạy bare metal. Whitelist cứng ns_50 (10.10.1.50) để đảm bảo legitimate user không bao giờ bị chặn. LOG với prefix `XDP_CANDIDATE: ` để feedback_loop đọc được.

### run_experiment_1a.sh (kịch bản 1a)

Orchestrate 3 phase tự động: baseline (60s) → cooldown (10s) → iptables_only (60s) → cooldown (10s) → feedback_loop (60s). Trigger tấn công qua SSH đến Attacker VM bằng `hping3 -S -p 80 --flood 10.10.2.2`. Nếu SSH không được setup, tự động chuyển sang manual mode. In summary table sau khi hoàn tất. Thời gian phase có thể override bằng `--duration=120`.

---

## 8. Chi tiết Kịch bản 1b — Slow Loris (cần làm tiếp)

### Mục tiêu

Chứng minh hai điều đồng thời: giới hạn của XDP đơn thuần (không thể phát hiện Slow Loris vì mỗi packet hợp lệ về network), và giá trị của Suricata trong kiến trúc đa tầng (phát hiện L7 pattern rồi feedback về XDP).

### Công cụ tấn công

Dùng `slowloris` (Python tool). Trên VirtualBox: `--socket-count 100 --sleeptime 10`. Nếu bare metal: tăng lên 300-500 connections.

**Quan trọng**: nginx phải giữ `keepalive_timeout 65` và `client_header_timeout 60` ở mặc định — không được set ngắn hơn vì nginx sẽ tự mitigate và kịch bản mất ý nghĩa.

### Hai phase thực nghiệm

Phase 1 là XDP-only: bật Slow Loris, quan sát `nginx_conn_established` tăng dần, `nginx_latency_ms` tăng, cuối cùng ns_50 bắt đầu nhận lỗi. Đây là bằng chứng XDP không giải quyết được Slow Loris — `legitimate_user_ok` chuyển về 0.

Phase 2 là Full stack: reset nginx, bật lại Slow Loris. Suricata phát hiện pattern → EVE log → Python Watcher → XDP API. Đo thời gian từ packet đầu tiên đến khi XDP rule có hiệu lực — đây là **detection + response latency**, chỉ số quan trọng nhất của kịch bản này.

### Suricata rule (cần viết)

Rule dựa trên `threshold` và `detection_filter`: nhiều TCP connection đến port 80 từ cùng một IP trong khoảng thời gian ngắn, nhưng không có HTTP request hoàn chỉnh (header không kết thúc bằng `\r\n\r\n`). Bạn có kinh nghiệm viết Sagan rules nên phần này sẽ quen thuộc về cú pháp.

### Metrics CSV cho kịch bản 1b

Các cột giống monitor.py chuẩn, chú ý đặc biệt đến `nginx_conn_established`, `nginx_conn_close_wait` (dấu hiệu đặc trưng của Slow Loris), và `xdp_rules_count` (tăng lên 1+ khi feedback loop kích hoạt).

### watcher.py (cần viết)

Tương tự `feedback_loop_iptables.py` nhưng đọc Suricata EVE JSON thay vì kernel log. Đọc `/var/log/suricata/eve.json` theo dạng tail. Filter `event_type == "alert"` và `alert.signature` chứa tên rule Slow Loris. Extract `src_ip`, gọi XDP API. Ghi timestamp chính xác để tính detection latency. Nhớ áp dụng cùng logic port: gọi API cho `port=80` (TCP) và `port=0` (ICMP) riêng biệt — không dùng port=0 như wildcard.

---

## 9. Chi tiết Kịch bản 2 — GeoIP (cần làm tiếp)

### Mục tiêu

Chứng minh BPF Map LPM Trie lookup là O(1) theo số entries, trong khi Iptables/ipset có overhead tăng theo kích thước ruleset.

### Nguồn dữ liệu

MaxMind GeoLite2 (miễn phí, cần đăng ký). File `GeoLite2-Country-CSV.zip`. Gợi ý chọn CN (~8.000-10.000 IPv4 CIDR) vì vừa khít giới hạn `max_entries = 10.000` hiện tại.

Nếu cần test vượt 10.000 entries: sửa `__uint(max_entries, 10000)` trong `xdp-filter.c` thành `50000` rồi chạy `go generate` để recompile.

### Năm mức ruleset

100, 500, 1.000, 5.000, 10.000 entries. Mỗi mức chạy độc lập với cả hai implementation (XDP và Iptables/ipset). Đo latency percentile p50/p95/p99 — quan trọng hơn average vì cho thấy tail latency.

### Iptables setup cho GeoIP

Dùng `ipset create geoip_block hash:net` rồi load CIDR vào set, sau đó `iptables -I FORWARD -m set --match-set geoip_block src -j DROP`. Không tạo từng rule riêng lẻ — sẽ rất chậm.

### false_positive_count

Cột này phải luôn bằng 0 trong mọi lần đo — ns_50 không bao giờ được bị block nhầm.

---

## 10. Thông tin thêm về những trao đổi từ ban đầu về kịch bản nếu cần thêm dữ kiện

**Lưu ý:** Những điều dưới đây là sơ khai, ban đầu, nguyên thủy của kế hoạch lập kịch bản, do đó có thể sai khác một chút với những thông tin bên trên!

### Nhóm 1

#### Kịch bản 1a — Feedback loop: Iptables→ XDP

**Bối cảnh**: Hệ thống đang chịu tấn công kết hợp SYN Flood/UDP Flood/ICMP Flood cường độ lớn. Ban đầu Iptables chịu trách nhiệm lọc, nhưng khi IP xấu đã được xác định, hệ thống tự động đẩy IP đó xuống XDP block ở tầng driver — tức là gói tin bị drop ngay trước khi chạm vào network stack, giải phóng tài nguyên cho Iptables tập trung vào những IP chưa được phân loại.

**Mục tiêu đo lường**: So sánh CPU usage, memory, và latency của nginx khi chặn hoàn toàn bằng Iptables so với khi có feedback loop về XDP. Kỳ vọng là sau khi feedback loop kích hoạt, tải trên Iptables giảm xuống rõ rệt và nginx tiếp tục phục vụ request hợp lệ ổn định hơn.

**Giá trị chứng minh**: Đây là bằng chứng trực tiếp cho luận điểm "kết hợp thông minh hiệu quả hơn từng thành phần riêng lẻ"

#### Kịch bản 1b — Slow Loris**

**Bối cảnh**: Slow Loris là tấn công giữ kết nối HTTP mở mãi bằng cách gửi header chậm rãi, không bao giờ hoàn thành request. Mỗi gói tin nhìn hoàn toàn hợp lệ về mặt network, nên XDP không thể phân biệt được đây là tấn công. Nếu chỉ dùng XDP đơn thuần, Slow Loris sẽ làm cạn kiệt connection pool của nginx mà không bị chặn.

**Cách kiến trúc đa tầng giải quyết**: Suricata nhận diện pattern bất thường của Slow Loris (nhiều kết nối từ một IP, header gửi cực chậm), sau đó đưa IP đó vào BPF Map để XDP block toàn bộ traffic từ IP đó ngay lập tức. Kết quả là nginx được giải phóng connection pool và tiếp tục phục vụ user thật.

**Mục tiêu đo lường**: Đo thời gian từ khi Slow Loris bắt đầu đến khi Suricata phát hiện và XDP block thành công (detection + response latency). Đo connection count của nginx trước và sau khi hệ thống phản ứng. So sánh kịch bản có và không có Suricata.

### Nhóm 2 — GeoIP/Blacklist**: Chặn theo vùng địa lý

**Bối cảnh và lý do thực tiễn**: Trong thực tế, khi một cuộc tấn công DDoS quy mô lớn xảy ra, rất thường thấy toàn bộ traffic tấn công đến từ một dải IP của một quốc gia hoặc khu vực cụ thể (ví dụ botnet tập trung ở một vùng). Chặn theo GeoIP là biện pháp thô nhưng hiệu quả cao trong tình huống này — thay vì phải xử lý từng IP một, hệ thống chặn cả một dải IP lớn bằng một tập luật.

**Điểm so sánh cần kiểm thử**: Cùng một tập GeoIP ruleset (ví dụ chặn một dải /8 hoặc /16 giả lập), triển khai ở hai nơi: một là trong Iptables dùng ipset kết hợp module geoip, hai là load thẳng vào BPF Map để XDP lookup và drop tại driver. Khi tập luật nhỏ (vài trăm entry) thì cả hai có thể tương đương, nhưng khi tập luật lớn lên (hàng chục nghìn CIDR entry của một quốc gia thực), XDP với BPF Map lookup O(1) được kỳ vọng giữ hiệu năng ổn định trong khi Iptables bắt đầu chịu áp lực vì phải duyệt ruleset tuần tự.

**Mục tiêu đo lường**: Throughput và latency của nginx với user hợp lệ (ngoài vùng bị chặn) khi tập luật GeoIP tăng dần kích thước. Đây vừa kiểm thử hiệu năng, vừa kiểm thử tính đúng đắn — đảm bảo user hợp lệ không bị chặn nhầm (false positive).


## 11. Quyết định thiết kế đã chốt (không thay đổi)

Suricata chạy passive (IDS), ủy quyền block cho XDP. 

Python Watcher được chọn thay vì Lua script vì dễ debug. 

Mọi kịch bản đo `legitimate_user_ok` song song với firewall metrics — đây là điều kiện thành công bắt buộc, không phải metric phụ. 

Tham số tấn công có hai mức: nhẹ cho VirtualBox, mạnh hơn cho bare metal, với comment rõ ràng trong mỗi script. 

Lỗi thiết kế port=0 trong XDP Core được giữ nguyên tạm thời, sẽ sửa source code sau khi thực nghiệm hoàn thành.
