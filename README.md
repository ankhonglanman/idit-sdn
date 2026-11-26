# IDIT-SDN — Hướng dẫn & Tổng hợp Lệnh Vận hành

**IDIT-SDN** (*Intrusion Detection Framework for Software Defined Wireless Sensor Networks*) là framework phát hiện xâm nhập cho mạng cảm biến không dây định nghĩa bằng phần mềm (SDWSN), xây dựng trên **IT-SDN v0.41** và **Contiki OS 3.0**.

- **Mặt phẳng dữ liệu (WSN Motes)**: Node cảm biến chạy Contiki 3.0 trên phần cứng giả lập MSP430 (**Z1** / **Sky**), thực hiện thu thập dữ liệu, chuyển tiếp theo bảng luồng và phát hiện bất thường phân tán (Change-Point cục bộ).
- **Mặt phẳng điều khiển (`controller-pc`)**: Ứng dụng C/C++ viết trên **Qt 5** kết nối với `controller-node` qua TCP/Serial (mặc định `127.0.0.1:60001`), tính toán định tuyến Dijkstra trên đồ thị `digraph`, thu thập chỉ số mạng (`Control overhead`, `Data PDR`) và phát hiện tấn công tập trung (**FDFF**, **FNI**).

---

## Cấu trúc thư mục chính

| Đường dẫn | Vai trò |
| :--- | :--- |
| `applications/` | Mã nguồn ứng dụng Contiki (`enabled-node.c`, `sink-node.c`, `controller-node.c`, `management-sink.c`, `attack-fdff.c`, `attack-two.c`, `attack-three.c`), Makefile và script `compile.sh`. |
| `applications/attack-demo/` | Cấu hình build riêng cho kịch bản demo tấn công FDFF 9 node (chu kỳ 10s, không làm thay đổi firmware chuẩn). |
| `contiki-sdn/` | Tầng mạng SDN trên Contiki (`sdn-core.c`, `sdn-serial.c`, neighbor/controller discovery). |
| `sdn-common/` | Thành phần dùng chung giữa mote & controller (`sdn-process-packets.c`, `sdn-node-security-module.c`, bảng luồng, hàng đợi). |
| `controller-server/` | Mã nguồn controller (`controller-core.c`, `sdn-security-module.c`, `sdn-metrics-cal.c`), thư viện `digraph/` và giao diện Qt `controller-pc/`. |
| `simulation/` | Kịch bản Cooja (`.csc`), script chạy mô phỏng (`run_simulations.sh`, `run_attack_demo.sh`, `path_simulation.sh`) và kết quả `results/`. |
| `Dockerfile`, `docker-compose.yml` | Môi trường container **Ubuntu 20.04** tích hợp sẵn OpenJDK 8, Ant, `mspgcc 4.7.2`, Qt 5.12.8, Contiki 3.0, MSPSim và Cooja. |
| `IDIT_SDN__Installation_Guide.pdf` | Tài liệu hướng dẫn cài đặt gốc của tác giả. |

---

## 1. Quản lý môi trường Docker (Ubuntu 20.04 + WSLg)

Toàn bộ toolchain biên dịch và mô phỏng (`msp430-gcc 4.7.2`, Java 8, Ant, Cooja, Qt 5.12.8) nằm sẵn trong container `idit-sdn`.

```bash
# Build image và khởi chạy container chạy nền
docker compose up -d --build

# Kiểm tra trạng thái container
docker ps

# Mở shell tương tác bên trong container (thư mục làm việc: /root/idit-sdn)
docker exec -it idit-sdn bash

# Dừng / bật lại / gỡ bỏ container
docker compose stop
docker compose start
docker compose down
```

Kiểm tra nhanh các công cụ và toolchain bên trong container:

```bash
docker exec idit-sdn bash -lc "java -version && ant -version && msp430-gcc --version && qmake --version && ls -lh /root/contiki-3.0/tools/cooja/dist/cooja.jar /root/contiki-3.01/tools/cooja/dist/cooja.jar"
```

---

## 2. Biên dịch Firmware cho các node cảm biến (`applications/`)

> **Lưu ý**: Lệnh `make TARGET=z1 clean` của Contiki xóa toàn bộ `*.z1` trong thư mục hiện tại. Script `applications/compile.sh` đã được sửa để build toàn bộ nhóm `Makefile_enabled_node` trước khi dọn file trung gian và build `controller-node.z1`.

```bash
# Biên dịch toàn bộ 5 firmware Z1 chuẩn (sink-node, management-sink, attack-fdff, enabled-node, controller-node)
docker exec -w /root/idit-sdn/applications idit-sdn ./compile.sh z1

# Xem dung lượng ROM/RAM (text/data/bss) của các firmware đã build
docker exec -w /root/idit-sdn/applications idit-sdn size *.z1
```

Biên dịch thủ công từng nhóm / từng firmware cụ thể:

```bash
# Build các node mạng và tấn công từ Makefile_enabled_node
docker exec -w /root/idit-sdn/applications idit-sdn bash -lc "make TARGET=z1 clean -f Makefile_enabled_node && make TARGET=z1 -f Makefile_enabled_node enabled-node sink-node management-sink attack-fdff attack-two"

# Build node tấn công sửa đổi gói tin (attack-three) từ Makefile_intrusion_node
docker exec -w /root/idit-sdn/applications idit-sdn bash -lc "make TARGET=z1 clean -f Makefile_intrusion_node && make TARGET=z1 -f Makefile_intrusion_node attack-three"

# Build node giao tiếp controller (controller-node.z1)
docker exec -w /root/idit-sdn/applications idit-sdn bash -lc "make TARGET=z1 -f Makefile_controller_node"
```

---

## 3. Biên dịch `controller-pc` (Qt 5)

```bash
# Biên dịch controller chuẩn (chu kỳ 60s, thư mục mà run_simulations.sh sử dụng)
docker exec -w /root/idit-sdn/controller-server idit-sdn bash -lc "mkdir -p build-controller-pc && cd build-controller-pc && qmake ../controller-pc/controller-pc.pro && make -j4"

# Biên dịch controller cho kịch bản demo tấn công FDFF (chu kỳ 10s, S_SKIP=38, M_WIN=60)
docker exec -w /root/idit-sdn/controller-server idit-sdn bash -lc "mkdir -p build-controller-pc-attack-demo && cd build-controller-pc-attack-demo && qmake ../controller-pc/controller-pc-attack-demo.pro && make -j4"
```

---

## 4. Chạy mô phỏng Cooja & Controller

### A. Bộ kịch bản Đánh giá đầy đủ (Benign IDS OFF vs Benign IDS ON vs FDFF Attack IDS ON)
Tự động build hai biến thể firmware/controller (**IDS OFF** và **IDS ON** kèm `-DSDN_METRIC` và `ENERGY_MANAGER`), chạy cả 3 kịch bản trên cùng topo lưới 3×3 (cổng `60010`, `2000s` mô phỏng mỗi lượt), rồi tính **PDR, End-to-End Delay, Control Overhead, Detection Rate, False Positive Rate và Chi phí IDS (ROM/RAM/Energy/Overhead)**:

```bash
# Chạy toàn bộ 3 kịch bản và sinh báo cáo simulation/results/evaluation_report.md
docker exec -it -w /root/idit-sdn/simulation idit-sdn ./run_evaluation_suite.sh

# Chỉ phân tích lại log có sẵn bằng script Python
docker exec -w /root/idit-sdn/simulation idit-sdn python3 evaluate_ids.py
```

### B. Kịch bản Demo Tấn công FDFF đơn lẻ (9 node lưới 3×3, cổng `60010`)
Tự động build firmware trong `applications/attack-demo/`, build `controller-pc-attack-demo`, chạy Cooja headless `2000s` mô phỏng (~2,4 phút thực tế) với Node 5 tấn công FDFF từ `t ≈ 1235s`, và in báo cáo tóm tắt:

```bash
docker exec -it -w /root/idit-sdn/simulation idit-sdn ./run_attack_demo.sh
```

### C. Mô phỏng Headless quy mô 36 node (`run_simulations.sh`, cổng `60001+`)
Cấu hình các biến `MIN_ITER`, `MAX_ITER`, `COOJA_INSTANCES`, `nodes_v`, `topologies`, `SIM_TIME_MS` trong `simulation/run_simulations.sh` và đường dẫn trong `simulation/path_simulation.sh`, sau đó chạy:

```bash
docker exec -it -w /root/idit-sdn/simulation idit-sdn ./run_simulations.sh
```

### D. Chạy giao diện đồ họa (Cooja GUI + `controller-pc` qua WSLg/X11)

```bash
# Terminal 1: Mở giao diện Cooja GUI (File -> Open simulation -> chọn file .csc trong simulation/)
docker exec -it -w /root/contiki-3.0/tools/cooja idit-sdn ant run

# Terminal 2: Mở giao diện controller-pc (mặc định cổng 60001; truyền SDN_CONTROLLER_PORT nếu dùng cổng khác)
docker exec -it idit-sdn /root/idit-sdn/controller-server/build-controller-pc/controller-pc

# Hoặc chạy controller-pc ở chế độ offscreen (không cần X11) kết nối cổng 60010 cho 9 node
docker exec -it idit-sdn env QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_PORT=60010 /root/idit-sdn/controller-server/build-controller-pc-attack-demo/controller-pc 9
```

---

## 5. Theo dõi, lọc Log & Quản lý tiến trình mô phỏng

Các file log được lưu trong `simulation/results/`:
- Mô phỏng 36 node (`run_simulations.sh`): `ITSDN_log_n36_top_*.txt` (Cooja), `ITSDN_n36_top_*.txt` (serial 36 motes), `controller_ITSDN_n36_top_*.txt` (controller).
- Demo tấn công FDFF (`run_attack_demo.sh`): `attack_demo_cooja.txt`, `attack_demo_motes.txt`, `attack_demo_controller.txt`.

```bash
# Theo dõi log controller theo thời gian thực
tail -f simulation/results/controller_ITSDN_n36_top_a1_1_i1_z1.txt
tail -f simulation/results/attack_demo_controller.txt

# Lọc chỉ số Control Overhead, Data PDR và kết quả phát hiện Change-Point / IDS từ log controller
grep -E 'Control overhead =|Total overhead =|delivery rate =|Starting CP|DT:|CP detected|CP not detected|attack detected|First suspect|New suspect|New alarm|Attacker indentified|Blocklist|Banned:' simulation/results/attack_demo_controller.txt

# Lọc lưu lượng tấn công và cảnh báo phân tán từ log mote
grep -E 'Sending data to false flow:|Adding suspect:|CP detected in|Sending CP detection alarm' simulation/results/attack_demo_motes.txt

# Lọc trạng thái thiết lập tuyến và đồ thị trên controller
grep -E 'Flow ID Table|Route was found|Route not found|Graph complete' simulation/results/controller_ITSDN_n36_top_a1_1_i1_z1.txt
```

Kiểm tra hoặc dừng các tiến trình mô phỏng đang chạy ngầm trong container:

```bash
# Xem các tiến trình đang chạy trong container
docker exec idit-sdn ps -ef

# Dừng tiến trình mô phỏng Cooja và controller-pc
docker exec idit-sdn bash -lc "pkill -x java || true; pkill -x controller-pc || true"
```

---

## 6. Kiểm thử module `digraph` & Tài liệu mã nguồn

```bash
# Biên dịch và chạy chương trình kiểm thử đồ thị & Dijkstra trên host/container
docker exec -w /root/idit-sdn/controller-server/digraph idit-sdn bash -lc "make digraph-test && ./digraph-test"
```

*(Lưu ý: script `controller-server/digraph/run_test.sh` có sẵn trong repo gọi thêm `valgrind ./digraph-test`, yêu cầu cài đặt `valgrind` nếu muốn chạy trực tiếp script đó.)*

Sinh tài liệu mã nguồn bằng Doxygen (nếu máy có cài `doxygen`):

```bash
doxygen Doxyfile
```

---

## 7. Lưu ý kỹ thuật quan trọng

1. **Tốc độ đồng hồ Z1 trong Cooja (`1s Contiki = 2.0s mô phỏng Cooja`)**: Khi chạy mô phỏng Z1 trên MSPSim/Cooja, các timer dùng `CLOCK_SECOND` (128 ticks) trôi chậm gấp đôi thời gian mô phỏng Cooja (`SEC_TIMER = 10` phát xung mỗi `20.0s` Cooja). Cần nhân hệ số `2×` khi thiết lập `TIMEOUT(...)` trong file `.csc` so với tổng thời gian `ATTACK_TRIGGER` và cửa sổ `M_WIN`.
2. **Nền tảng `sky` vs `z1`**: Trong `contiki-sdn/sdn-serial.c`, phần khởi tạo serial hiện bật `uart0_init` / `uart0_set_input` cho **Z1** và comment `uart1_init` / `uart1_set_input` (dùng cho **Sky/Wismote**). Do đó `controller-node` mặc định chỉ link thành công cho `TARGET=z1`.
3. **File mô phỏng `.csc` trong `run_simulations.sh`**: Phải dùng đường dẫn tuyệt đối của `applications/` và tên firmware thực tế (`attack-fdff.z1`); không gọi `make TARGET=z1 clean` xen kẽ giữa các lần build firmware.
