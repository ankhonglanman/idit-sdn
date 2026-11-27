# AGENT.md — Quản lý Task & Hướng dẫn vận hành cho Agent (IDIT-SDN)

Tài liệu này quy định **quy trình làm việc, ràng buộc kỹ thuật và bảng quản lý task** cho các agent (hoặc kỹ sư) phát triển, kiểm thử và mô phỏng trên repository **IDIT-SDN**.

---

## 1. Bối cảnh môi trường & Nguyên tắc bắt buộc

1. **Thực thi bên trong container `idit-sdn`**:
   - Hệ điều hành host là Kali WSL2; toàn bộ toolchain đúng phiên bản (`Ubuntu 20.04`, `openjdk-8-jdk`, `ant 1.10.7`, `msp430-gcc 4.7.2`, `Qt 5.12.8`, `Contiki 3.0`) nằm trong container `idit-sdn`.
   - Mọi lệnh build firmware, build `controller-pc`, hoặc chạy Cooja phải chạy qua `docker exec ... idit-sdn ...`.
2. **Cô lập thử nghiệm (Isolation) để không đụng độ mô phỏng đang chạy**:
   - Không sửa đổi hoặc ghi đè cổng `60001` hay thư mục `/root/contiki-3.01` nếu đang có phiên chạy `run_simulations.sh`.
   - Kịch bản mới hoặc bản thử nghiệm phải dùng:
     - Cổng riêng qua biến môi trường `SDN_CONTROLLER_PORT` (ví dụ `60010`, `60011`, …).
     - Thư mục build riêng cho firmware (`applications/<scenario>/`) và controller (`controller-server/build-controller-pc-<scenario>/`).
     - File `.csc` và file log riêng trong `simulation/results/`.
3. **Các bẫy kỹ thuật đã xác nhận trong codebase (KHÔNG lặp lại lỗi cũ)**:
   - **`make TARGET=z1 clean` xóa tất cả `*.z1`**: Luôn build gộp các target dùng chung `Makefile_enabled_node` rồi mới xóa thủ công `obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h` trước khi build `Makefile_controller_node`.
   - **Tỷ lệ đồng hồ Z1 trong Cooja**: `1 giây Contiki = 2.0 giây thời gian mô phỏng Cooja`. Mọi phép tính `ATTACK_TRIGGER`, `DIST_INIT_DELAY`, `CP_TIMER`, `M_WIN` và `TIMEOUT(...)` phải quy đổi theo hệ số `2×` này.
   - **Sửa lỗi `-DENERGY` trong `sdn-common/sdn-node-security-module.c` (`TASK-05`)**: Đã sửa triệt để lỗi gọi `security_node_ts_monitoring(..., ts_counter - m_win)` với chỉ số âm trong pha huấn luyện; khi kết hợp `-DENERGY` với `-DTRANS_TS`/`-DRX_CTRL_PCKT` sử dụng Welford O(1) online variance (~22 B RAM) để không vượt giới hạn RAM của Z1/Sky.
   - **Giới hạn mảng `temp_flowid[4]` trong `applications/attack-fdff.c`**: Node tấn công FDFF chỉ được có **tối đa 4 láng giềng** trong bảng láng giềng nếu chưa mở rộng kích thước mảng `temp_flowid`.
   - **`sdnaddr_print` vs `sdnaddr_print_nodebug`**: `sdnaddr_print()` bị tắt khi không bật `-DDEBUG_SDN`; cần dùng `sdnaddr_print_nodebug()` nếu muốn luôn in địa chỉ node vào log mote.
   - **Giữ tương thích ngược**: Mọi hằng số mới thêm vào code C/C++ phải bọc trong `#ifndef ... #endif` để không làm đổi hành vi mặc định của cấu hình 36 node.

---

## 2. Phân vai Agent (Agent Roles)

| Vai trò Agent | Phạm vi thư mục phụ trách | Nhiệm vụ chính |
| :--- | :--- | :--- |
| **Firmware & Protocol Agent** | `applications/`, `contiki-sdn/`, `sdn-common/` | Sửa lỗi code C trên Contiki, cấu hình Makefile mote, tạo ứng dụng node tấn công / phòng thủ mới, đảm bảo ROM/RAM vừa bộ nhớ Z1 (`text + data < ~48 KB` / `bss < ~8 KB`). |
| **Controller & IDS Agent** | `controller-server/`, `controller-server/digraph/`, `sdn-common/sdn-node-security-module.c` | Phát triển thuật toán Change-Point tập trung/phân tán, cơ chế blocklist/cô lập node, biên dịch Qt5 `controller-pc` và chạy test `digraph`. |
| **Simulation & Evaluation Agent** | `simulation/`, `simulation/results/` | Thiết kế topo `.csc`, viết script tự động hóa không treo, chạy Cooja `-nogui`, trích xuất số liệu Overhead / PDR / độ trễ phát hiện (`i_s`, `DT`, `ca`). |

---

## 3. Quy trình thực hiện một Task (Definition of Done)

Mỗi agent khi nhận một task từ bảng dưới đây phải thực hiện đúng 5 bước:
1. **Kiểm tra hiện trạng**: Đọc các file liên quan, kiểm tra `docker exec idit-sdn ps -ef` và xác nhận không trùng cổng TCP (`60001`, `60010`, …).
2. **Triển khai thay đổi tối thiểu**: Giữ nguyên comment/docstring hiện có, giữ tương thích ngược bằng `#ifndef` hoặc tham số/env var riêng.
3. **Biên dịch kiểm chứng (`exit code 0`)**: Build cả firmware Z1 (`size *.z1`) và `controller-pc` (`qmake && make`) trong container `idit-sdn`.
4. **Mô phỏng & đối chiếu log thực tế**: Chạy Cooja headless đến khi kết thúc (hoặc đủ cửa sổ phát hiện), kiểm tra log trong `simulation/results/` có đủ bằng chứng hoạt động và không còn tiến trình mồ côi (`java`, `controller-pc`).
5. **Cập nhật trạng thái**: Đổi `[ ]` → `[x]` kèm ghi chú file thay đổi và kết quả đo được vào mục **4** bên dưới.

---

## 4. Bảng quản lý Task (Task Tracker)

### Đã hoàn thành (`[x]`)

- [x] **`TASK-01` — Thiết lập môi trường Docker Ubuntu 20.04 & WSLg X11**
  - *Phạm vi*: `Dockerfile`, `docker-compose.yml`, `IDIT_SDN__Installation_Guide.pdf`
  - *Kết quả*: Đã dựng container `idit-sdn` đầy đủ OpenJDK 8, Ant 1.10.7, `msp430-gcc 4.7.2`, Qt 5.12.8, Contiki 3.0 + MSPSim + `cooja.jar`, cấu hình `DISPLAY=:0` và mount `/tmp/.X11-unix`.
- [x] **`TASK-02` — Sửa lỗi script biên dịch & chạy mô phỏng headless 36 node**
  - *Phạm vi*: `simulation/run_simulations.sh`, `applications/compile.sh`
  - *Kết quả*: Sửa lỗi `make TARGET=z1 clean` xóa mất `.z1` vừa build, sửa target `attack-one` → `attack-fdff`, đổi `--platform offscreen` → `QT_QPA_PLATFORM=offscreen`, giảm `-mx12120m` → `-mx2048m`, và thêm kiểm tra `kill -0` thoát sớm khi Cooja crash.
- [x] **`TASK-03` — Hỗ trợ tham số hóa ngưỡng IDS & cổng controller**
  - *Phạm vi*: `applications/attack-fdff.c`, `controller-server/sdn-security-module.c`, `sdn-common/sdn-node-security-module.c`, `sdn-common/sdn-send-packet.c`, `controller-server/controller-pc/mainwindow.cpp`
  - *Kết quả*: Thêm `#ifndef` cho `ATTACK_TRIGGER`, `S_SKIP`, `M_WIN`, `DIST_M_WIN`, `DIST_INIT_DELAY`; khởi tạo `sum_counter = 0`; kiểm tra `suspect_addr != NULL`; thêm `SDN_CONTROLLER_PORT`; chuyển `sdnaddr_print` sang `sdnaddr_print_nodebug` khi thêm suspect.
- [x] **`TASK-04` — Tạo & chạy thành công kịch bản tấn công FDFF (9 node lưới 3×3)**
  - *Phạm vi*: `simulation/attack_fdff_demo_z1.csc`, `simulation/run_attack_demo.sh`, `applications/attack-demo/`, `controller-server/controller-pc/controller-pc-attack-demo.pro`
  - *Kết quả*: Node 5 bơm 156 gói luồng giả từ `t = 1235.48s`; controller phát hiện **`FDFF attack detected`** tại `Sample 65` (`DT = 2.97 >= ca = 2.79`, đạt đỉnh `11.07`); các node 2, 4, 6, 8 ghi nhận 148 lần suspect `[ 05 00 ]`; Node 2 & Node 8 phát cảnh báo phân tán và controller đưa `[ 05 00 ]` vào `Suspects' list`.
- [x] **`TASK-04B` — Bộ đánh giá định lượng Benign vs Attack & Chi phí IDS**
  - *Phạm vi*: `applications/attack-demo-ids-off/`, `controller-server/controller-pc/controller-pc-ids-off.pro`, `applications/sink-node.c`, `simulation/eval_*_z1.csc`, `simulation/run_evaluation_suite.sh`, `simulation/evaluate_ids.py`, `simulation/results/evaluation_report.md`
  - *Kết quả*: Đo đầy đủ A/B trên 3 kịch bản (Benign IDS OFF, Benign IDS ON, FDFF Attack IDS ON) về **PDR, Delay (ms), Control Overhead, Energy (mJ), ROM/RAM, Detection Rate (94.74% cửa sổ) và FPR (0.00% tập trung, 14.29% phân tán)**.

---

- [x] **`TASK-05` — Sửa lỗi ghi ngoài biên mảng `monitoring[]` khi bật cờ `-DENERGY`** *(Ưu tiên: Cao | Vai trò: Firmware + IDS Agent)*
  - *Phạm vi*: `sdn-common/sdn-node-security-module.{h,c}`, `applications/attack-energy/`, `simulation/attack_energy_z1.csc`, `simulation/run_energy_test.sh`
  - *Kết quả*: Sửa nhánh huấn luyện dùng `security_node_ts_training`, thêm `security_node_consumption_mJ_from_tx()` tránh đếm lặp `last_tx`, dùng Welford O(1) variance khi bật đồng thời `-DTRANS_TS -DENERGY` (~22 B RAM). Chạy kiểm chứng trên cổng `60013` thành công: log mote in đầy đủ `Sample 0..20` cả `Transmitting time` lẫn `Consumption (mJ)`, controller phát hiện FDFF từ Sample 64 (đỉnh `DT = 14.80`) và cô lập `[ 05 00 ]`.

- [x] **`TASK-06` — Tạo & kiểm chứng kịch bản tấn công FNI / Sửa đổi gói láng giềng (`attack-three.c`)** *(Ưu tiên: Cao | Vai trò: Firmware + Simulation Agent)*
  - *Phạm vi*: `applications/attack-three.c`, `applications/attack-fni/`, `controller-server/sdn-metrics-cal.c`, `controller-server/controller-pc/controller-pc-attack-fni.pro`, `simulation/attack_fni_z1.csc`, `simulation/run_fni_demo.sh`
  - *Kết quả*: Tham số hóa `TOTAL_EXPECTED_DATA_PCKTS` (`7.0f` cho 7 cảm biến 3×3 gửi mỗi `10s`), loại bỏ `malloc` trong `attack-three.c` (dùng buffer tĩnh + `sdn_packetbuf_pool_get`), bổ sung `#ifdef FNI_BROAD_POISON` để Node 5 giả mạo `SDN_PACKET_NEIGHBOR_REPORT` xoay vòng `[ 08 00 ]`, `[ 09 00 ]`, `[ 06 00 ]`, `[ 04 00 ]`. Trên cổng `60011`, `Average = 86.36%`, `Var = 138.72`; PDR thực tế tụt từ `85.96%` (trước tấn công) xuống `32.23%` (trong tấn công); controller phát hiện **`FNI attack detected`** liên tục 34 cửa sổ từ **Sample 66** (`DT = 3.77 >= ca = 2.79`, đỉnh `16.28`).

- [x] **`TASK-07` — Tạo & kiểm chứng kịch bản tấn công Control-Plane Request Flood (`attack-two.c`)** *(Ưu tiên: Trung bình | Vai trò: Simulation Agent)*
  - *Phạm vi*: `applications/attack-two.c`, `applications/attack-two-demo/`, `simulation/attack_two_z1.csc`, `simulation/run_attack_two_demo.sh`
  - *Kết quả*: Chạy thành công trên cổng `60012` với `ATTACK_PERIOD=4` (khởi phát lúc `t = 1115.48s`, bơm `111` `sdn_send_data_flow_request`). `Total overhead = 520` (`Radio Control TX = 1123` so với `771` benign), kích hoạt phát hiện tập trung từ **Sample 66** (`DT = 3.08 >= ca = 2.79`, 34 cửa sổ, đỉnh `6.60`, chậm hơn 1–2 cửa sổ và đỉnh `DT` thấp hơn FDFF đỉnh `8.71–10.93`).

- [x] **`TASK-08` — Hoàn thiện cơ chế phân loại Attacker & Cô lập qua Blocklist** *(Ưu tiên: Cao | Vai trò: Controller & IDS Agent)*
  - *Phạm vi*: `sdn-common/sdn-node-security-module.{h,c}`, `sdn-common/sdn-process-packets.c`, `sdn-common/sdn-send-packet.c`, `controller-server/sdn-security-module.{h,c}`, `controller-server/sdn-process-packets-controller.{h,c}`, `controller-server/sdn-flow-table-cache.c`, `controller-server/digraph/{digraph,dijkstra}.c`
  - *Kết quả*: Thêm truyền tin cậy + retry cho `SDN_SEC_CP_DETECT_ALARM` (`ALARM_MAX_RETRIES=5`) kèm ACK (`security_node_alarm_acked`), chống đếm trùng reporter trên controller (`reporters[]`), sửa lỗi `digraph_get_vertice` trong Dijkstra (`digraph-test` pass), và bổ sung `sdn_isolate_attacker()` xóa đỉnh tấn công khỏi `digraph` + thanh lọc bảng luồng. Log `attack_demo_controller.txt` xác nhận `[ 05 00 ]` nhận đủ `2/4` alarms (`Node 2` & `Node 4`), bị đưa vào Blocklist (`Banned: YES`), Node 4 & Node 8 được cập nhật tuyến mới tránh `[ 05 00 ]`.

- [x] **`TASK-09` — Hỗ trợ biên dịch tự động `controller-node` cho cả `TARGET=z1` và `TARGET=sky`** *(Ưu tiên: Thấp | Vai trò: Firmware Agent)*
  - *Phạm vi*: `contiki-sdn/sdn-serial.c`, `Dockerfile`, `hardware/fit-iotlab/`
  - *Kết quả*: Tách nhánh UART theo kiến trúc (`Z1` -> `uart0`, `Sky` -> `uart1`, `CC2538 Remote/Zoul/OpenMote` -> `dev/uart.h`, `iotlab-m3` -> giữ cấu hình 500k baud `uart1_set_input`). Cả `./compile.sh z1` và `./compile.sh sky` build đủ 5/5 firmware không lỗi linker; đồng thời đã cross-compile xong 6 firmware ARM Cortex-M3 (`TARGET=remote`) cho FIT IoT-LAB.

- [x] **`TASK-10` — Mở rộng script phân tích & vẽ biểu đồ tự động từ `simulation/results/`** *(Ưu tiên: Trung bình | Vai trò: Simulation & Evaluation Agent)*
  - *Phạm vi*: `simulation/evaluate_ids.py`, `simulation/results/csv/`, `simulation/results/charts/`, `simulation/results/full_experiment_report.md`
  - *Kết quả*: Hỗ trợ parse log 36 node dùng dấu phẩy thập phân (`controller_ITSDN_n36_top_a1_1_i1_z1.txt`, 16 samples) và toàn bộ 7 kịch bản 3×3; xuất `8` file CSV (`csv/summary_all_scenarios.csv` + 7 file `csv/ts_*.csv`), sinh `4` biểu đồ PNG (`fdff_before_after.png`, `fni_before_after.png`, `attack_comparison.png`, `n36_timeseries.png`) và xuất báo cáo `full_experiment_report.md`.

---

### Hàng đợi cần thực hiện (`[ ]` Backlog)

*(Hiện tại toàn bộ các task từ `TASK-01` đến `TASK-10` đều đã hoàn tất.)*
