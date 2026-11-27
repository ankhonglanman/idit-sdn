# Báo cáo Đánh giá Thực nghiệm IDIT-SDN (Benign vs FDFF Attack & IDS Cost)

## 1. Hiệu năng mạng: PDR, End-to-End Delay & Control Overhead (2000s mô phỏng)

| Kịch bản | Benign TX | Benign RX | PDR (%) | Delay TB (ms) | Delay Trung vị (ms) | Delay P95 (ms) | Control Orig (SDN / IDS) | Radio Control TX Tổng | Năng lượng Node 2..9 (mJ) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Benign (IDS OFF) | 77 | 69 | 89.61% | 12942.29 | 2143.52 | 119394.95 | 241 (241 / 0) | 241 | 9220 (TB 1152.5) |
| Benign (IDS ON) | 77 | 63 | 81.82% | 3921.65 | 3144.14 | 11645.49 | 771 (227 / 544) | 771 | 19919 (TB 2489.9) |
| FDFF Attack (IDS ON) | 79 | 64 | 81.01% | 3693.35 | 2662.59 | 7608.90 | 1131 (645 / 486) | 1131 | 23933 (TB 2991.6) |

### Phân tách trước và trong khi tấn công FDFF (`t_attack = 1235.48s`)

| Giai đoạn | Benign TX | Benign RX | PDR (%) | Delay TB (ms) | Delay P95 (ms) | Gói tấn công giả |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Trước tấn công (`t < 1235.5s`) | 37 | 30 | 81.08% | 4193.35 | 11960.09 | 0 |
| Trong tấn công (`t >= 1235.5s`) | 42 | 29 | 69.05% | 3182.79 | 5011.02 | 156 |

## 2. Detection Rate (TPR), False Positive Rate (FPR) & Detection Delay

| Tầng phát hiện | Benign (IDS ON) — False Positive | FDFF Attack (IDS ON) — Detection Rate / Kết quả |
| :--- | :--- | :--- |
| **Tập trung (Controller Change-Point)** | 0/39 cửa sổ (**FPR = 0.00%**) | **35/38 cửa sổ sau tấn công (92.11%)**, phát hiện lần đầu tại Sample 65 (độ trễ ~64.52s), đỉnh `DT = 8.71` vs `ca = 2.79` |
| **Phân tán (Node cục bộ + Suspect)** | 0/7 node CP alarm (**FPR = 0.00%**) | 4/4 láng giềng `[2, 4, 6, 8]` ghi nhận suspect `[ 05 00 ]`; 2/4 láng giềng `[2, 6]` vượt ngưỡng CP & gửi alarm; node ngoài vùng FP: `[7]`; Controller suspects: `['First suspect: [ 05 00 ]', 'New alarm: [ 05 00 ], Alarms: 2']` |

## 3. Phân tích Chi phí của IDS (IDS ON vs IDS OFF trên Benign Traffic)

### A. Chi phí bộ nhớ Firmware (Z1 MSP430: ROM = `text+data`, RAM = `data+bss`)

| Firmware | IDS OFF ROM (B) | IDS ON ROM (B) | Tăng ROM | IDS OFF RAM (B) | IDS ON RAM (B) | Tăng RAM |
| :--- | ---: | ---: | :--- | ---: | ---: | :--- |
| `enabled-node.z1` | 41767 | 48435 | +6668.00 (+15.96%) | 6642 | 6992 | +350.00 (+5.27%) |
| `sink-node.z1` | 41405 | 42887 | +1482.00 (+3.58%) | 6602 | 6930 | +328.00 (+4.97%) |
| `controller-node.z1` | 33165 | 33535 | +370.00 (+1.12%) | 6560 | 6816 | +256.00 (+3.90%) |

### B. Chi phí vận hành (Runtime Cost trên mạng 9 node trong 2000s)

| Chỉ số | Benign IDS OFF | Benign IDS ON | Chênh lệch (Chi phí IDS) |
| :--- | ---: | ---: | :--- |
| Control packets khởi phát | 241 | 771 | +530.00 (+219.92%) |
| Tổng radio TX điều khiển (gồm chuyển tiếp) | 241 | 771 | +530.00 (+219.92%) |
| Năng lượng tiêu thụ Node 2..9 (mJ) | 9220 | 19919 | +10699.00 (+116.04%) |
| PDR dữ liệu (%) | 89.61% | 81.82% | -7.79 pp |
| End-to-End Delay trung bình (ms) | 12942.29 | 3921.65 | -9020.64 (-69.70%) |
