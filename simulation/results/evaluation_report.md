# Báo cáo Đánh giá Thực nghiệm IDIT-SDN (Benign vs FDFF Attack & IDS Cost)

## 1. Hiệu năng mạng: PDR, End-to-End Delay & Control Overhead (2000s mô phỏng)

| Kịch bản | Benign TX | Benign RX | PDR (%) | Delay TB (ms) | Delay Trung vị (ms) | Delay P95 (ms) | Control Orig (SDN / IDS) | Radio Control TX Tổng | Năng lượng Node 2..9 (mJ) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Benign (IDS OFF) | 77 | 69 | 89.61% | 9397.42 | 2639.30 | 12153.50 | 206 (206 / 0) | 206 | 8725 (TB 1090.6) |
| Benign (IDS ON) | 77 | 67 | 87.01% | 10706.28 | 2901.49 | 13652.56 | 776 (232 / 544) | 776 | 20328 (TB 2541.0) |
| FDFF Attack (IDS ON) | 77 | 66 | 85.71% | 5250.06 | 2692.63 | 7552.07 | 1136 (652 / 484) | 1136 | 24230 (TB 3028.8) |

### Phân tách trước và trong khi tấn công FDFF (`t_attack = 1235.49s`)

| Giai đoạn | Benign TX | Benign RX | PDR (%) | Delay TB (ms) | Delay P95 (ms) | Gói tấn công giả |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Trước tấn công (`t < 1235.5s`) | 38 | 30 | 78.95% | 7754.53 | 11152.23 | 0 |
| Trong tấn công (`t >= 1235.5s`) | 39 | 30 | 76.92% | 3234.83 | 6052.13 | 156 |

## 2. Detection Rate (TPR), False Positive Rate (FPR) & Detection Delay

| Tầng phát hiện | Benign (IDS ON) — False Positive | FDFF Attack (IDS ON) — Detection Rate / Kết quả |
| :--- | :--- | :--- |
| **Tập trung (Controller Change-Point)** | 0/39 cửa sổ (**FPR = 0.00%**) | **36/38 cửa sổ sau tấn công (94.74%)**, phát hiện lần đầu tại Sample 64 (độ trễ ~44.51s), đỉnh `DT = 10.8` vs `ca = 2.79` |
| **Phân tán (Node cục bộ + Suspect)** | 1/7 node CP alarm (**FPR = 14.29%**) | 4/4 láng giềng `[2, 4, 6, 8]` ghi nhận suspect `[ 05 00 ]`; 1/4 láng giềng `[2]` vượt ngưỡng CP & gửi alarm; node ngoài vùng FP: `[]`; Controller suspects: `[]` |

## 3. Phân tích Chi phí của IDS (IDS ON vs IDS OFF trên Benign Traffic)

### A. Chi phí bộ nhớ Firmware (Z1 MSP430: ROM = `text+data`, RAM = `data+bss`)

| Firmware | IDS OFF ROM (B) | IDS ON ROM (B) | Tăng ROM | IDS OFF RAM (B) | IDS ON RAM (B) | Tăng RAM |
| :--- | ---: | ---: | :--- | ---: | ---: | :--- |
| `enabled-node.z1` | 41767 | 48161 | +6394.00 (+15.31%) | 6642 | 6988 | +346.00 (+5.21%) |
| `sink-node.z1` | 41405 | 42805 | +1400.00 (+3.38%) | 6602 | 6928 | +326.00 (+4.94%) |
| `controller-node.z1` | 33165 | 33535 | +370.00 (+1.12%) | 6560 | 6816 | +256.00 (+3.90%) |

### B. Chi phí vận hành (Runtime Cost trên mạng 9 node trong 2000s)

| Chỉ số | Benign IDS OFF | Benign IDS ON | Chênh lệch (Chi phí IDS) |
| :--- | ---: | ---: | :--- |
| Control packets khởi phát | 206 | 776 | +570.00 (+276.70%) |
| Tổng radio TX điều khiển (gồm chuyển tiếp) | 206 | 776 | +570.00 (+276.70%) |
| Năng lượng tiêu thụ Node 2..9 (mJ) | 8725 | 20328 | +11603.00 (+132.99%) |
| PDR dữ liệu (%) | 89.61% | 87.01% | -2.60 pp |
| End-to-End Delay trung bình (ms) | 9397.42 | 10706.28 | +1308.86 (+13.93%) |
