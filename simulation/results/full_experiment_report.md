# Báo cáo Tổng hợp Toàn bộ Thí nghiệm IDIT-SDN

## 1. Bảng tổng hợp các kịch bản (3x3 Grid & 36-node Log)

| Kịch bản | Loại | TX / RX | PDR (%) | Delay TB (ms) | Radio Ctrl TX | Energy (mJ) | Samples | Peak Ctrl DT | Peak PDR DT | FDFF First / Count | FNI First / Count | Banned |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| `eval_benign_ids_off` | grid3x3 | 77 / 69 | 89.61 | 12942.29 | 241 | 9220 | 0 | - | - | - | - | - |
| `eval_benign_ids_on` | grid3x3 | 77 / 63 | 81.82 | 3921.65 | 771 | 19919 | 99 | 1.29 | 0.56 | - | - | - |
| `eval_attack_ids_on` | grid3x3 | 79 / 64 | 81.01 | 3693.35 | 1131 | 23933 | 99 | 8.71 | 1.19 | 65 (35) | - | [ 05 00 ] |
| `attack_demo` | grid3x3 | 77 / 65 | 84.42 | 3859.11 | 1124 | 24858 | 99 | 10.93 | 1.16 | 64 (36) | - | [ 05 00 ] |
| `attack_fni` | grid3x3 | 501 / 287 | 57.29 | 2536.54 | 1008 | 28461 | 99 | 4.97 | 16.28 | 64 (22) | 66 (34) | - |
| `attack_two` | grid3x3 | 81 / 69 | 85.19 | 3304.0 | 1123 | 23219 | 99 | 6.6 | 0.59 | 66 (34) | - | - |
| `attack_energy` | grid3x3 | 66 / 53 | 80.3 | 4377.1 | 970 | 20974 | 89 | 14.8 | 0.85 | 64 (26) | - | [ 05 00 ] |
| `n36_ITSDN_n36_top_a1_1_i1_z1` | n36 | 0 / 0 | 0.0 | - | 331 | 0 | 16 | - | - | - | - | - |

## 2. File CSV chuỗi thời gian đã xuất

- `csv/ts_eval_benign_ids_on.csv`
- `csv/ts_eval_attack_ids_on.csv`
- `csv/ts_attack_demo.csv`
- `csv/ts_attack_fni.csv`
- `csv/ts_attack_two.csv`
- `csv/ts_attack_energy.csv`
- `csv/ts_n36_ITSDN_n36_top_a1_1_i1_z1.csv`
- `csv/summary_all_scenarios.csv`

## 3. Biểu đồ PNG đã sinh

- `charts/fdff_before_after.png`
- `charts/fni_before_after.png`
- `charts/attack_comparison.png`
- `charts/n36_timeseries.png`
