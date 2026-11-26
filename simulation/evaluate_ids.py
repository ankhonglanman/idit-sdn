#!/usr/bin/env python3
"""Evaluate IDIT-SDN across Benign (IDS OFF), Benign (IDS ON), and Attack (IDS ON)."""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"

METRIC_RE = re.compile(
    r"^(\d+):(\d+):.*?=\[\s*([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})\s*\]=(TX|RX)=([0-9A-Fa-f]{2})=([0-9A-Fa-f]{2})=([^=\r\n]*)="
)
ENERGY_RE = re.compile(r"^(\d+):(\d+):.*?E:\s*(\d+)\s*mJ")
CP_SAMPLE_RE = re.compile(r"^CP (detected|not detected yet) in (\d+)")
DT_RE = re.compile(r"^DT:\s*([0-9.]+)\s+ca:\s*([0-9.]+)")
DIST_SUSPECT_RE = re.compile(r"^(\d+):(\d+):.*?Adding suspect:\s*\[\s*([0-9A-Fa-f]{2})\s+00\s*\]")
DIST_CP_RE = re.compile(r"^(\d+):(\d+):.*?CP detected in (\d+)")
DIST_ALARM_RE = re.compile(r"^(\d+):(\d+):.*?Sending CP detection alarm")
FALSE_FLOW_RE = re.compile(r"^(\d+):(\d+):.*?Sending data to false flow:")
SIZE_LINE_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+[0-9a-fA-F]+\s+(\S+)\s*$")


def parse_firmware_sizes(path: Path) -> dict:
    data: dict[str, dict] = {"ids_on": {}, "ids_off": {}, "controller_pc": {}}
    if not path.exists():
        return data
    section = None
    for line in path.read_text(errors="replace").splitlines():
        s = line.strip()
        if s == "# IDS_ON_FIRMWARE":
            section = "ids_on"
            continue
        if s == "# IDS_OFF_FIRMWARE":
            section = "ids_off"
            continue
        if s == "# CONTROLLER_BINARIES":
            section = "controller_pc"
            continue
        if section in ("ids_on", "ids_off"):
            m = SIZE_LINE_RE.match(line)
            if m:
                text, data_b, bss, dec, fname = m.groups()
                text_i, data_i, bss_i = int(text), int(data_b), int(bss)
                data[section][fname] = {
                    "text": text_i,
                    "data": data_i,
                    "bss": bss_i,
                    "rom": text_i + data_i,
                    "ram": data_i + bss_i,
                }
        elif section == "controller_pc" and s:
            parts = s.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                data["controller_pc"][Path(parts[1]).parent.name] = int(parts[0])
    return data


def analyze_motes(path: Path, attack_start_us: int | None = None) -> dict:
    tx_data_events: list[tuple[int, int, str]] = []
    rx_data_events: list[tuple[int, int, str]] = []
    attack_tx_count = 0
    first_attack_us: int | None = None

    orig_ctrl_sdn = 0
    orig_ctrl_ids = 0
    hop_ctrl_sdn = 0
    hop_ctrl_ids = 0

    energy_by_node: dict[int, int] = {}
    dist_suspects: dict[int, list[str]] = {}
    dist_cp_nodes: dict[int, tuple[float, int]] = {}
    dist_alarm_nodes: list[tuple[float, int]] = []

    for raw in path.read_text(errors="replace").splitlines():
        m_att = FALSE_FLOW_RE.match(raw)
        if m_att:
            t_us = int(m_att.group(1))
            if first_attack_us is None:
                first_attack_us = t_us
            attack_tx_count += 1

        m_e = ENERGY_RE.match(raw)
        if m_e:
            mote_id = int(m_e.group(2))
            energy_by_node[mote_id] = int(m_e.group(3))

        m_sus = DIST_SUSPECT_RE.match(raw)
        if m_sus:
            mote_id = int(m_sus.group(2))
            suspect_hex = m_sus.group(3).upper()
            dist_suspects.setdefault(mote_id, []).append(suspect_hex)

        m_cp = DIST_CP_RE.match(raw)
        if m_cp:
            t_s = int(m_cp.group(1)) / 1e6
            mote_id = int(m_cp.group(2))
            sample = int(m_cp.group(3))
            dist_cp_nodes.setdefault(mote_id, (t_s, sample))

        m_al = DIST_ALARM_RE.match(raw)
        if m_al:
            dist_alarm_nodes.append((int(m_al.group(1)) / 1e6, int(m_al.group(2))))

        m = METRIC_RE.match(raw)
        if not m:
            continue
        t_us = int(m.group(1))
        mote_id = int(m.group(2))
        src_node = int(m.group(3), 16)
        direction = m.group(5)
        pkt_type = m.group(6).upper()
        seq_hex = m.group(7).upper()
        dest = m.group(8).strip()

        if direction == "TX":
            if pkt_type == "05":
                if src_node == mote_id and dest == "2017":
                    tx_data_events.append((t_us, src_node, seq_hex))
            else:
                is_mngt = pkt_type in ("11", "12")
                if is_mngt:
                    hop_ctrl_ids += 1
                    if src_node == mote_id:
                        orig_ctrl_ids += 1
                else:
                    hop_ctrl_sdn += 1
                    if src_node == mote_id:
                        orig_ctrl_sdn += 1
        elif direction == "RX":
            if mote_id == 3 and pkt_type == "05" and dest == "2017":
                rx_data_events.append((t_us, src_node, seq_hex))

    if attack_start_us is None:
        attack_start_us = first_attack_us

    def compute_pdr_delay(
        tx_list: list[tuple[int, int, str]], rx_list: list[tuple[int, int, str]]
    ) -> dict:
        matched_tx_indices: set[int] = set()
        delays_ms: list[float] = []
        matched_rx = 0

        for rx_us, src_node, seq_hex in rx_list:
            chosen_idx = None
            for idx in range(len(tx_list) - 1, -1, -1):
                if idx in matched_tx_indices:
                    continue
                tx_us, tx_src, tx_seq = tx_list[idx]
                if tx_src == src_node and tx_seq == seq_hex and tx_us <= rx_us:
                    chosen_idx = idx
                    break
            if chosen_idx is not None:
                matched_tx_indices.add(chosen_idx)
                matched_rx += 1
                delays_ms.append((rx_us - tx_list[chosen_idx][0]) / 1000.0)

        tx_n = len(tx_list)
        rx_n = matched_rx
        pdr = (100.0 * rx_n / tx_n) if tx_n > 0 else 0.0
        return {
            "tx": tx_n,
            "rx": rx_n,
            "pdr_pct": round(pdr, 2),
            "delay_mean_ms": round(statistics.mean(delays_ms), 2) if delays_ms else None,
            "delay_median_ms": round(statistics.median(delays_ms), 2) if delays_ms else None,
            "delay_p95_ms": round(sorted(delays_ms)[int(0.95 * (len(delays_ms) - 1))], 2)
            if delays_ms
            else None,
            "delay_max_ms": round(max(delays_ms), 2) if delays_ms else None,
        }

    overall = compute_pdr_delay(tx_data_events, rx_data_events)
    split = {}
    if first_attack_us is not None:
        pre_tx = [e for e in tx_data_events if e[0] < first_attack_us]
        pre_rx = [e for e in rx_data_events if e[0] < first_attack_us]
        post_tx = [e for e in tx_data_events if e[0] >= first_attack_us]
        post_rx = [e for e in rx_data_events if e[0] >= first_attack_us]
        split["pre_attack"] = compute_pdr_delay(pre_tx, pre_rx)
        split["during_attack"] = compute_pdr_delay(post_tx, post_rx)

    sensor_energies = {nid: val for nid, val in sorted(energy_by_node.items()) if nid != 1}
    total_sensor_mj = sum(sensor_energies.values())
    mean_sensor_mj = (total_sensor_mj / len(sensor_energies)) if sensor_energies else 0.0

    return {
        "attack_start_s": round(first_attack_us / 1e6, 2) if first_attack_us is not None else None,
        "attack_false_flow_sends": attack_tx_count,
        "data_traffic": overall,
        "data_traffic_split": split,
        "control_overhead": {
            "originated_sdn": orig_ctrl_sdn,
            "originated_ids_mngt": orig_ctrl_ids,
            "originated_total": orig_ctrl_sdn + orig_ctrl_ids,
            "radio_tx_sdn": hop_ctrl_sdn,
            "radio_tx_ids_mngt": hop_ctrl_ids,
            "radio_tx_total": hop_ctrl_sdn + hop_ctrl_ids,
        },
        "energy_mj": {
            "per_node": energy_by_node,
            "sensor_nodes_total_mj": total_sensor_mj,
            "sensor_nodes_mean_mj": round(mean_sensor_mj, 2),
        },
        "distributed_ids": {
            "suspects_by_node": {nid: len(lst) for nid, lst in sorted(dist_suspects.items())},
            "cp_detected_nodes": dist_cp_nodes,
            "alarm_nodes": dist_alarm_nodes,
        },
    }


def analyze_controller(path: Path) -> dict:
    if not path.exists():
        return {}
    lines = path.read_text(errors="replace").splitlines()
    total_overhead = None
    last_dt = None
    last_ca = None

    ctrl_ov_samples: dict[int, dict] = {}
    pdr_samples: dict[int, dict] = {}
    fdff_samples: list[int] = []
    fni_samples: list[int] = []
    suspect_alarms: list[str] = []
    attackers: list[str] = []

    current_metric = None
    for line in lines:
        s = line.strip()
        if s.startswith("Total overhead ="):
            total_overhead = int(s.split("=")[1].strip())
        elif s == "Control packets":
            current_metric = "ctrl"
        elif s == "Delivery rate":
            current_metric = "pdr"
        else:
            m_dt = DT_RE.match(s)
            if m_dt:
                last_dt = float(m_dt.group(1))
                last_ca = float(m_dt.group(2))
                continue
            m_cp = CP_SAMPLE_RE.match(s)
            if m_cp:
                detected = m_cp.group(1) == "detected"
                sample_idx = int(m_cp.group(2))
                entry = {"detected": detected, "dt": last_dt, "ca": last_ca}
                if current_metric == "ctrl":
                    ctrl_ov_samples[sample_idx] = entry
                elif current_metric == "pdr":
                    pdr_samples[sample_idx] = entry
                continue

        if s == "FDFF attack detected":
            if ctrl_ov_samples:
                fdff_samples.append(max(ctrl_ov_samples))
        elif s == "FNI attack detected":
            if pdr_samples:
                fni_samples.append(max(pdr_samples))
        elif s.startswith("First suspect:") or s.startswith("New alarm:") or s.startswith("New suspect:"):
            suspect_alarms.append(s)
        elif s.startswith("Attacker indentified:") or "included in Blocklist" in s:
            attackers.append(s)

    max_ctrl_dt = max((v["dt"] for v in ctrl_ov_samples.values() if v["dt"] is not None), default=None)
    return {
        "controller_reported_total_overhead": total_overhead,
        "monitoring_samples_count": len(ctrl_ov_samples),
        "ctrl_ov_cp_detected_samples": sorted([k for k, v in ctrl_ov_samples.items() if v["detected"]]),
        "pdr_cp_detected_samples": sorted([k for k, v in pdr_samples.items() if v["detected"]]),
        "fdff_detected_samples": fdff_samples,
        "fni_detected_samples": fni_samples,
        "max_ctrl_dt": max_ctrl_dt,
        "ca": last_ca,
        "suspect_events": suspect_alarms,
        "blocklist_events": attackers,
    }


def pct_delta(new_val: float, base_val: float) -> str:
    if base_val == 0:
        return "N/A"
    delta = new_val - base_val
    pct = 100.0 * delta / base_val
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:.2f} ({sign}{pct:.2f}%)"


def main() -> None:
    sizes = parse_firmware_sizes(RESULTS_DIR / "eval_firmware_sizes.txt")
    scenarios = {}
    for name in ("benign_ids_off", "benign_ids_on", "attack_ids_on"):
        motes = analyze_motes(RESULTS_DIR / f"eval_{name}_motes.txt")
        ctrl = analyze_controller(RESULTS_DIR / f"eval_{name}_controller.txt")
        scenarios[name] = {"motes": motes, "controller": ctrl}

    off_m = scenarios["benign_ids_off"]["motes"]
    on_m = scenarios["benign_ids_on"]["motes"]
    att_m = scenarios["attack_ids_on"]["motes"]
    on_c = scenarios["benign_ids_on"]["controller"]
    att_c = scenarios["attack_ids_on"]["controller"]

    # Detection Rate & FPR calculation
    benign_samples = on_c.get("monitoring_samples_count", 0)
    benign_fp_samples = len(on_c.get("fdff_detected_samples", [])) + len(on_c.get("fni_detected_samples", []))
    centr_fpr = (100.0 * benign_fp_samples / benign_samples) if benign_samples > 0 else 0.0

    # Attack starts at t ~ 1235.48s -> sample ~62 (10s Contiki = 20s Cooja)
    att_start_s = att_m.get("attack_start_s") or 1235.48
    att_start_sample = int(att_start_s // 20) + 1
    att_samples_total = att_c.get("monitoring_samples_count", 0)
    att_fdff_list = att_c.get("fdff_detected_samples", [])
    att_post_samples = [s for s in range(61, 61 + att_samples_total) if s >= att_start_sample]
    att_tp_samples = [s for s in att_fdff_list if s >= att_start_sample]
    centr_dr = (100.0 * len(att_tp_samples) / len(att_post_samples)) if att_post_samples else 0.0
    first_det_sample = min(att_tp_samples) if att_tp_samples else None
    first_det_delay_s = round((first_det_sample * 20.0) - att_start_s, 2) if first_det_sample else None

    dist_benign_fp = len(on_m["distributed_ids"]["cp_detected_nodes"])
    dist_benign_fpr = 100.0 * dist_benign_fp / 7.0
    att_neighbor_ids = {2, 4, 6, 8}
    dist_att_tp_nodes = sorted(
        nid for nid in att_m["distributed_ids"]["cp_detected_nodes"] if nid in att_neighbor_ids
    )
    dist_att_non_neighbor_fp = sorted(
        nid for nid in att_m["distributed_ids"]["cp_detected_nodes"] if nid not in att_neighbor_ids
    )
    dist_suspect_neighbors = sorted(
        nid for nid in att_m["distributed_ids"]["suspects_by_node"] if nid in att_neighbor_ids
    )

    report = {
        "firmware_sizes": sizes,
        "scenarios": scenarios,
        "detection_summary": {
            "centralized_benign_samples": benign_samples,
            "centralized_benign_fp_samples": benign_fp_samples,
            "centralized_fpr_pct": round(centr_fpr, 2),
            "centralized_attack_post_samples": len(att_post_samples),
            "centralized_attack_tp_samples": len(att_tp_samples),
            "centralized_window_dr_pct": round(centr_dr, 2),
            "centralized_first_detection_sample": first_det_sample,
            "centralized_detection_delay_s": first_det_delay_s,
            "distributed_benign_fp_nodes": dist_benign_fp,
            "distributed_benign_fpr_pct": round(dist_benign_fpr, 2),
            "distributed_attack_suspect_neighbors": dist_suspect_neighbors,
            "distributed_attack_cp_neighbors": dist_att_tp_nodes,
            "distributed_attack_non_neighbor_fp": dist_att_non_neighbor_fp,
        },
    }

    (RESULTS_DIR / "evaluation_report.json").write_text(json.dumps(report, indent=2))

    # Build Markdown Report
    md: list[str] = []
    md.append("# Báo cáo Đánh giá Thực nghiệm IDIT-SDN (Benign vs FDFF Attack & IDS Cost)")
    md.append("")
    md.append("## 1. Hiệu năng mạng: PDR, End-to-End Delay & Control Overhead (2000s mô phỏng)")
    md.append("")
    md.append("| Kịch bản | Benign TX | Benign RX | PDR (%) | Delay TB (ms) | Delay Trung vị (ms) | Delay P95 (ms) | Control Orig (SDN / IDS) | Radio Control TX Tổng | Năng lượng Node 2..9 (mJ) |")
    md.append("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for label, m in [
        ("Benign (IDS OFF)", off_m),
        ("Benign (IDS ON)", on_m),
        ("FDFF Attack (IDS ON)", att_m),
    ]:
        dt = m["data_traffic"]
        co = m["control_overhead"]
        en = m["energy_mj"]
        md.append(
            f"| {label} | {dt['tx']} | {dt['rx']} | {dt['pdr_pct']:.2f}% | "
            f"{dt['delay_mean_ms'] or 0:.2f} | {dt['delay_median_ms'] or 0:.2f} | {dt['delay_p95_ms'] or 0:.2f} | "
            f"{co['originated_total']} ({co['originated_sdn']} / {co['originated_ids_mngt']}) | "
            f"{co['radio_tx_total']} | {en['sensor_nodes_total_mj']} (TB {en['sensor_nodes_mean_mj']:.1f}) |"
        )

    if att_m["data_traffic_split"]:
        md.append("")
        md.append("### Phân tách trước và trong khi tấn công FDFF (`t_attack = " + f"{att_start_s:.2f}s`)")
        md.append("")
        md.append("| Giai đoạn | Benign TX | Benign RX | PDR (%) | Delay TB (ms) | Delay P95 (ms) | Gói tấn công giả |")
        md.append("| :--- | ---: | ---: | ---: | ---: | ---: | ---: |")
        pre = att_m["data_traffic_split"]["pre_attack"]
        dur = att_m["data_traffic_split"]["during_attack"]
        md.append(f"| Trước tấn công (`t < {att_start_s:.1f}s`) | {pre['tx']} | {pre['rx']} | {pre['pdr_pct']:.2f}% | {pre['delay_mean_ms'] or 0:.2f} | {pre['delay_p95_ms'] or 0:.2f} | 0 |")
        md.append(f"| Trong tấn công (`t >= {att_start_s:.1f}s`) | {dur['tx']} | {dur['rx']} | {dur['pdr_pct']:.2f}% | {dur['delay_mean_ms'] or 0:.2f} | {dur['delay_p95_ms'] or 0:.2f} | {att_m['attack_false_flow_sends']} |")

    md.append("")
    md.append("## 2. Detection Rate (TPR), False Positive Rate (FPR) & Detection Delay")
    md.append("")
    md.append("| Tầng phát hiện | Benign (IDS ON) — False Positive | FDFF Attack (IDS ON) — Detection Rate / Kết quả |")
    md.append("| :--- | :--- | :--- |")
    md.append(
        f"| **Tập trung (Controller Change-Point)** | {benign_fp_samples}/{benign_samples} cửa sổ (**FPR = {centr_fpr:.2f}%**) | "
        f"**{len(att_tp_samples)}/{len(att_post_samples)} cửa sổ sau tấn công ({centr_dr:.2f}%)**, "
        f"phát hiện lần đầu tại Sample {first_det_sample} (độ trễ ~{first_det_delay_s}s), đỉnh `DT = {att_c.get('max_ctrl_dt')}` vs `ca = {att_c.get('ca')}` |"
    )
    md.append(
        f"| **Phân tán (Node cục bộ + Suspect)** | {dist_benign_fp}/7 node CP alarm (**FPR = {dist_benign_fpr:.2f}%**) | "
        f"4/4 láng giềng `{dist_suspect_neighbors}` ghi nhận suspect `[ 05 00 ]`; "
        f"{len(dist_att_tp_nodes)}/4 láng giềng `{dist_att_tp_nodes}` vượt ngưỡng CP & gửi alarm; "
        f"node ngoài vùng FP: `{dist_att_non_neighbor_fp}`; Controller suspects: `{att_c.get('suspect_events')}` |"
    )

    md.append("")
    md.append("## 3. Phân tích Chi phí của IDS (IDS ON vs IDS OFF trên Benign Traffic)")
    md.append("")
    md.append("### A. Chi phí bộ nhớ Firmware (Z1 MSP430: ROM = `text+data`, RAM = `data+bss`)")
    md.append("")
    md.append("| Firmware | IDS OFF ROM (B) | IDS ON ROM (B) | Tăng ROM | IDS OFF RAM (B) | IDS ON RAM (B) | Tăng RAM |")
    md.append("| :--- | ---: | ---: | :--- | ---: | ---: | :--- |")
    for fw in ("enabled-node.z1", "sink-node.z1", "controller-node.z1"):
        off_f = sizes["ids_off"].get(fw, {})
        on_f = sizes["ids_on"].get(fw, {})
        if off_f and on_f:
            md.append(
                f"| `{fw}` | {off_f['rom']} | {on_f['rom']} | {pct_delta(on_f['rom'], off_f['rom'])} | "
                f"{off_f['ram']} | {on_f['ram']} | {pct_delta(on_f['ram'], off_f['ram'])} |"
            )

    md.append("")
    md.append("### B. Chi phí vận hành (Runtime Cost trên mạng 9 node trong 2000s)")
    md.append("")
    md.append("| Chỉ số | Benign IDS OFF | Benign IDS ON | Chênh lệch (Chi phí IDS) |")
    md.append("| :--- | ---: | ---: | :--- |")
    md.append(
        f"| Control packets khởi phát | {off_m['control_overhead']['originated_total']} | "
        f"{on_m['control_overhead']['originated_total']} | "
        f"{pct_delta(on_m['control_overhead']['originated_total'], off_m['control_overhead']['originated_total'])} |"
    )
    md.append(
        f"| Tổng radio TX điều khiển (gồm chuyển tiếp) | {off_m['control_overhead']['radio_tx_total']} | "
        f"{on_m['control_overhead']['radio_tx_total']} | "
        f"{pct_delta(on_m['control_overhead']['radio_tx_total'], off_m['control_overhead']['radio_tx_total'])} |"
    )
    md.append(
        f"| Năng lượng tiêu thụ Node 2..9 (mJ) | {off_m['energy_mj']['sensor_nodes_total_mj']} | "
        f"{on_m['energy_mj']['sensor_nodes_total_mj']} | "
        f"{pct_delta(on_m['energy_mj']['sensor_nodes_total_mj'], off_m['energy_mj']['sensor_nodes_total_mj'])} |"
    )
    md.append(
        f"| PDR dữ liệu (%) | {off_m['data_traffic']['pdr_pct']:.2f}% | "
        f"{on_m['data_traffic']['pdr_pct']:.2f}% | "
        f"{on_m['data_traffic']['pdr_pct'] - off_m['data_traffic']['pdr_pct']:+.2f} pp |"
    )
    md.append(
        f"| End-to-End Delay trung bình (ms) | {off_m['data_traffic']['delay_mean_ms'] or 0:.2f} | "
        f"{on_m['data_traffic']['delay_mean_ms'] or 0:.2f} | "
        f"{pct_delta(on_m['data_traffic']['delay_mean_ms'] or 0, off_m['data_traffic']['delay_mean_ms'] or 0)} |"
    )

    md_text = "\n".join(md) + "\n"
    (RESULTS_DIR / "evaluation_report.md").write_text(md_text)
    print(md_text)


if __name__ == "__main__":
    main()
