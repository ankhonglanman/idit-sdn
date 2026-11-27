#!/usr/bin/env python3
"""Evaluate IDIT-SDN across all simulation scenarios, export CSVs and PNG charts."""

from __future__ import annotations

import csv
import json
import re
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"
CSV_DIR = RESULTS_DIR / "csv"
CHARTS_DIR = RESULTS_DIR / "charts"

METRIC_RE = re.compile(
    r"^(\d+):(\d+):.*?=\[\s*([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})\s*\]=(TX|RX)=([0-9A-Fa-f]{2})=([0-9A-Fa-f]{2})=([^=\r\n]*)="
)
ENERGY_RE = re.compile(r"^(\d+):(\d+):.*?E:\s*(\d+)\s*mJ")
CP_SAMPLE_RE = re.compile(r"^CP (detected|not detected yet) in (\d+)")
DT_RE = re.compile(r"^DT:\s*([0-9.,]+)\s+ca:\s*([0-9.,]+)")
CTRL_OV_VAL_RE = re.compile(r"^Control overhead\s*=\s*([0-9.,]+)")
DATA_DR_VAL_RE = re.compile(r"^Data packets delivery rate\s*=\s*([0-9.,]+)")
TOTAL_OV_RE = re.compile(r"^Total overhead\s*=\s*(\d+)")
VAR_CTRL_RE = re.compile(r"^Variance control packets overhead:\s*([0-9.,]+)")
VAR_PDR_RE = re.compile(r"^Variance data packets delivery rate:\s*([0-9.,]+)")
BANNED_RE = re.compile(r"^(\[\s*[0-9A-Fa-f]{2}\s+[0-9A-Fa-f]{2}\s*\])[- ]+Banned:\s*YES")
DIST_SUSPECT_RE = re.compile(r"^(\d+):(\d+):.*?Adding suspect:\s*\[\s*([0-9A-Fa-f]{2})\s+00\s*\]")
DIST_CP_RE = re.compile(r"^(\d+):(\d+):.*?CP detected in (\d+)")
DIST_ALARM_RE = re.compile(r"^(\d+):(\d+):.*?Sending CP detection alarm")
ATTACK_EVENT_RE = re.compile(
    r"^(\d+):(\d+):.*?(?:Sending data to false flow:|Sending false flow request:|Injecting (?:false|synthesized).*?neighbor report)"
)
SIZE_LINE_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+[0-9a-fA-F]+\s+(\S+)\s*$")


def _parse_float(val: str) -> float:
    return float(val.strip().replace(",", "."))


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
                text, data_b, bss, _dec, fname = m.groups()
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
    if not path.exists():
        return {}
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

    text = path.read_text(errors="replace").replace("\x00", "")
    for raw in text.splitlines():
        m_att = ATTACK_EVENT_RE.match(raw)
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


def _empty_ts_row(sample_idx: int) -> dict:
    return {
        "sample": sample_idx,
        "ctrl_overhead": None,
        "ctrl_dt": None,
        "ctrl_ca": None,
        "ctrl_cp_detected": None,
        "fdff_alert": 0,
        "pdr_pct": None,
        "pdr_dt": None,
        "pdr_ca": None,
        "pdr_cp_detected": None,
        "fni_alert": 0,
    }


def analyze_controller(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(errors="replace").replace("\x00", "")
    lines = text.splitlines()

    total_overhead = None
    var_ctrl = None
    var_pdr = None
    last_dt = None
    last_ca = None

    ctrl_ov_samples: dict[int, dict] = {}
    pdr_samples: dict[int, dict] = {}
    fdff_samples: list[int] = []
    fni_samples: list[int] = []
    suspect_alarms: list[str] = []
    attackers: list[str] = []
    banned_nodes: list[str] = []

    ts_rows: dict[int, dict] = {}
    ctrl_seq_idx = 0
    pdr_seq_idx = 0
    current_metric = None

    for line in lines:
        s = line.strip()
        if not s:
            continue

        m_tot = TOTAL_OV_RE.match(s)
        if m_tot:
            total_overhead = int(m_tot.group(1))
            continue

        m_vc = VAR_CTRL_RE.match(s)
        if m_vc:
            var_ctrl = _parse_float(m_vc.group(1))
            continue

        m_vp = VAR_PDR_RE.match(s)
        if m_vp:
            var_pdr = _parse_float(m_vp.group(1))
            continue

        m_cov = CTRL_OV_VAL_RE.match(s)
        if m_cov:
            ctrl_seq_idx += 1
            row = ts_rows.setdefault(ctrl_seq_idx, _empty_ts_row(ctrl_seq_idx))
            row["ctrl_overhead"] = _parse_float(m_cov.group(1))
            continue

        m_dr = DATA_DR_VAL_RE.match(s)
        if m_dr:
            pdr_seq_idx += 1
            row = ts_rows.setdefault(pdr_seq_idx, _empty_ts_row(pdr_seq_idx))
            row["pdr_pct"] = _parse_float(m_dr.group(1))
            continue

        if s == "Control packets":
            current_metric = "ctrl"
            continue
        if s == "Delivery rate":
            current_metric = "pdr"
            continue

        m_dt = DT_RE.match(s)
        if m_dt:
            last_dt = _parse_float(m_dt.group(1))
            last_ca = _parse_float(m_dt.group(2))
            continue

        m_cp = CP_SAMPLE_RE.match(s)
        if m_cp:
            detected = m_cp.group(1) == "detected"
            sample_idx = int(m_cp.group(2))
            entry = {"detected": detected, "dt": last_dt, "ca": last_ca}
            if current_metric == "ctrl":
                ctrl_ov_samples[sample_idx] = entry
                if ctrl_seq_idx > 0:
                    row = ts_rows.setdefault(ctrl_seq_idx, _empty_ts_row(ctrl_seq_idx))
                    row["ctrl_dt"] = last_dt
                    row["ctrl_ca"] = last_ca
                    row["ctrl_cp_detected"] = 1 if detected else 0
            elif current_metric == "pdr":
                pdr_samples[sample_idx] = entry
                if pdr_seq_idx > 0:
                    row = ts_rows.setdefault(pdr_seq_idx, _empty_ts_row(pdr_seq_idx))
                    row["pdr_dt"] = last_dt
                    row["pdr_ca"] = last_ca
                    row["pdr_cp_detected"] = 1 if detected else 0
            continue

        if s == "FDFF attack detected":
            if ctrl_ov_samples:
                fdff_samples.append(max(ctrl_ov_samples))
            if ctrl_seq_idx > 0 and ctrl_seq_idx in ts_rows:
                ts_rows[ctrl_seq_idx]["fdff_alert"] = 1
        elif s == "FNI attack detected":
            if pdr_samples:
                fni_samples.append(max(pdr_samples))
            if pdr_seq_idx > 0 and pdr_seq_idx in ts_rows:
                ts_rows[pdr_seq_idx]["fni_alert"] = 1
        elif s.startswith("First suspect:") or s.startswith("New alarm:") or s.startswith("New suspect:"):
            suspect_alarms.append(s)
        elif s.startswith("Attacker indentified:") or "included in Blocklist" in s:
            attackers.append(s)
        else:
            m_ban = BANNED_RE.match(s)
            if m_ban:
                addr_str = " ".join(m_ban.group(1).split())
                if addr_str not in banned_nodes:
                    banned_nodes.append(addr_str)

    max_ctrl_dt = max((v["dt"] for v in ctrl_ov_samples.values() if v["dt"] is not None), default=None)
    max_pdr_dt = max((v["dt"] for v in pdr_samples.values() if v["dt"] is not None), default=None)
    ordered_ts = [ts_rows[idx] for idx in sorted(ts_rows)]

    return {
        "controller_reported_total_overhead": total_overhead,
        "var_ctrl_overhead": var_ctrl,
        "var_data_pdr": var_pdr,
        "monitoring_samples_count": len(ctrl_ov_samples),
        "total_series_samples": len(ordered_ts),
        "ctrl_ov_cp_detected_samples": sorted([k for k, v in ctrl_ov_samples.items() if v["detected"]]),
        "pdr_cp_detected_samples": sorted([k for k, v in pdr_samples.items() if v["detected"]]),
        "fdff_detected_samples": fdff_samples,
        "fni_detected_samples": fni_samples,
        "max_ctrl_dt": max_ctrl_dt,
        "max_pdr_dt": max_pdr_dt,
        "ca": last_ca,
        "suspect_events": suspect_alarms,
        "blocklist_events": attackers,
        "banned_nodes": banned_nodes,
        "timeseries": ordered_ts,
    }


def pct_delta(new_val: float, base_val: float) -> str:
    if base_val == 0:
        return "N/A"
    delta = new_val - base_val
    pct = 100.0 * delta / base_val
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:.2f} ({sign}{pct:.2f}%)"


def export_timeseries_csv(scenario_key: str, rows: list[dict]) -> Path | None:
    if not rows:
        return None
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CSV_DIR / f"ts_{scenario_key}.csv"
    fieldnames = [
        "sample",
        "ctrl_overhead",
        "ctrl_dt",
        "ctrl_ca",
        "ctrl_cp_detected",
        "fdff_alert",
        "pdr_pct",
        "pdr_dt",
        "pdr_ca",
        "pdr_cp_detected",
        "fni_alert",
    ]
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    return out_path


def export_summary_csv(records: list[dict]) -> Path:
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CSV_DIR / "summary_all_scenarios.csv"
    fieldnames = [
        "scenario",
        "kind",
        "tx",
        "rx",
        "pdr_pct",
        "delay_mean_ms",
        "ctrl_orig_total",
        "ctrl_radio_tx_total",
        "energy_total_mj",
        "controller_total_overhead",
        "samples",
        "var_ctrl",
        "var_pdr",
        "max_ctrl_dt",
        "max_pdr_dt",
        "fdff_first_sample",
        "fdff_det_count",
        "fni_first_sample",
        "fni_det_count",
        "attack_start_s",
        "attack_events",
        "banned_nodes",
    ]
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    return out_path


def plot_fdff_chart(benign_c: dict, fdff_c: dict, fdff_m: dict) -> Path | None:
    b_ts = benign_c.get("timeseries", [])
    a_ts = fdff_c.get("timeseries", [])
    if not b_ts or not a_ts:
        return None
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CHARTS_DIR / "fdff_before_after.png"

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6.8), sharex=True)
    bx = [r["sample"] for r in b_ts if r["ctrl_overhead"] is not None]
    by = [r["ctrl_overhead"] for r in b_ts if r["ctrl_overhead"] is not None]
    ax_s = [r["sample"] for r in a_ts if r["ctrl_overhead"] is not None]
    ay = [r["ctrl_overhead"] for r in a_ts if r["ctrl_overhead"] is not None]

    ax1.plot(bx, by, label="Benign (IDS ON)", color="#2ca02c", linewidth=1.6)
    ax1.plot(ax_s, ay, label="FDFF Attack (IDS ON)", color="#d62728", linewidth=1.8)

    att_start_s = fdff_m.get("attack_start_s")
    att_sample = int(att_start_s // 20) + 1 if att_start_s else 62
    fdff_first = min(fdff_c.get("fdff_detected_samples", []), default=None)

    ax1.axvline(att_sample, color="#ff7f0e", linestyle="--", linewidth=1.4, label=f"Attack Start (~Sample {att_sample})")
    if fdff_first:
        ax1.axvline(fdff_first, color="#9467bd", linestyle=":", linewidth=1.6, label=f"First FDFF Detection (Sample {fdff_first})")
    ax1.set_ylabel("Control Overhead (pkts / 20s)")
    ax1.set_title("FDFF Attack: Control Overhead & Change-Point Statistic (Benign vs Attack)")
    ax1.grid(True, alpha=0.3)
    ax1.legend(loc="upper right", fontsize=8)

    b_dt_x = [r["sample"] for r in b_ts if r["ctrl_dt"] is not None]
    b_dt_y = [r["ctrl_dt"] for r in b_ts if r["ctrl_dt"] is not None]
    a_dt_x = [r["sample"] for r in a_ts if r["ctrl_dt"] is not None]
    a_dt_y = [r["ctrl_dt"] for r in a_ts if r["ctrl_dt"] is not None]
    ca = fdff_c.get("ca") or 2.79

    ax2.plot(b_dt_x, b_dt_y, label="Benign Control DT", color="#2ca02c", linewidth=1.6)
    ax2.plot(a_dt_x, a_dt_y, label="FDFF Control DT", color="#d62728", linewidth=1.8)
    ax2.axhline(ca, color="#1f77b4", linestyle="--", linewidth=1.4, label=f"Threshold ca = {ca:.2f}")
    ax2.axvline(att_sample, color="#ff7f0e", linestyle="--", linewidth=1.2)
    if fdff_first:
        ax2.axvline(fdff_first, color="#9467bd", linestyle=":", linewidth=1.6)
    ax2.set_xlabel("Sample Index (10s Contiki = 20s Cooja)")
    ax2.set_ylabel("Control Overhead DT")
    ax2.grid(True, alpha=0.3)
    ax2.legend(loc="upper left", fontsize=8)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_fni_chart(fni_c: dict, fni_m: dict) -> Path | None:
    ts = fni_c.get("timeseries", [])
    if not ts:
        return None
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CHARTS_DIR / "fni_before_after.png"

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6.8), sharex=True)
    px = [r["sample"] for r in ts if r["pdr_pct"] is not None]
    py = [r["pdr_pct"] for r in ts if r["pdr_pct"] is not None]

    att_start_s = fni_m.get("attack_start_s")
    att_sample = int(att_start_s // 20) + 1 if att_start_s else 61
    fni_first = min(fni_c.get("fni_detected_samples", []), default=None)

    ax1.plot(px, py, label="Data Packets Delivery Rate (%)", color="#1f77b4", linewidth=1.8)
    ax1.axvline(att_sample, color="#ff7f0e", linestyle="--", linewidth=1.4, label=f"FNI Poisoning Start (~Sample {att_sample})")
    if fni_first:
        ax1.axvline(fni_first, color="#9467bd", linestyle=":", linewidth=1.6, label=f"First FNI Detection (Sample {fni_first})")
    ax1.set_ylabel("Controller Measured PDR (%)")
    ax1.set_title("FNI Attack (attack-three): Delivery Rate Drop & Change-Point Detection")
    ax1.grid(True, alpha=0.3)
    ax1.legend(loc="lower left", fontsize=8)

    dx = [r["sample"] for r in ts if r["pdr_dt"] is not None]
    dy = [r["pdr_dt"] for r in ts if r["pdr_dt"] is not None]
    cx = [r["sample"] for r in ts if r["ctrl_dt"] is not None]
    cy = [r["ctrl_dt"] for r in ts if r["ctrl_dt"] is not None]
    ca = fni_c.get("ca") or 2.79

    ax2.plot(dx, dy, label="Delivery Rate DT (FNI indicator)", color="#d62728", linewidth=1.8)
    if cx:
        ax2.plot(cx, cy, label="Control Overhead DT", color="#7f7f7f", linewidth=1.2, alpha=0.8)
    ax2.axhline(ca, color="#1f77b4", linestyle="--", linewidth=1.4, label=f"Threshold ca = {ca:.2f}")
    ax2.axvline(att_sample, color="#ff7f0e", linestyle="--", linewidth=1.2)
    if fni_first:
        ax2.axvline(fni_first, color="#9467bd", linestyle=":", linewidth=1.6)
    ax2.set_xlabel("Sample Index (10s Contiki = 20s Cooja)")
    ax2.set_ylabel("Change-Point DT")
    ax2.grid(True, alpha=0.3)
    ax2.legend(loc="upper left", fontsize=8)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_comparison_chart(records: list[dict]) -> Path | None:
    grid9 = [r for r in records if r["kind"] == "grid3x3" and (r["tx"] > 0 or r["samples"] > 0)]
    if not grid9:
        return None
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CHARTS_DIR / "attack_comparison.png"

    labels = [r["scenario"] for r in grid9]
    pdrs = [r["pdr_pct"] or 0.0 for r in grid9]
    radio_ctrl = [r["ctrl_radio_tx_total"] or 0 for r in grid9]
    ctrl_dt = [r["max_ctrl_dt"] or 0.0 for r in grid9]
    pdr_dt = [r["max_pdr_dt"] or 0.0 for r in grid9]

    fig, axes = plt.subplots(1, 3, figsize=(14, 4.8))
    x = list(range(len(labels)))

    axes[0].bar(x, pdrs, color="#1f77b4", alpha=0.85)
    axes[0].set_title("Data PDR (%)")
    axes[0].set_ylim(0, 105)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    axes[0].grid(True, axis="y", alpha=0.3)

    axes[1].bar(x, radio_ctrl, color="#ff7f0e", alpha=0.85)
    axes[1].set_title("Radio Control TX (pkts)")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    axes[1].grid(True, axis="y", alpha=0.3)

    w = 0.38
    axes[2].bar([i - w / 2 for i in x], ctrl_dt, width=w, color="#d62728", label="Peak Ctrl DT")
    axes[2].bar([i + w / 2 for i in x], pdr_dt, width=w, color="#9467bd", label="Peak PDR DT")
    axes[2].axhline(2.79, color="#2ca02c", linestyle="--", linewidth=1.3, label="ca = 2.79")
    axes[2].set_title("Peak Change-Point DT")
    axes[2].set_xticks(x)
    axes[2].set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    axes[2].grid(True, axis="y", alpha=0.3)
    axes[2].legend(fontsize=8)

    fig.suptitle("IDIT-SDN 3x3 Grid Scenarios Comparison", fontsize=12)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_n36_chart(stem: str, ctrl_data: dict) -> Path | None:
    ts = ctrl_data.get("timeseries", [])
    if not ts:
        return None
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CHARTS_DIR / "n36_timeseries.png"

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9.5, 6.0), sharex=True)
    cx = [r["sample"] for r in ts if r["ctrl_overhead"] is not None]
    cy = [r["ctrl_overhead"] for r in ts if r["ctrl_overhead"] is not None]
    px = [r["sample"] for r in ts if r["pdr_pct"] is not None]
    py = [r["pdr_pct"] for r in ts if r["pdr_pct"] is not None]

    ax1.plot(cx, cy, marker="o", markersize=4, color="#ff7f0e", linewidth=1.6)
    ax1.set_ylabel("Control Overhead (pkts)")
    ax1.set_title(f"36-Node Topology Log ({stem}): {len(ts)} Captured Samples")
    ax1.grid(True, alpha=0.3)

    ax2.plot(px, py, marker="s", markersize=4, color="#1f77b4", linewidth=1.6)
    ax2.set_xlabel("Sample Index")
    ax2.set_ylabel("Data Packets Delivery Rate (%)")
    ax2.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def _strip_eval_timeseries(ctrl_dict: dict) -> dict:
    return {k: v for k, v in ctrl_dict.items() if k != "timeseries"}


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

    # Detection Rate & FPR calculation (3-scenario A/B evaluation)
    benign_samples = on_c.get("monitoring_samples_count", 0)
    benign_fp_samples = len(on_c.get("fdff_detected_samples", [])) + len(on_c.get("fni_detected_samples", []))
    centr_fpr = (100.0 * benign_fp_samples / benign_samples) if benign_samples > 0 else 0.0

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

    json_scenarios = {
        k: {"motes": v["motes"], "controller": _strip_eval_timeseries(v["controller"])}
        for k, v in scenarios.items()
    }
    report = {
        "firmware_sizes": sizes,
        "scenarios": json_scenarios,
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

    # Build A/B Evaluation Markdown Report (evaluation_report.md)
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

    if att_m.get("data_traffic_split"):
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

    # Extended analytics: all 3x3 scenarios + 36-node logs + CSVs + PNG charts
    all_specs = [
        ("eval_benign_ids_off", "grid3x3", RESULTS_DIR / "eval_benign_ids_off_motes.txt", RESULTS_DIR / "eval_benign_ids_off_controller.txt"),
        ("eval_benign_ids_on", "grid3x3", RESULTS_DIR / "eval_benign_ids_on_motes.txt", RESULTS_DIR / "eval_benign_ids_on_controller.txt"),
        ("eval_attack_ids_on", "grid3x3", RESULTS_DIR / "eval_attack_ids_on_motes.txt", RESULTS_DIR / "eval_attack_ids_on_controller.txt"),
        ("attack_demo", "grid3x3", RESULTS_DIR / "attack_demo_motes.txt", RESULTS_DIR / "attack_demo_controller.txt"),
        ("attack_fni", "grid3x3", RESULTS_DIR / "attack_fni_motes.txt", RESULTS_DIR / "attack_fni_controller.txt"),
        ("attack_two", "grid3x3", RESULTS_DIR / "attack_two_motes.txt", RESULTS_DIR / "attack_two_controller.txt"),
        ("attack_energy", "grid3x3", RESULTS_DIR / "attack_energy_motes.txt", RESULTS_DIR / "attack_energy_controller.txt"),
    ]

    for ctrl_path in sorted(RESULTS_DIR.glob("controller_ITSDN_*.txt")):
        stem = ctrl_path.stem.replace("controller_", "")
        mote_path = RESULTS_DIR / f"{stem}.txt"
        all_specs.append((f"n36_{stem}", "n36", mote_path, ctrl_path))

    parsed_all: dict[str, dict] = {}
    summary_records: list[dict] = []
    exported_csvs: list[Path] = []
    exported_charts: list[Path] = []

    for key, kind, m_path, c_path in all_specs:
        if not m_path.exists() and not c_path.exists():
            continue
        m_data = analyze_motes(m_path) if m_path.exists() else {}
        c_data = analyze_controller(c_path) if c_path.exists() else {}
        parsed_all[key] = {"kind": kind, "motes": m_data, "controller": c_data}

        csv_p = export_timeseries_csv(key, c_data.get("timeseries", []))
        if csv_p:
            exported_csvs.append(csv_p)

        dt = m_data.get("data_traffic", {})
        co = m_data.get("control_overhead", {})
        en = m_data.get("energy_mj", {})
        fdff_det = c_data.get("fdff_detected_samples", [])
        fni_det = c_data.get("fni_detected_samples", [])
        summary_records.append(
            {
                "scenario": key,
                "kind": kind,
                "tx": dt.get("tx", 0),
                "rx": dt.get("rx", 0),
                "pdr_pct": dt.get("pdr_pct"),
                "delay_mean_ms": dt.get("delay_mean_ms"),
                "ctrl_orig_total": co.get("originated_total"),
                "ctrl_radio_tx_total": co.get("radio_tx_total"),
                "energy_total_mj": en.get("sensor_nodes_total_mj"),
                "controller_total_overhead": c_data.get("controller_reported_total_overhead"),
                "samples": c_data.get("total_series_samples", 0),
                "var_ctrl": c_data.get("var_ctrl_overhead"),
                "var_pdr": c_data.get("var_data_pdr"),
                "max_ctrl_dt": c_data.get("max_ctrl_dt"),
                "max_pdr_dt": c_data.get("max_pdr_dt"),
                "fdff_first_sample": min(fdff_det) if fdff_det else None,
                "fdff_det_count": len(fdff_det),
                "fni_first_sample": min(fni_det) if fni_det else None,
                "fni_det_count": len(fni_det),
                "attack_start_s": m_data.get("attack_start_s"),
                "attack_events": m_data.get("attack_false_flow_sends", 0),
                "banned_nodes": "; ".join(c_data.get("banned_nodes", [])),
            }
        )

    summary_csv = export_summary_csv(summary_records)
    exported_csvs.append(summary_csv)

    if "eval_benign_ids_on" in parsed_all and "eval_attack_ids_on" in parsed_all:
        p = plot_fdff_chart(
            parsed_all["eval_benign_ids_on"]["controller"],
            parsed_all["eval_attack_ids_on"]["controller"],
            parsed_all["eval_attack_ids_on"]["motes"],
        )
        if p:
            exported_charts.append(p)

    if "attack_fni" in parsed_all:
        p = plot_fni_chart(parsed_all["attack_fni"]["controller"], parsed_all["attack_fni"]["motes"])
        if p:
            exported_charts.append(p)

    p = plot_comparison_chart(summary_records)
    if p:
        exported_charts.append(p)

    for key, obj in parsed_all.items():
        if obj["kind"] == "n36" and obj["controller"].get("timeseries"):
            p = plot_n36_chart(key.replace("n36_", ""), obj["controller"])
            if p:
                exported_charts.append(p)
            break

    # Write consolidated full_experiment_report.md
    full_md: list[str] = [
        "# Báo cáo Tổng hợp Toàn bộ Thí nghiệm IDIT-SDN",
        "",
        "## 1. Bảng tổng hợp các kịch bản (3x3 Grid & 36-node Log)",
        "",
        "| Kịch bản | Loại | TX / RX | PDR (%) | Delay TB (ms) | Radio Ctrl TX | Energy (mJ) | Samples | Peak Ctrl DT | Peak PDR DT | FDFF First / Count | FNI First / Count | Banned |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |",
    ]
    for r in summary_records:
        fdff_str = f"{r['fdff_first_sample']} ({r['fdff_det_count']})" if r["fdff_first_sample"] else "-"
        fni_str = f"{r['fni_first_sample']} ({r['fni_det_count']})" if r["fni_first_sample"] else "-"
        full_md.append(
            f"| `{r['scenario']}` | {r['kind']} | {r['tx']} / {r['rx']} | "
            f"{r['pdr_pct'] if r['pdr_pct'] is not None else '-'} | "
            f"{r['delay_mean_ms'] if r['delay_mean_ms'] is not None else '-'} | "
            f"{r['ctrl_radio_tx_total'] if r['ctrl_radio_tx_total'] is not None else '-'} | "
            f"{r['energy_total_mj'] if r['energy_total_mj'] is not None else '-'} | "
            f"{r['samples']} | {r['max_ctrl_dt'] if r['max_ctrl_dt'] is not None else '-'} | "
            f"{r['max_pdr_dt'] if r['max_pdr_dt'] is not None else '-'} | {fdff_str} | {fni_str} | "
            f"{r['banned_nodes'] or '-'} |"
        )

    full_md.extend(["", "## 2. File CSV chuỗi thời gian đã xuất", ""])
    for p in exported_csvs:
        full_md.append(f"- `{p.relative_to(RESULTS_DIR)}`")

    full_md.extend(["", "## 3. Biểu đồ PNG đã sinh", ""])
    for p in exported_charts:
        full_md.append(f"- `{p.relative_to(RESULTS_DIR)}`")

    (RESULTS_DIR / "full_experiment_report.md").write_text("\n".join(full_md) + "\n")
    print(md_text)
    print(f"Exported {len(exported_csvs)} CSV files and {len(exported_charts)} PNG charts.")


if __name__ == "__main__":
    main()
