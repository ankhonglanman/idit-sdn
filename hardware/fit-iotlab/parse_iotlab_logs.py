#!/usr/bin/env python3
"""Convert FIT IoT-LAB serial_aggregator logs (<ts>;<node>;<msg>) to Cooja motes log format."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

LINE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?);([^;]+);(.*)$")
NODE_NUM_RE = re.compile(r"(\d+)$")


def convert_iotlab_log(raw_text: str) -> str:
    lines_out: list[str] = []
    t0: float | None = None
    node_map: dict[str, int] = {}
    next_id = 1

    for raw in raw_text.splitlines():
        m = LINE_RE.match(raw)
        if not m:
            continue
        ts_s = float(m.group(1))
        node_name = m.group(2).strip()
        msg = m.group(3)

        if t0 is None:
            t0 = ts_s
        rel_us = max(0, int(round((ts_s - t0) * 1_000_000)))

        if node_name not in node_map:
            num_m = NODE_NUM_RE.search(node_name)
            if num_m:
                node_map[node_name] = int(num_m.group(1))
            else:
                node_map[node_name] = next_id
                next_id += 1
        mote_id = node_map[node_name]
        lines_out.append(f"{rel_us}:{mote_id}:{msg}")

    return "\n".join(lines_out) + ("\n" if lines_out else "")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path, help="Input serial_aggregator log file")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output Cooja-compatible motes log")
    args = ap.parse_args()

    converted = convert_iotlab_log(args.input.read_text(errors="replace"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(converted)
    print(f"Converted {len(converted.splitlines())} lines -> {args.output}")


if __name__ == "__main__":
    main()
