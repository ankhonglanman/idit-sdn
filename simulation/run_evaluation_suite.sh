#!/bin/bash
set -euo pipefail

ROOT_DIR="/root/idit-sdn"
RESULTS_DIR="$ROOT_DIR/simulation/results"
COOJA_DIST="/root/contiki-3.0/tools/cooja/dist"
SIZE_FILE="$RESULTS_DIR/eval_firmware_sizes.txt"

export CONTIKI="${CONTIKI:-/root/contiki-3.0}"

mkdir -p "$RESULTS_DIR" \
  "$ROOT_DIR/applications/attack-demo" \
  "$ROOT_DIR/applications/attack-demo-ids-off" \
  "$ROOT_DIR/controller-server/build-controller-pc-attack-demo" \
  "$ROOT_DIR/controller-server/build-controller-pc-ids-off"

build_firmware_dir() {
  local dir="$1"
  local targets="$2"
  (
    cd "$dir"
    ln -sf ../enabled-node.c enabled-node.c
    ln -sf ../sink-node.c sink-node.c
    ln -sf ../attack-fdff.c attack-fdff.c
    ln -sf ../controller-node.c controller-node.c
    ln -sf ../project-conf.h project-conf.h

    make TARGET=z1 clean -f Makefile_node
    make TARGET=z1 -f Makefile_node $targets
    rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h

    make TARGET=z1 -f Makefile_controller
    rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h
  )
}

echo "[1/5] Building IDS-ON and IDS-OFF Z1 firmwares..."
build_firmware_dir "$ROOT_DIR/applications/attack-demo" "enabled-node sink-node attack-fdff"
build_firmware_dir "$ROOT_DIR/applications/attack-demo-ids-off" "enabled-node sink-node"

{
  echo "# IDS_ON_FIRMWARE"
  size "$ROOT_DIR"/applications/attack-demo/*.z1 | sed 's|/[^ ]*/||g'
  echo "# IDS_OFF_FIRMWARE"
  size "$ROOT_DIR"/applications/attack-demo-ids-off/*.z1 | sed 's|/[^ ]*/||g'
} > "$SIZE_FILE"

echo "[2/5] Building IDS-ON and IDS-OFF controller-pc..."
(
  cd "$ROOT_DIR/controller-server/build-controller-pc-attack-demo"
  qmake ../controller-pc/controller-pc-attack-demo.pro
  make clean
  make -j4
)
(
  cd "$ROOT_DIR/controller-server/build-controller-pc-ids-off"
  qmake ../controller-pc/controller-pc-ids-off.pro
  make clean
  make -j4
)

{
  echo "# CONTROLLER_BINARIES"
  stat -c '%s %n' "$ROOT_DIR/controller-server/build-controller-pc-attack-demo/controller-pc"
  stat -c '%s %n' "$ROOT_DIR/controller-server/build-controller-pc-ids-off/controller-pc"
} >> "$SIZE_FILE"

CTRL_PID=""
COOJA_PID=""
cleanup() {
  if [ -n "$CTRL_PID" ] && kill -0 "$CTRL_PID" 2>/dev/null; then
    kill "$CTRL_PID" 2>/dev/null || true
    wait "$CTRL_PID" 2>/dev/null || true
  fi
  if [ -n "$COOJA_PID" ] && kill -0 "$COOJA_PID" 2>/dev/null; then
    kill "$COOJA_PID" 2>/dev/null || true
    wait "$COOJA_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

run_scenario() {
  local name="$1"
  local csc_file="$2"
  local ctrl_bin="$3"

  local cooja_log="$RESULTS_DIR/eval_${name}_cooja.txt"
  local motes_log="$RESULTS_DIR/eval_${name}_motes.txt"
  local ctrl_log="$RESULTS_DIR/eval_${name}_controller.txt"
  rm -f "$cooja_log" "$motes_log" "$ctrl_log"

  echo ">>> Running scenario: $name"
  cd "$COOJA_DIST"
  java -mx2048m -jar cooja.jar -nogui="$csc_file" > "$cooja_log" 2>&1 &
  COOJA_PID=$!

  while [ ! -f "$cooja_log" ]; do
    if ! kill -0 "$COOJA_PID" 2>/dev/null; then
      echo "ERROR: Cooja exited before creating $cooja_log"
      exit 1
    fi
    sleep 0.5
  done

  while [ "$(grep -c "Listening on port: 60010" "$cooja_log" || true)" -ne 1 ]; do
    if ! kill -0 "$COOJA_PID" 2>/dev/null; then
      echo "ERROR: Cooja exited before opening port 60010:"
      cat "$cooja_log"
      exit 1
    fi
    sleep 0.5
  done

  QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_PORT=60010 "$ctrl_bin" 9 > "$ctrl_log" 2>&1 &
  CTRL_PID=$!

  wait "$COOJA_PID" || true
  COOJA_PID=""
  if [ -n "$CTRL_PID" ] && kill -0 "$CTRL_PID" 2>/dev/null; then
    kill "$CTRL_PID" 2>/dev/null || true
    wait "$CTRL_PID" 2>/dev/null || true
  fi
  CTRL_PID=""
  sleep 1
}

echo "[3/5] Running Scenario 1/3: Benign (IDS OFF)..."
run_scenario "benign_ids_off" \
  "$ROOT_DIR/simulation/eval_benign_ids_off_z1.csc" \
  "$ROOT_DIR/controller-server/build-controller-pc-ids-off/controller-pc"

echo "[4/5] Running Scenario 2/3: Benign (IDS ON)..."
run_scenario "benign_ids_on" \
  "$ROOT_DIR/simulation/eval_benign_ids_on_z1.csc" \
  "$ROOT_DIR/controller-server/build-controller-pc-attack-demo/controller-pc"

echo "[5/5] Running Scenario 3/3: FDFF Attack (IDS ON)..."
run_scenario "attack_ids_on" \
  "$ROOT_DIR/simulation/eval_attack_ids_on_z1.csc" \
  "$ROOT_DIR/controller-server/build-controller-pc-attack-demo/controller-pc"

cd "$ROOT_DIR/simulation"
python3 "$ROOT_DIR/simulation/evaluate_ids.py"
