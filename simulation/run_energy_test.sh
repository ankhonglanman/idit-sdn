#!/bin/bash
set -euo pipefail

ROOT_DIR="/root/idit-sdn"
APP_ENERGY_DIR="$ROOT_DIR/applications/attack-energy"
CTRL_BUILD_DIR="$ROOT_DIR/controller-server/build-controller-pc-attack-demo"
RESULTS_DIR="$ROOT_DIR/simulation/results"
CSC_FILE="$ROOT_DIR/simulation/attack_energy_z1.csc"
COOJA_DIST="/root/contiki-3.0/tools/cooja/dist"

COOJA_LOG="$RESULTS_DIR/attack_energy_cooja.txt"
MOTES_LOG="$RESULTS_DIR/attack_energy_motes.txt"
CTRL_LOG="$RESULTS_DIR/attack_energy_controller.txt"

export CONTIKI="${CONTIKI:-/root/contiki-3.0}"

mkdir -p "$APP_ENERGY_DIR" "$CTRL_BUILD_DIR" "$RESULTS_DIR"
rm -f "$COOJA_LOG" "$MOTES_LOG" "$CTRL_LOG"

echo "[1/4] Verifying standalone -DENERGY compile (without -DTRANS_TS)..."
(
  cd "$APP_ENERGY_DIR"
  ln -sf ../enabled-node.c enabled-node.c
  ln -sf ../sink-node.c sink-node.c
  ln -sf ../attack-fdff.c attack-fdff.c
  ln -sf ../controller-node.c controller-node.c
  ln -sf ../project-conf.h project-conf.h

  sed 's/CFLAGS += -DTRANS_TS/# CFLAGS += -DTRANS_TS/' Makefile_node > Makefile_energy_only
  make TARGET=z1 clean -f Makefile_energy_only
  make TARGET=z1 -f Makefile_energy_only enabled-node
  size enabled-node.z1
  rm -f Makefile_energy_only
  rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h
)

echo "[2/4] Compiling Z1 firmwares with both -DTRANS_TS and -DENERGY..."
(
  cd "$APP_ENERGY_DIR"
  make TARGET=z1 clean -f Makefile_node
  make TARGET=z1 -f Makefile_node enabled-node sink-node attack-fdff
  rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h

  make TARGET=z1 -f Makefile_controller
  rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h
  size *.z1
)

echo "[3/4] Ensuring controller-pc-attack-demo is built..."
(
  cd "$CTRL_BUILD_DIR"
  qmake ../controller-pc/controller-pc-attack-demo.pro
  make -j4
)

echo "[4/4] Running Cooja headless simulation on port 60013 (1800s simulated)..."
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

cd "$COOJA_DIST"
java -Djava.awt.headless=true -mx2048m -jar cooja.jar -nogui="$CSC_FILE" > "$COOJA_LOG" 2>&1 &
COOJA_PID=$!

while [ ! -f "$COOJA_LOG" ]; do
  if ! kill -0 "$COOJA_PID" 2>/dev/null; then
    echo "ERROR: Cooja exited before creating $COOJA_LOG"
    exit 1
  fi
  sleep 0.5
done

while [ "$(grep -c "Listening on port: 60013" "$COOJA_LOG" || true)" -ne 1 ]; do
  if ! kill -0 "$COOJA_PID" 2>/dev/null; then
    echo "ERROR: Cooja exited before opening port 60013:"
    cat "$COOJA_LOG"
    exit 1
  fi
  sleep 0.5
done

QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_PORT=60013 "$CTRL_BUILD_DIR/controller-pc" 9 > "$CTRL_LOG" 2>&1 &
CTRL_PID=$!

wait "$COOJA_PID" || true
COOJA_PID=""
cleanup
cd "$ROOT_DIR/simulation"

echo "=== Energy Validation Summary ==="
echo "--- Sample 0..20 (Transmitting time & Consumption mJ) ---"
grep -E "Sample: [0-9]+, (Transmitting time|Consumption \(mJ\)):" "$MOTES_LOG" | head -n 45 || true
echo "--- CP & Attack detection ---"
grep -E "CP detected in|FDFF attack detected|Attacker indentified|Banned: YES" "$MOTES_LOG" "$CTRL_LOG" | head -n 30 || true
