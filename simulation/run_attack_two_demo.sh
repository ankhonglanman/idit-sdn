#!/bin/bash
set -euo pipefail

ROOT_DIR="/root/idit-sdn"
APP_TWO_DIR="$ROOT_DIR/applications/attack-two-demo"
CTRL_BUILD_DIR="$ROOT_DIR/controller-server/build-controller-pc-attack-demo"
RESULTS_DIR="$ROOT_DIR/simulation/results"
CSC_FILE="$ROOT_DIR/simulation/attack_two_z1.csc"
COOJA_DIST="/root/contiki-3.0/tools/cooja/dist"

COOJA_LOG="$RESULTS_DIR/attack_two_cooja.txt"
MOTES_LOG="$RESULTS_DIR/attack_two_motes.txt"
CTRL_LOG="$RESULTS_DIR/attack_two_controller.txt"

export CONTIKI="${CONTIKI:-/root/contiki-3.0}"

mkdir -p "$APP_TWO_DIR" "$CTRL_BUILD_DIR" "$RESULTS_DIR"
rm -f "$COOJA_LOG" "$MOTES_LOG" "$CTRL_LOG"

echo "[1/4] Preparing symlinks and compiling Z1 firmwares for Request Flood (attack-two)..."
(
  cd "$APP_TWO_DIR"
  ln -sf ../enabled-node.c enabled-node.c
  ln -sf ../sink-node.c sink-node.c
  ln -sf ../attack-two.c attack-two.c
  ln -sf ../controller-node.c controller-node.c
  ln -sf ../project-conf.h project-conf.h

  make TARGET=z1 clean -f Makefile_node
  make TARGET=z1 -f Makefile_node enabled-node sink-node attack-two
  rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h

  make TARGET=z1 -f Makefile_controller
  rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h
  size *.z1
)

echo "[2/4] Ensuring controller-pc-attack-demo is built..."
(
  cd "$CTRL_BUILD_DIR"
  qmake ../controller-pc/controller-pc-attack-demo.pro
  make -j4
)

echo "[3/4] Starting Cooja headless simulation (port 60012, timeout 2000s simulated)..."
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

while [ "$(grep -c "Listening on port: 60012" "$COOJA_LOG" || true)" -ne 1 ]; do
  if ! kill -0 "$COOJA_PID" 2>/dev/null; then
    echo "ERROR: Cooja exited before opening port 60012:"
    cat "$COOJA_LOG"
    exit 1
  fi
  sleep 0.5
done

echo "[4/4] Connecting controller-pc (port 60012) and waiting for simulation completion..."
QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_PORT=60012 "$CTRL_BUILD_DIR/controller-pc" 9 > "$CTRL_LOG" 2>&1 &
CTRL_PID=$!

wait "$COOJA_PID" || true
COOJA_PID=""
cleanup
cd "$ROOT_DIR/simulation"

echo "=== Request Flood (attack-two) Simulation Summary ==="
echo "--- False Flow Requests (Node 5) ---"
grep -m 10 "Sending false flow request:" "$MOTES_LOG" || true
echo "--- Control Overhead & Centralized Detection ---"
grep -E "Control overhead =|DT:|CP detected in|FDFF attack detected" "$CTRL_LOG" | tail -n 50 || true
