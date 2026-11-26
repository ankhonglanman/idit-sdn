#!/bin/bash
set -euo pipefail

ROOT_DIR="/root/idit-sdn"
APP_DEMO_DIR="$ROOT_DIR/applications/attack-demo"
CTRL_BUILD_DIR="$ROOT_DIR/controller-server/build-controller-pc-attack-demo"
RESULTS_DIR="$ROOT_DIR/simulation/results"
CSC_FILE="$ROOT_DIR/simulation/attack_fdff_demo_z1.csc"
COOJA_DIST="/root/contiki-3.0/tools/cooja/dist"

COOJA_LOG="$RESULTS_DIR/attack_demo_cooja.txt"
MOTES_LOG="$RESULTS_DIR/attack_demo_motes.txt"
CTRL_LOG="$RESULTS_DIR/attack_demo_controller.txt"

export CONTIKI="${CONTIKI:-/root/contiki-3.0}"

mkdir -p "$APP_DEMO_DIR" "$CTRL_BUILD_DIR" "$RESULTS_DIR"
rm -f "$COOJA_LOG" "$MOTES_LOG" "$CTRL_LOG"

echo "[1/4] Preparing symlinks and compiling Z1 firmwares for FDFF attack demo..."
(
  cd "$APP_DEMO_DIR"
  ln -sf ../enabled-node.c enabled-node.c
  ln -sf ../sink-node.c sink-node.c
  ln -sf ../attack-fdff.c attack-fdff.c
  ln -sf ../controller-node.c controller-node.c
  ln -sf ../project-conf.h project-conf.h

  make TARGET=z1 clean -f Makefile_node
  make TARGET=z1 -f Makefile_node enabled-node sink-node attack-fdff
  rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h

  make TARGET=z1 -f Makefile_controller
  rm -rf obj_z1 contiki-z1.a contiki-z1.map symbols.c symbols.h
  ls -lh *.z1
)

echo "[2/4] Compiling controller-pc for attack demo (10s sampling, S_SKIP=35, M_WIN=60)..."
(
  cd "$CTRL_BUILD_DIR"
  qmake ../controller-pc/controller-pc-attack-demo.pro
  make clean
  make -j4
  ls -lh controller-pc
)

echo "[3/4] Starting Cooja headless simulation (port 60010, timeout 2000s simulated)..."
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
java -mx2048m -jar cooja.jar -nogui="$CSC_FILE" > "$COOJA_LOG" 2>&1 &
COOJA_PID=$!

while [ ! -f "$COOJA_LOG" ]; do
  if ! kill -0 "$COOJA_PID" 2>/dev/null; then
    echo "ERROR: Cooja exited before creating $COOJA_LOG"
    exit 1
  fi
  sleep 0.5
done

while [ "$(grep -c "Listening on port: 60010" "$COOJA_LOG" || true)" -ne 1 ]; do
  if ! kill -0 "$COOJA_PID" 2>/dev/null; then
    echo "ERROR: Cooja exited before opening port 60010. Cooja log:"
    cat "$COOJA_LOG"
    exit 1
  fi
  sleep 0.5
done

echo "[4/4] Connecting controller-pc (port 60010) and waiting for simulation completion..."
QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_PORT=60010 "$CTRL_BUILD_DIR/controller-pc" 9 > "$CTRL_LOG" 2>&1 &
CTRL_PID=$!

wait "$COOJA_PID" || true
COOJA_PID=""
cleanup
cd "$ROOT_DIR/simulation"

echo "=== Simulation Complete: Summary ==="
echo "--- Attack injection (Node 5) ---"
grep -m 10 "Sending data to false flow:" "$MOTES_LOG" || true
echo "--- Distributed detection (Neighbor nodes) ---"
grep -E "Adding suspect:|CP detected in|Sending CP detection alarm" "$MOTES_LOG" | head -n 30 || true
echo "--- Centralized & Blocklist detection (Controller) ---"
grep -E "Control overhead =|CP detected in|CP not detected|DT:|FDFF attack detected|FNI attack detected|First suspect|New suspect|New alarm|Attacker indentified|included in Blocklist|Banned:" "$CTRL_LOG" | head -n 80 || true
