#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_DIR="$ROOT_DIR/applications"
CTRL_BUILD_DIR="$ROOT_DIR/controller-server/build-controller-pc-iotlab"

TARGET="${1:-remote}"
BOARD="${BOARD:-}"
RF_CHANNEL="${RF_CHANNEL:-22}"
PAN_ID="${PAN_ID:-0x1D17}"
USE_NULLRDC="${USE_NULLRDC:-0}"
TX_POWER="${TX_POWER:-}"

export CONTIKI="${CONTIKI:-/root/contiki-3.0}"

OUT_DIR="$SCRIPT_DIR/build/$TARGET"
mkdir -p "$OUT_DIR" "$CTRL_BUILD_DIR"

MAKE_ARGS=(
  "TARGET=$TARGET"
  "RF_CHANNEL=$RF_CHANNEL"
  "PAN_ID=$PAN_ID"
  "USE_NULLRDC=$USE_NULLRDC"
)
if [ -n "$BOARD" ]; then
  MAKE_ARGS+=("BOARD=$BOARD")
fi
if [ -n "$TX_POWER" ]; then
  MAKE_ARGS+=("TX_POWER=$TX_POWER")
fi

echo "=== Building IDIT-SDN FIT IoT-LAB firmwares ==="
echo "TARGET=$TARGET BOARD=${BOARD:-default} RF_CHANNEL=$RF_CHANNEL PAN_ID=$PAN_ID CONTIKI=$CONTIKI"

cd "$SCRIPT_DIR"
ln -sf "$APP_DIR/enabled-node.c" enabled-node.c
ln -sf "$APP_DIR/sink-node.c" sink-node.c
ln -sf "$APP_DIR/attack-fdff.c" attack-fdff.c
ln -sf "$APP_DIR/attack-two.c" attack-two.c
ln -sf "$APP_DIR/attack-three.c" attack-three.c
ln -sf "$APP_DIR/attack.h" attack.h
ln -sf "$APP_DIR/controller-node.c" controller-node.c

clean_intermediate() {
  rm -rf "obj_$TARGET" "contiki-$TARGET.a" "contiki-$TARGET.map" symbols.c symbols.h *.co
}

echo "[1/4] Building enabled-node, sink-node, attack-fdff, attack-two..."
make -f Makefile_node "${MAKE_ARGS[@]}" clean || true
clean_intermediate
make -f Makefile_node "${MAKE_ARGS[@]}" enabled-node sink-node attack-fdff attack-two
clean_intermediate

echo "[2/4] Building attack-three (FNI)..."
make -f Makefile_intrusion "${MAKE_ARGS[@]}" attack-three
clean_intermediate

echo "[3/4] Building controller-node..."
make -f Makefile_controller "${MAKE_ARGS[@]}" controller-node
clean_intermediate

for app in enabled-node sink-node attack-fdff attack-two attack-three controller-node; do
  if [ -f "${app}.${TARGET}" ]; then
    cp -f "${app}.${TARGET}" "$OUT_DIR/${app}.${TARGET}"
    cp -f "${app}.${TARGET}" "$OUT_DIR/${app}.elf"
  fi
  if [ -f "${app}.bin" ]; then
    cp -f "${app}.bin" "$OUT_DIR/${app}.bin"
  fi
done

echo "--- Firmware sizes ($OUT_DIR) ---"
if command -v arm-none-eabi-size >/dev/null 2>&1 && [[ "$TARGET" != "z1" && "$TARGET" != "sky" ]]; then
  arm-none-eabi-size "$OUT_DIR"/*."$TARGET"
else
  size "$OUT_DIR"/*."$TARGET"
fi

echo "[4/4] Building controller-pc-iotlab (MTENSEC, S_SKIP=25, M_WIN=45)..."
(
  cd "$CTRL_BUILD_DIR"
  qmake ../controller-pc/controller-pc-iotlab.pro
  make -j4
  ls -lh controller-pc
)

echo "Build complete. Outputs in $OUT_DIR and $CTRL_BUILD_DIR/controller-pc"
