#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CTRL_BIN="$ROOT_DIR/controller-server/build-controller-pc-iotlab/controller-pc"
RESULTS_DIR="$SCRIPT_DIR/results"

SCENARIO="fdff"
SITE="lille"
BOARD="firefly"
TARGET="remote"
NUM_NODES=9
NODE_LIST=""
DURATION=20
MODE="tunnel"
DRY_RUN=0
EXP_NAME=""

usage() {
  cat <<EOF
Usage: $0 [options]
  --scenario benign|fdff|fni|flood   Experiment scenario (default: fdff)
  --site     lille|grenoble|...      FIT IoT-LAB site (default: lille)
  --board    firefly|m3|remote|...   IoT-LAB hardware board (default: firefly)
  --target   remote|zoul|iotlab-m3   Firmware target directory under build/ (default: remote)
  --num-nodes N                      Total nodes to reserve (default: 9)
  --nodes    id1,id2,...             Explicit comma-separated node IDs (first=controller, second=sink, fifth/last=attacker)
  --duration MIN                     Experiment duration in minutes (default: 20)
  --mode     frontend|tunnel         Controller execution mode (default: tunnel)
  --name     NAME                    Custom experiment name
  --dry-run                          Print commands without calling FIT IoT-LAB API
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --scenario) SCENARIO="$2"; shift 2 ;;
    --site) SITE="$2"; shift 2 ;;
    --board) BOARD="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --num-nodes) NUM_NODES="$2"; shift 2 ;;
    --nodes) NODE_LIST="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --name) EXP_NAME="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

case "$SCENARIO" in
  benign) ATTACK_FW="enabled-node" ;;
  fdff)   ATTACK_FW="attack-fdff" ;;
  fni)    ATTACK_FW="attack-three" ;;
  flood)  ATTACK_FW="attack-two" ;;
  *) echo "Invalid --scenario: $SCENARIO"; exit 1 ;;
esac

FW_DIR="$SCRIPT_DIR/build/$TARGET"
for fw in controller-node sink-node enabled-node "$ATTACK_FW"; do
  if [ ! -f "$FW_DIR/${fw}.${TARGET}" ]; then
    echo "ERROR: Missing firmware $FW_DIR/${fw}.${TARGET}. Run ./build_iotlab.sh $TARGET first."
    exit 1
  fi
done
if [ ! -x "$CTRL_BIN" ]; then
  echo "ERROR: Missing controller binary $CTRL_BIN. Run ./build_iotlab.sh $TARGET first."
  exit 1
fi

ARCHI="${BOARD}:cc2538"
if [ "$BOARD" = "m3" ]; then
  ARCHI="m3:at86rf231"
elif [ "$BOARD" = "openmote" ]; then
  ARCHI="openmote:cc2538"
fi

EXP_NAME="${EXP_NAME:-idit-sdn-${SCENARIO}}"
mkdir -p "$RESULTS_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
MOTE_RAW_LOG="$RESULTS_DIR/iotlab_${SCENARIO}_${SITE}_${STAMP}_raw.log"
CTRL_LOG="$RESULTS_DIR/iotlab_${SCENARIO}_${SITE}_${STAMP}_controller.txt"

if [ -n "$NODE_LIST" ]; then
  IFS=',' read -r -a NODES_ARR <<< "$NODE_LIST"
  NUM_NODES="${#NODES_ARR[@]}"
  CTRL_NODE="${BOARD}-${NODES_ARR[0]}.${SITE}.iot-lab.info"
  SINK_NODE="${BOARD}-${NODES_ARR[1]}.${SITE}.iot-lab.info"
  ATT_NODE="${BOARD}-${NODES_ARR[$((NUM_NODES > 4 ? 4 : NUM_NODES - 1))]}.${SITE}.iot-lab.info"
  NODE_SPEC="${SITE},${BOARD},${NODE_LIST// /,}"
else
  CTRL_NODE="${BOARD}-<id1>.${SITE}.iot-lab.info"
  SINK_NODE="${BOARD}-<id2>.${SITE}.iot-lab.info"
  ATT_NODE="${BOARD}-<id5>.${SITE}.iot-lab.info"
  NODE_SPEC="${NUM_NODES},archi=${ARCHI}+site=${SITE}"
fi

echo "=== FIT IoT-LAB Experiment Plan ==="
echo "Scenario     : $SCENARIO (attacker firmware: $ATTACK_FW.$TARGET)"
echo "Site / Board : $SITE / $BOARD ($ARCHI), $NUM_NODES nodes, ${DURATION} min"
echo "Controller   : $CTRL_NODE (firmware: controller-node.$TARGET)"
echo "Sink         : $SINK_NODE (firmware: sink-node.$TARGET)"
echo "Attacker     : $ATT_NODE (firmware: $ATTACK_FW.$TARGET)"
echo "Other nodes  : enabled-node.$TARGET"
echo "Logs         : $MOTE_RAW_LOG, $CTRL_LOG"

if [ "$DRY_RUN" -eq 1 ]; then
  echo ""
  echo "--- [DRY-RUN] Commands to execute on FIT IoT-LAB ---"
  echo "1) Submit & wait for experiment:"
  echo "   EXP_ID=\$(iotlab-experiment submit -n \"$EXP_NAME\" -d $DURATION -l $NODE_SPEC | jq -r '.id')"
  echo "   iotlab-experiment wait -i \"\$EXP_ID\""
  echo "2) Flash firmwares (controller, sink, attacker, remaining sensor nodes):"
  echo "   iotlab-node --flash \"$FW_DIR/controller-node.$TARGET\" -l ${SITE},${BOARD},<id_ctrl>"
  echo "   iotlab-node --flash \"$FW_DIR/sink-node.$TARGET\" -l ${SITE},${BOARD},<id_sink>"
  echo "   iotlab-node --flash \"$FW_DIR/${ATTACK_FW}.$TARGET\" -l ${SITE},${BOARD},<id_att>"
  echo "   iotlab-node --flash \"$FW_DIR/enabled-node.$TARGET\" -l ${SITE},${BOARD},<other_ids>"
  echo "3) Capture all mote serial logs:"
  echo "   serial_aggregator -i \"\$EXP_ID\" > \"$MOTE_RAW_LOG\" 2>&1 &"
  echo "4) Run controller-pc ($MODE mode):"
  if [ "$MODE" = "frontend" ]; then
    echo "   QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_HOST=$CTRL_NODE SDN_CONTROLLER_PORT=20000 \"$CTRL_BIN\" $NUM_NODES > \"$CTRL_LOG\" 2>&1"
  else
    echo "   # On local host, open SSH tunnel to controller mote port 20000:"
    echo "   ssh -N -L 20000:${CTRL_NODE}:20000 <iotlab_user>@${SITE}.iot-lab.info &"
    echo "   QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_HOST=127.0.0.1 SDN_CONTROLLER_PORT=20000 \"$CTRL_BIN\" $NUM_NODES > \"$CTRL_LOG\" 2>&1"
  fi
  echo "5) Post-process hardware logs into evaluation suite:"
  echo "   python3 \"$SCRIPT_DIR/parse_iotlab_logs.py\" \"$MOTE_RAW_LOG\" -o \"$RESULTS_DIR/iotlab_${SCENARIO}_motes.txt\""
  exit 0
fi

for cmd in iotlab-experiment iotlab-node serial_aggregator python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command '$cmd' not found. Run this on FIT IoT-LAB frontend or use --dry-run."
    exit 1
  fi
done

SUBMIT_JSON=$(iotlab-experiment submit -n "$EXP_NAME" -d "$DURATION" -l "$NODE_SPEC")
EXP_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<< "$SUBMIT_JSON")
echo "Submitted experiment ID: $EXP_ID"
trap 'iotlab-experiment stop -i "$EXP_ID" >/dev/null 2>&1 || true' EXIT

iotlab-experiment wait -i "$EXP_ID"
NODES_JSON=$(iotlab-experiment get -i "$EXP_ID" -n)
ALL_HOSTS=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print("\n".join(sorted(x["network_address"] for x in d["items"])))' <<< "$NODES_JSON")
mapfile -t HOST_ARR <<< "$ALL_HOSTS"

if [ "${#HOST_ARR[@]}" -lt 3 ]; then
  echo "ERROR: Need at least 3 nodes, got ${#HOST_ARR[@]}"
  exit 1
fi

CTRL_HOST="${HOST_ARR[0]}"
SINK_HOST="${HOST_ARR[1]}"
ATT_IDX=$(( ${#HOST_ARR[@]} > 4 ? 4 : ${#HOST_ARR[@]} - 1 ))
ATT_HOST="${HOST_ARR[$ATT_IDX]}"
OTHER_ARGS=()
for i in "${!HOST_ARR[@]}"; do
  if [ "$i" -ne 0 ] && [ "$i" -ne 1 ] && [ "$i" -ne "$ATT_IDX" ]; then
    OTHER_ARGS+=("${HOST_ARR[$i]}")
  fi
done

node_id_of() {
  local h="${1%%.*}"
  echo "${h#${BOARD}-}"
}

echo "Flashing controller ($CTRL_HOST)..."
iotlab-node --flash "$FW_DIR/controller-node.$TARGET" -l "${SITE},${BOARD},$(node_id_of "$CTRL_HOST")"
echo "Flashing sink ($SINK_HOST)..."
iotlab-node --flash "$FW_DIR/sink-node.$TARGET" -l "${SITE},${BOARD},$(node_id_of "$SINK_HOST")"
echo "Flashing attacker/role ($ATT_HOST -> $ATTACK_FW)..."
iotlab-node --flash "$FW_DIR/${ATTACK_FW}.$TARGET" -l "${SITE},${BOARD},$(node_id_of "$ATT_HOST")"
for h in "${OTHER_ARGS[@]}"; do
  iotlab-node --flash "$FW_DIR/enabled-node.$TARGET" -l "${SITE},${BOARD},$(node_id_of "$h")"
done

serial_aggregator -i "$EXP_ID" > "$MOTE_RAW_LOG" 2>&1 &
AGG_PID=$!
trap 'kill "$AGG_PID" 2>/dev/null || true; iotlab-experiment stop -i "$EXP_ID" >/dev/null 2>&1 || true' EXIT

CTRL_TARGET_HOST="$CTRL_HOST"
if [ "$MODE" = "tunnel" ]; then
  CTRL_TARGET_HOST="127.0.0.1"
fi

echo "Starting controller-pc against ${CTRL_TARGET_HOST}:20000 for ${DURATION}m..."
timeout "$((DURATION * 60))" env QT_QPA_PLATFORM=offscreen SDN_CONTROLLER_HOST="$CTRL_TARGET_HOST" SDN_CONTROLLER_PORT=20000 "$CTRL_BIN" "${#HOST_ARR[@]}" > "$CTRL_LOG" 2>&1 || true

kill "$AGG_PID" 2>/dev/null || true
python3 "$SCRIPT_DIR/parse_iotlab_logs.py" "$MOTE_RAW_LOG" -o "$RESULTS_DIR/iotlab_${SCENARIO}_motes.txt"
echo "Experiment finished. Converted motes log: $RESULTS_DIR/iotlab_${SCENARIO}_motes.txt"
