#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  Vector Daemon — Steady-State Performance Benchmark
# ═══════════════════════════════════════════════════════════════════════
#  Starts Vector as a daemon, feeds continuous Kafka load, scrapes
#  its blackhole sink output every second for a configurable
#  measurement window, then prints a full report.
#
#  Usage:  ./vector.sh [DURATION_SECS]    (default: 30)
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

DURATION=${1:-30}
INPUT_LOG="auth_1m.log"
VECTOR_CFG="/home/shabh/.vector/config/vector.yaml"
VECTOR_BIN="/home/shabh/.vector/bin/vector"
KAFKA_TOPIC="raw-logs"

SUDO_CMD="sudo"
LOG_DIR="/tmp/vector_daemon_$$"
mkdir -p "$LOG_DIR"
VECTOR_LOG="${LOG_DIR}/vector.log"

cleanup() {
    echo
    echo "[CLEANUP] Stopping load generator and Vector..."
    kill "${PRODUCER_PID:-}" 2>/dev/null || true
    kill "${VECTOR_PID:-}" 2>/dev/null || true
    sleep 1
    kill -9 "${VECTOR_PID:-}" 2>/dev/null || true
    rm -rf "$LOG_DIR"
}
trap cleanup EXIT

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            Vector Daemon Steady-State Benchmark              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Measurement Window : ${DURATION}s                                   ║"
echo "║  Input Log          : ${INPUT_LOG}                          ║"
echo "║  Vector Config      : vector.yaml (VRL + blackhole)         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# ── 1. Ensure Kafka is running ────────────────────────────────────────
if ! $SUDO_CMD docker ps 2>/dev/null | grep -q kafka-bench; then
    echo "[SETUP] Starting Kafka..."
    $SUDO_CMD docker compose up -d kafka
    sleep 5
fi

# ── 2. Recreate topic ────────────────────────────────────────────────
echo "[SETUP] Recreating topic: $KAFKA_TOPIC..."
$SUDO_CMD docker exec kafka-bench \
    /opt/bitnami/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --delete --topic "$KAFKA_TOPIC" 2>/dev/null || true
sleep 2
$SUDO_CMD docker exec kafka-bench \
    /opt/bitnami/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --topic "$KAFKA_TOPIC" \
    --partitions 3 --replication-factor 1 \
    --config retention.ms=300000 \
    --config segment.bytes=52428800 \
    2>/dev/null || true

# ── 3. Clean Vector state and start daemon ────────────────────────────
echo "[DAEMON] Cleaning Vector state..."
$SUDO_CMD rm -rf /var/lib/vector/* 2>/dev/null || true

echo "[DAEMON] Starting Vector..."
$VECTOR_BIN --config "$VECTOR_CFG" >"$VECTOR_LOG" 2>&1 &
VECTOR_PID=$!
disown $VECTOR_PID

# Wait for Vector to start
sleep 3

if ! kill -0 $VECTOR_PID 2>/dev/null; then
    echo "[ERROR] Vector failed to start. Log:"
    cat "$VECTOR_LOG"
    exit 1
fi
echo "[DAEMON] Vector running on PID $VECTOR_PID"

# ── 4. Start continuous load generator ────────────────────────────────
echo "[LOAD] Starting continuous Kafka producer (looping $INPUT_LOG)..."
(
    while true; do
        cat "$INPUT_LOG"
    done | $SUDO_CMD docker exec -i kafka-bench \
        /opt/bitnami/kafka/bin/kafka-console-producer.sh \
        --bootstrap-server localhost:9092 \
        --topic "$KAFKA_TOPIC" >/dev/null 2>&1
) &
PRODUCER_PID=$!
disown $PRODUCER_PID

# ── 5. Warm-up period ────────────────────────────────────────────────
echo "[WARMUP] Waiting 10s for pipeline to reach steady state..."
sleep 10

# ── 6. Measurement phase ─────────────────────────────────────────────
echo "[MEASURE] Collecting metrics every 1s for ${DURATION}s..."

# Parse the latest event count from Vector's blackhole log output.
# Vector logs lines like:
#   ... INFO vector::sinks::blackhole::sink: Collected events. events=12345 raw_bytes_collected=...
get_vector_total() {
    # Get the last blackhole log line and extract the events count
    grep "Collected events" "$VECTOR_LOG" 2>/dev/null | tail -1 | \
        sed -n 's/.*events=\([0-9]*\).*/\1/p' || echo 0
}

# Snapshot starting total
start_total=$(get_vector_total)

SAMPLES_FILE="${LOG_DIR}/samples.csv"
echo "second,total_consumed,cpu_pct,rss_kb" > "$SAMPLES_FILE"

for sec in $(seq 1 $DURATION); do
    sleep 1

    combined_total=$(get_vector_total)

    # Get CPU% and RSS for Vector process
    cpu_mem=$(ps -p $VECTOR_PID -o %cpu=,rsz= --no-headers 2>/dev/null | \
        awk '{printf "%.1f,%d", $1, $2}' 2>/dev/null || echo "0.0,0")

    cpu_pct=$(echo "$cpu_mem" | cut -d, -f1)
    rss_kb=$(echo "$cpu_mem" | cut -d, -f2)

    echo "${sec},${combined_total},${cpu_pct},${rss_kb}" >> "$SAMPLES_FILE"
    printf "\r  [%3d/%ds] Total: %s events | CPU: %s%% | RSS: %d KB" \
        "$sec" "$DURATION" "$combined_total" "$cpu_pct" "$rss_kb"
done

echo  # newline after progress

# Snapshot ending total
end_total=$(get_vector_total)

# ── 7. Compute final stats ────────────────────────────────────────────
RESULTS=$(python3 - <<EOF
import csv

samples = []
with open("${SAMPLES_FILE}") as f:
    reader = csv.DictReader(f)
    for row in reader:
        samples.append({
            "second": int(row["second"]),
            "total": int(row["total_consumed"]),
            "cpu": float(row["cpu_pct"]),
            "rss": int(row["rss_kb"]),
        })

start_total = ${start_total}
end_total = ${end_total}
duration = ${DURATION}

events_during_window = end_total - start_total
steady_eps = int(events_during_window / duration) if duration > 0 else 0

# Per-second EPS from deltas
eps_list = []
for i in range(1, len(samples)):
    delta = samples[i]["total"] - samples[i-1]["total"]
    if delta > 0:
        eps_list.append(delta)

avg_eps = int(sum(eps_list) / len(eps_list)) if eps_list else 0
peak_sec_eps = max(eps_list) if eps_list else 0
min_sec_eps = min(eps_list) if eps_list else 0

avg_cpu = sum(s["cpu"] for s in samples) / len(samples) if samples else 0
avg_rss_mb = (sum(s["rss"] for s in samples) / len(samples)) / 1024 if samples else 0
peak_rss_mb = max(s["rss"] for s in samples) / 1024 if samples else 0

print(f"{events_during_window},{steady_eps},{avg_eps},{peak_sec_eps},{min_sec_eps},{avg_cpu:.1f},{avg_rss_mb:.1f},{peak_rss_mb:.1f}")
EOF
)

IFS=',' read -r EVENTS STEADY_EPS AVG_EPS PEAK_SEC MIN_SEC AVG_CPU AVG_RSS PEAK_RSS <<< "$RESULTS"

echo
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              VECTOR STEADY-STATE RESULTS                     ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Measurement Window  : $(printf "%-37s" "${DURATION}s")║"
echo "║  Events Processed    : $(printf "%-37s" "${EVENTS}")║"
echo "║  Steady-State EPS    : $(printf "%-37s" "${STEADY_EPS} events/sec")║"
echo "║  Avg Per-Second EPS  : $(printf "%-37s" "${AVG_EPS} events/sec")║"
echo "║  Peak Per-Second EPS : $(printf "%-37s" "${PEAK_SEC} events/sec")║"
echo "║  Min  Per-Second EPS : $(printf "%-37s" "${MIN_SEC} events/sec")║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Avg CPU (1 proc)    : $(printf "%-37s" "${AVG_CPU}%")║"
echo "║  Avg RSS             : $(printf "%-37s" "${AVG_RSS} MB")║"
echo "║  Peak RSS            : $(printf "%-37s" "${PEAK_RSS} MB")║"
echo "║  CPU Efficiency      : $(printf "%-37s" "$(python3 -c "print(f'{int(${STEADY_EPS}/(${AVG_CPU}/100)) if float(\"${AVG_CPU}\") > 0 else 0} EPS/core')")")║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo
