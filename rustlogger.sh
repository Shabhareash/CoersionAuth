#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  RustLogger Daemon — Steady-State Performance Benchmark
# ═══════════════════════════════════════════════════════════════════════
#  Starts 3 daemon instances (one per partition), feeds continuous
#  Kafka load, scrapes the HTTP /metrics endpoints every second for
#  a configurable measurement window, then prints a full report.
#
#  Usage:  ./rustlogger.sh [DURATION_SECS]    (default: 30)
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

DURATION=${1:-30}
INPUT_LOG="auth_1m.log"
RUST_YAML="auth.yaml"
KAFKA_TOPIC="raw-logs"
BASE_METRICS_PORT=9093   # ports 9093, 9094, 9095 for the 3 consumers

export RAYON_NUM_THREADS=2
export TOKIO_WORKER_THREADS=2

SUDO_CMD="sudo"
LOG_DIR="/mnt/win_ssd/rustlogger_daemon_$$"
mkdir -p "$LOG_DIR"

cleanup() {
    echo
    echo "[CLEANUP] Stopping load generator and daemons..."
    kill "${PRODUCER_PID:-}" 2>/dev/null || true
    for pid in "${DAEMON_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Give them a moment to flush
    sleep 1
    for pid in "${DAEMON_PIDS[@]:-}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    rm -rf "$LOG_DIR"
}
trap cleanup EXIT

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         RustLogger Daemon Steady-State Benchmark             ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Measurement Window : ${DURATION}s                                    ║"
echo "║  Input Log          : ${INPUT_LOG}                            ║"
echo "║  Partitions         : 3                                      ║"
echo "║  Metrics Ports      : 9093, 9094, 9095                       ║"
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

# ── 3. Start 3 RustLogger daemon instances ───────────────────────────
echo "[DAEMON] Starting 3 RustLogger daemon consumers..."
DAEMON_PIDS=()

for id in 0 1 2; do
    port=$((BASE_METRICS_PORT + id))
    DAEMON=1 \
    METRICS_PORT=$port \
    KAFKA_BROKER="localhost:9092" \
    KAFKA_TOPIC="$KAFKA_TOPIC" \
    KAFKA_GROUP="rustlogger-daemon" \
    KAFKA_PARTITION="$id" \
    WRITE_TO_STDOUT=1 \
        ./target/release/kafka_pipeline "$RUST_YAML" \
        > /dev/null \
        2> "${LOG_DIR}/consumer_${id}.log" &
    pid=$!
    DAEMON_PIDS+=($pid)
    disown $pid
    echo "  → Consumer $id (partition $id) started on PID $pid, metrics at :$port"
done

# Wait for HTTP servers to be ready
echo "[DAEMON] Waiting for metrics endpoints..."
sleep 3

for port in $BASE_METRICS_PORT $((BASE_METRICS_PORT+1)) $((BASE_METRICS_PORT+2)); do
    for attempt in $(seq 1 10); do
        if curl -s --connect-timeout 1 "http://localhost:${port}/metrics" >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
done
echo "[DAEMON] All 3 consumers running."

# ── 4. Start continuous load generator ────────────────────────────────
echo "[LOAD] Starting continuous native Rust Kafka producer (looping $INPUT_LOG)..."
(
    while true; do
        ./target/release/kafka_producer "$INPUT_LOG" "$KAFKA_TOPIC" 10 "localhost:9092" >/dev/null 2>&1
    done
) &
PRODUCER_PID=$!
disown $PRODUCER_PID

# ── 5. Warm-up period ────────────────────────────────────────────────
echo "[WARMUP] Waiting 10s for pipeline to reach steady state..."
sleep 10

# ── 6. Measurement phase ─────────────────────────────────────────────
echo "[MEASURE] Collecting metrics every 1s for ${DURATION}s..."

# Snapshot the starting totals from all 3 consumers
start_total=0
for port in $BASE_METRICS_PORT $((BASE_METRICS_PORT+1)) $((BASE_METRICS_PORT+2)); do
    val=$(curl -s "http://localhost:${port}/metrics" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['total_consumed'])" 2>/dev/null || echo 0)
    start_total=$((start_total + val))
done

# Collect per-second CPU/memory snapshots
SAMPLES_FILE="${LOG_DIR}/samples.csv"
echo "second,total_consumed,cpu_pct,rss_kb" > "$SAMPLES_FILE"

for sec in $(seq 1 $DURATION); do
    sleep 1

    # Query metrics from all 3 endpoints
    combined_total=0
    for port in $BASE_METRICS_PORT $((BASE_METRICS_PORT+1)) $((BASE_METRICS_PORT+2)); do
        val=$(curl -s --connect-timeout 1 "http://localhost:${port}/metrics" 2>/dev/null | \
              python3 -c "import sys,json; print(json.load(sys.stdin)['total_consumed'])" 2>/dev/null || echo 0)
        combined_total=$((combined_total + val))
    done

    # Get CPU% and RSS for all kafka_pipeline processes
    cpu_mem=$(ps -C kafka_pipeline -o %cpu=,rsz= --no-headers 2>/dev/null | \
        awk '{cpu+=$1; rss+=$2} END {printf "%.1f,%d", cpu, rss}' 2>/dev/null || echo "0.0,0")

    cpu_pct=$(echo "$cpu_mem" | cut -d, -f1)
    rss_kb=$(echo "$cpu_mem" | cut -d, -f2)

    echo "${sec},${combined_total},${cpu_pct},${rss_kb}" >> "$SAMPLES_FILE"
    printf "\r  [%3d/%ds] Total: %d events | CPU: %s%% | RSS: %d KB" \
        "$sec" "$DURATION" "$combined_total" "$cpu_pct" "$rss_kb"
done

echo  # newline after progress

# Snapshot the ending totals
end_total=0
for port in $BASE_METRICS_PORT $((BASE_METRICS_PORT+1)) $((BASE_METRICS_PORT+2)); do
    val=$(curl -s "http://localhost:${port}/metrics" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['total_consumed'])" 2>/dev/null || echo 0)
    end_total=$((end_total + val))
done

# Get peak EPS from all consumers
peak_eps=0
for port in $BASE_METRICS_PORT $((BASE_METRICS_PORT+1)) $((BASE_METRICS_PORT+2)); do
    val=$(curl -s "http://localhost:${port}/metrics" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['peak_eps'])" 2>/dev/null || echo 0)
    peak_eps=$((peak_eps + val))
done

# ── 7. Compute final stats ────────────────────────────────────────────
python3 - <<EOF
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
combined_peak = ${peak_eps}

cpu_eff = int(steady_eps / (avg_cpu / 100)) if avg_cpu > 0 else 0

WIDTH = 62
print()
print("╔" + "═" * WIDTH + "╗")
print(f"║{'RUSTLOGGER STEADY-STATE RESULTS':^{WIDTH}}║")
print("╠" + "═" * WIDTH + "╣")

def row(label, val):
    print(f"║  {label:<19} : {str(val):<38}║")

row("Measurement Window", f"{duration}s")
row("Events Processed", f"{events_during_window:,}")
row("Steady-State EPS", f"{steady_eps:,} events/sec")
row("Avg Per-Second EPS", f"{avg_eps:,} events/sec")
row("Peak Per-Second EPS", f"{peak_sec_eps:,} events/sec")
row("Min Per-Second EPS", f"{min_sec_eps:,} events/sec")
row("Combined Peak EPS", f"{combined_peak:,} events/sec")
print("╠" + "═" * WIDTH + "╣")
row("Avg CPU (3 procs)", f"{avg_cpu:.1f}%")
row("Avg RSS (3 procs)", f"{avg_rss_mb:.1f} MB")
row("Peak RSS", f"{peak_rss_mb:.1f} MB")
row("CPU Efficiency", f"{cpu_eff:,} EPS/core")
print("╚" + "═" * WIDTH + "╝")
print()
EOF
