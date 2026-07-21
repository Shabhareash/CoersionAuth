#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  RustLogger Peak Throughput Benchmark (Parsing Only)
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

# Limit threads per consumer to prevent CPU thrashing
export RAYON_NUM_THREADS=2
export TOKIO_WORKER_THREADS=2

INPUT_LOG="OpenSSH_200k.log"
YAML_CONFIG="ssh.yaml"
MULTIPLIER=${1:-1}
KAFKA_TOPIC="raw-logs"

TOTAL_LINES=$(wc -l < "$INPUT_LOG")
TOTAL_EVENTS=$((TOTAL_LINES * MULTIPLIER))

echo "=== Peak Performance Benchmark ($TOTAL_EVENTS events) ==="

# ---------------------------------------------------------------------
# Ensure Kafka is running
# ---------------------------------------------------------------------

if ! docker ps | grep -q kafka-bench; then
    echo "Starting Kafka..."
    docker compose up -d kafka
    sleep 3
fi

# ---------------------------------------------------------------------
# Recreate topic
# ---------------------------------------------------------------------

docker exec kafka-bench \
    /opt/bitnami/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --delete \
    --topic "$KAFKA_TOPIC" 2>/dev/null || true

docker exec kafka-bench \
    /opt/bitnami/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create \
    --topic "$KAFKA_TOPIC" \
    --partitions 3 \
    --replication-factor 1 \
    2>/dev/null || true

echo "Created topic $KAFKA_TOPIC."

# ---------------------------------------------------------------------
# Produce events
# ---------------------------------------------------------------------

echo "Producing events to Kafka..."

PRODUCE_START=$(date +%s%N)

./target/release/kafka_producer "$INPUT_LOG" "$KAFKA_TOPIC" "$MULTIPLIER" "localhost:9092"

PRODUCE_END=$(date +%s%N)

PRODUCE_SEC=$(python3 - <<EOF
print(f"{($PRODUCE_END-$PRODUCE_START)/1e9:.2f}")
EOF
)

echo "✓ Produced $TOTAL_EVENTS events in ${PRODUCE_SEC}s"

# ---------------------------------------------------------------------
# Run consumers
# ---------------------------------------------------------------------

echo "Running 3 consumers in parallel (parsing only)..."

CONSUMER_LOG_PREFIX="/tmp/rustlogger_peak_$$"
GROUP_ID="rustlogger-peak-$$"

CONSUMER_PIDS=()

for id in 1 2 3; do
    KAFKA_BROKER="localhost:9092" \
    KAFKA_TOPIC="$KAFKA_TOPIC" \
    KAFKA_GROUP="$GROUP_ID" \
    KAFKA_PARTITION="$((id - 1))" \
        ./target/release/kafka_pipeline "$YAML_CONFIG" \
        >"${CONSUMER_LOG_PREFIX}_${id}.log" 2>&1 &

    CONSUMER_PIDS+=($!)
done

sleep 1

# Tail ALL 3 consumer logs with colored prefixes so you see the full picture
TAIL_PIDS=()
for id in 1 2 3; do
    tail -f "${CONSUMER_LOG_PREFIX}_${id}.log" 2>/dev/null | \
        sed "s/^/[C${id}] /" &
    TAIL_PIDS+=($!)
done

for pid in "${CONSUMER_PIDS[@]}"; do
    wait "$pid" || true
done

for pid in "${TAIL_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
done

echo
echo "================ FINAL RESULTS ================"

for id in 1 2 3; do
    LOG="${CONSUMER_LOG_PREFIX}_${id}.log"

    echo
    echo "========================================================="
    echo "                   CONSUMER $id"
    echo "========================================================="

    if [[ -f "$LOG" ]]; then
        sed -n '/BENCHMARK RESULTS/,$p' "$LOG" || tail -30 "$LOG"
    fi
done

# Aggregated pipeline results calculation
echo
python3 - <<EOF
import re, glob
total_consumed = 0
max_duration_sec = 0.0
per_consumer = []

for log in sorted(glob.glob('${CONSUMER_LOG_PREFIX}_*.log')):
    try:
        content = open(log).read()
        consumed = re.search(r'Total Consumed\s*:\s*(\d+)', content)
        dur_ms = re.search(r'True Active Duration:\s*([\d\.]+)ms', content)
        dur_s  = re.search(r'True Active Duration:\s*([\d\.]+)s(?!e)', content)
        eps_match = re.search(r'True Active EPS\s*:\s*(\d+)', content)

        c = int(consumed.group(1)) if consumed else 0
        if dur_ms:
            d = float(dur_ms.group(1)) / 1000.0
        elif dur_s:
            d = float(dur_s.group(1))
        else:
            d = 0.0
        e = int(eps_match.group(1)) if eps_match else 0

        total_consumed += c
        max_duration_sec = max(max_duration_sec, d)
        per_consumer.append((c, d, e))
    except Exception as ex:
        pass

if max_duration_sec > 0:
    combined_eps = int(total_consumed / max_duration_sec)
    WIDTH = 62
    print()
    print("╔" + "═" * WIDTH + "╗")
    print(f"║{'COMBINED PIPELINE PERFORMANCE':^{WIDTH}}║")
    print("╠" + "═" * WIDTH + "╣")
    for i, (c, d, e) in enumerate(per_consumer):
        line = f"Consumer {i+1:<1}       : {c:>9,} events in {d*1000:>6.1f} ms → {e:>8,} EPS"
        print(f"║ {line:<{WIDTH-1}}║")
    print("╠" + "═" * WIDTH + "╣")
    print(f"║ {'Total Events':<18}: {total_consumed:>12,}{'':<{WIDTH-33}}║")
    print(f"║ {'Slowest Consumer':<18}: {max_duration_sec*1000:>8.1f} ms{'':<{WIDTH-32}}║")
    print(f"║ {'⚡ COMBINED EPS':<18}: {combined_eps:>12,}{'':<{WIDTH-33}}║")
    print("╚" + "═" * WIDTH + "╝")
else:
    print("⚠ Could not parse results from consumer logs.")
EOF

# Clean up logs
for id in 1 2 3; do
    LOG="${CONSUMER_LOG_PREFIX}_${id}.log"
    rm -f "$LOG"
done
