#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  RustLogger vs Vector Daemon Performance Comparison Script
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# Configurations
INPUT_LOG="auth_1m.log"
RUST_YAML="auth.yaml"
VECTOR_CFG="/home/shabh/.vector/config/vector.yaml"
KAFKA_TOPIC="raw-logs"
VECTOR_BIN="/home/shabh/.vector/bin/vector"

# Limit threads per consumer to prevent CPU thrashing
export RAYON_NUM_THREADS=4
export TOKIO_WORKER_THREADS=2

# Prompt for sudo password if not provided via env
SUDO_CMD="sudo"
if [ ! -f "$INPUT_LOG" ]; then
    echo "Error: $INPUT_LOG not found."
    exit 1
fi

TOTAL_LINES=$(wc -l < "$INPUT_LOG")
echo "=== head-to-head benchmark setup: $TOTAL_LINES events ==="

# Function to clean and recreate Kafka topic
recreate_topic() {
    echo "Recreating topic: $KAFKA_TOPIC..."
    $SUDO_CMD docker exec kafka-bench \
        /opt/bitnami/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --delete \
        --topic "$KAFKA_TOPIC" 2>/dev/null || true
    
    sleep 2

    $SUDO_CMD docker exec kafka-bench \
        /opt/bitnami/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --create \
        --topic "$KAFKA_TOPIC" \
        --partitions 3 \
        --replication-factor 1 \
        2>/dev/null || true
}

# Function to load events into Kafka
produce_events() {
    echo "Pre-populating Kafka topic with $TOTAL_LINES events from $INPUT_LOG..."
    START=$(date +%s)
    cat "$INPUT_LOG" | $SUDO_CMD docker exec -i kafka-bench \
        /opt/bitnami/kafka/bin/kafka-console-producer.sh \
        --bootstrap-server localhost:9092 \
        --topic "$KAFKA_TOPIC"
    END=$(date +%s)
    echo "✓ Produced events in $((END-START)) sec"
}

# =====================================================================
#  PART 1: RustLogger Benchmark
# =====================================================================
echo
echo "========================================================="
echo "               1. RUNNING RUSTLOGGER BENCHMARK           "
echo "========================================================="

recreate_topic
produce_events

echo "Starting 3 parallel RustLogger consumers (pinned to partition 0, 1, 2)..."
CONSUMER_LOG_PREFIX="/tmp/rustlogger_bench_$$"
GROUP_ID="rustlogger-bench-$$"
CONSUMER_PIDS=()

for id in 1 2 3; do
    KAFKA_BROKER="localhost:9092" \
    KAFKA_TOPIC="$KAFKA_TOPIC" \
    KAFKA_GROUP="$GROUP_ID" \
    KAFKA_PARTITION="$((id - 1))" \
        ./target/release/kafka_pipeline "$RUST_YAML" \
        >"${CONSUMER_LOG_PREFIX}_${id}.log" 2>&1 &

    pid=$!
    CONSUMER_PIDS+=($pid)
    disown $pid
done

echo "Waiting for RustLogger consumers to finish parsing..."
for pid in "${CONSUMER_PIDS[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.5
    done
done
echo "✓ RustLogger run complete."

# Extract RustLogger results using Python parser
RUST_STATS=$(python3 - <<EOF
import re, glob
total_consumed = 0
max_duration = 0.0

for log in glob.glob('${CONSUMER_LOG_PREFIX}_*.log'):
    try:
        content = open(log).read()
        consumed_m = re.search(r'Total Consumed\s*:\s*(\d+)', content)
        if consumed_m:
            total_consumed += int(consumed_m.group(1))
            
        duration_m = re.search(r'True Active Duration\s*:\s*([\d\.]+)(m?)s', content)
        if duration_m:
            val = float(duration_m.group(1))
            is_ms = duration_m.group(2) == 'm'
            if is_ms:
                val /= 1000.0
            max_duration = max(max_duration, val)
    except Exception as e:
        pass

eps = int(total_consumed / max_duration) if max_duration > 0 else 0
print(f"{total_consumed},{max_duration:.3f},{eps}")
EOF
)

RUST_TOTAL_CONSUMED=$(echo "$RUST_STATS" | cut -d, -f1)
RUST_MAX_DURATION=$(echo "$RUST_STATS" | cut -d, -f2)
RUST_EPS=$(echo "$RUST_STATS" | cut -d, -f3)

# Cleanup temporary logs
rm -f ${CONSUMER_LOG_PREFIX}_*.log

# =====================================================================
#  PART 2: Vector Benchmark
# =====================================================================
echo
echo "========================================================="
echo "               2. RUNNING VECTOR BENCHMARK               "
echo "========================================================="

recreate_topic
produce_events

echo "Starting Vector daemon..."
VECTOR_LOG="/tmp/vector_bench_$$.log"
rm -f "$VECTOR_LOG"

# Clean Vector state to avoid offset carry-over
$SUDO_CMD rm -rf /var/lib/vector/* 2>/dev/null || true

$VECTOR_BIN --config "$VECTOR_CFG" >"$VECTOR_LOG" 2>&1 &
VECTOR_PID=$!
disown $VECTOR_PID

echo "Monitoring Vector consumer group lag..."
# Poll lag until it reaches 0
while true; do
    sleep 1
    # Check if Vector exited unexpectedly
    if ! kill -0 $VECTOR_PID 2>/dev/null; then
        echo "Vector process died unexpectedly. Logs:"
        cat "$VECTOR_LOG"
        exit 1
    fi

    # Query lag
    LAG_INFO=$($SUDO_CMD docker exec kafka-bench \
        /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
        --bootstrap-server localhost:9092 \
        --describe \
        --group "vector-bench" 2>/dev/null || true)
    
    if [ -n "$LAG_INFO" ]; then
        TOTAL_LAG=$(echo "$LAG_INFO" | awk 'NR>1 {sum+=$6} END {print sum}')
        if [ "$TOTAL_LAG" = "0" ]; then
            echo "✓ Consumer lag reached 0. Stopping Vector..."
            break
        fi
        printf "\rCurrent Vector Lag: %s events" "$TOTAL_LAG"
    fi
done

# Let Vector flush the last metrics
sleep 2
kill -9 $VECTOR_PID 2>/dev/null || true

# Parse Vector logs for stats
echo
echo "Parsing Vector throughput from logs..."

VECTOR_STATS=$(python3 - <<EOF
import re
from datetime import datetime

pattern = re.compile(r"^([\d\-T\:\.]+Z)\s+INFO.*events=(\d+)")
matches = []

with open("$VECTOR_LOG") as f:
    for line in f:
        m = pattern.search(line)
        if m:
            ts_str, count_str = m.groups()
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                matches.append((ts, int(count_str)))
            except Exception as e:
                pass

non_zero = [m for m in matches if m[1] > 0]
if len(non_zero) >= 2:
    start_ts, start_count = non_zero[0]
    max_count = max(m[1] for m in non_zero)
    end_ts, end_count = next(m for m in non_zero if m[1] == max_count)
    duration = (end_ts - start_ts).total_seconds()
    if duration > 0:
        eps = int(max_count / duration)
        print(f"{max_count},{duration:.2f},{eps}")
    else:
        print(f"{max_count},0.1,0")
else:
    print("0,0.0,0")
EOF
)

VEC_TOTAL_CONSUMED=$(echo "$VECTOR_STATS" | cut -d, -f1)
VEC_DURATION=$(echo "$VECTOR_STATS" | cut -d, -f2)
VEC_EPS=$(echo "$VECTOR_STATS" | cut -d, -f3)

rm -f "$VECTOR_LOG"

# =====================================================================
#  PART 3: Final Comparison Report
# =====================================================================
echo
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  DAEMON PERFORMANCE SUMMARY                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  RUSTLOGGER:                                                 ║"
echo "║    - Events Processed: $(printf "%-32d" $RUST_TOTAL_CONSUMED)║"
echo "║    - Active Duration : $(printf "%-32s" "${RUST_MAX_DURATION}s")║"
echo "║    - Combined EPS    : $(printf "%-32s" "${RUST_EPS} events/sec")║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  VECTOR:                                                     ║"
echo "║    - Events Processed: $(printf "%-32d" $VEC_TOTAL_CONSUMED)║"
echo "║    - Active Duration : $(printf "%-32s" "${VEC_DURATION}s")║"
echo "║    - Combined EPS    : $(printf "%-32s" "${VEC_EPS} events/sec")║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo
