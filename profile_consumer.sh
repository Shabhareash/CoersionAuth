#!/bin/bash
set -e

echo "[1/6] Starting benchmark..."
./rustlogger.sh &
BENCH_PID=$!

echo "[2/6] Waiting for kafka_pipeline..."
PID=""

for i in {1..60}; do
    PID=$(pgrep -f kafka_pipeline | head -n1)
    if [ -n "$PID" ]; then
        break
    fi
    sleep 1
done

if [ -z "$PID" ]; then
    echo "Could not find kafka_pipeline."
    kill $BENCH_PID 2>/dev/null || true
    exit 1
fi

echo "[3/6] Profiling PID $PID"

sudo perf record \
    -F 99 \
    -m 1024 \
    --call-graph dwarf \
    -p "$PID" \
    -- sleep 30

echo "[4/6] Creating flame graph..."

perf script > out.perf
./FlameGraph/stackcollapse-perf.pl out.perf > out.folded
./FlameGraph/flamegraph.pl out.folded > flamegraph.svg

echo "[5/6] Stopping benchmark..."
kill $BENCH_PID 2>/dev/null || true
pkill -f kafka_pipeline || true
pkill -f kafka_producer || true

echo "[6/6] Done!"
echo
echo "Open with:"
echo "xdg-open flamegraph.svg"