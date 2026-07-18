#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  RustLogger End-to-End Pipeline Benchmark
#
#  Architecture:
#    Log File Generator → Kafka → RustLogger (native) → Elasticsearch → Kibana
#
#  Usage:
#    ./benchmark.sh                  (interactive — asks you everything)
#    ./benchmark.sh --multiplier 5   (5x the 200k log file = 1M events)
#    ./benchmark.sh --help
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─── Defaults ─────────────────────────────────────────────────────────
LOG_FILE="OpenSSH_200k.log"
YAML_CONFIG="ssh.yaml"
MULTIPLIER=""
KAFKA_TOPIC="raw-logs"
ES_INDEX="logs-ecs"
BULK_SIZE=5000
SKIP_INFRA=false
SKIP_BUILD=false
TEARDOWN=false

# ─── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     RustLogger End-to-End Pipeline Benchmark               ║"
    echo "║     Kafka → RustLogger (native) → Elasticsearch → Kibana  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --multiplier N     Number of times to replay the log file (e.g. 5 = 1M events)"
    echo "  --log-file PATH    Log file to use (default: OpenSSH_200k.log)"
    echo "  --yaml PATH        YAML pipeline config (default: ssh.yaml)"
    echo "  --topic NAME       Kafka topic (default: raw-logs)"
    echo "  --bulk-size N      Bulk size for ES (default: 5000)"
    echo "  --skip-infra       Don't start/stop docker containers"
    echo "  --skip-build       Don't rebuild RustLogger"
    echo "  --teardown         Stop containers after benchmark"
    echo "  --help             Show this help"
    exit 0
}

# ─── Parse args ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --multiplier)   MULTIPLIER="$2"; shift 2 ;;
        --log-file)     LOG_FILE="$2"; shift 2 ;;
        --yaml)         YAML_CONFIG="$2"; shift 2 ;;
        --topic)        KAFKA_TOPIC="$2"; shift 2 ;;
        --bulk-size)    BULK_SIZE="$2"; shift 2 ;;
        --skip-infra)   SKIP_INFRA=true; shift ;;
        --skip-build)   SKIP_BUILD=true; shift ;;
        --teardown)     TEARDOWN=true; shift ;;
        --help)         usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

# ─── Resolve paths ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${RED}Error: Log file '$LOG_FILE' not found${NC}"
    exit 1
fi
if [[ ! -f "$YAML_CONFIG" ]]; then
    echo -e "${RED}Error: YAML config '$YAML_CONFIG' not found${NC}"
    exit 1
fi

TOTAL_LINES=$(wc -l < "$LOG_FILE")
FILE_SIZE=$(du -h "$LOG_FILE" | cut -f1)

banner

# ─── Interactive multiplier prompt ────────────────────────────────────
if [[ -z "$MULTIPLIER" ]]; then
    echo -e "${BOLD}Log file: ${GREEN}$LOG_FILE${NC} (${YELLOW}$TOTAL_LINES lines${NC}, ${YELLOW}$FILE_SIZE${NC})"
    echo ""
    echo -e "${BOLD}How many times should the log file be replayed into Kafka?${NC}"
    echo -e "  1x = ~${TOTAL_LINES} events"
    echo -e "  2x = ~$((TOTAL_LINES * 2)) events"
    echo -e "  5x = ~$((TOTAL_LINES * 5)) events"
    echo -e "  10x = ~$((TOTAL_LINES * 10)) events"
    echo ""
    read -p "Enter multiplier (default: 1): " MULTIPLIER
    MULTIPLIER="${MULTIPLIER:-1}"
fi

TOTAL_EVENTS=$((TOTAL_LINES * MULTIPLIER))
echo ""
echo -e "${BOLD}Benchmark Configuration:${NC}"
echo -e "  Log file     : ${GREEN}$LOG_FILE${NC} ($FILE_SIZE)"
echo -e "  Multiplier   : ${YELLOW}${MULTIPLIER}x${NC}"
echo -e "  Total events : ${YELLOW}${TOTAL_EVENTS}${NC}"
echo -e "  YAML config  : ${GREEN}$YAML_CONFIG${NC}"
echo -e "  Kafka topic  : $KAFKA_TOPIC"
echo -e "  ES index     : $ES_INDEX"
echo -e "  Bulk size    : $BULK_SIZE"
echo ""

# ═══════════════════════════════════════════════════════════════════════
#  STEP 1: Infrastructure
# ═══════════════════════════════════════════════════════════════════════

if [[ "$SKIP_INFRA" == false ]]; then
    echo -e "${CYAN}━━━ Step 1: Starting infrastructure (Kafka + ES + Kibana) ━━━${NC}"

    # Stop old containers with same names if any
    docker rm -f kafka-bench es-bench kibana-bench 2>/dev/null || true

    docker compose up -d

    echo -e "${YELLOW}Waiting for Kafka to be ready...${NC}"
    for i in $(seq 1 60); do
        if docker exec kafka-bench /opt/bitnami/kafka/bin/kafka-topics.sh \
            --bootstrap-server localhost:9092 --list &>/dev/null; then
            echo -e "${GREEN}✓ Kafka is ready${NC}"
            break
        fi
        if [[ $i -eq 60 ]]; then
            echo -e "${RED}✗ Kafka failed to start in 60s${NC}"
            exit 1
        fi
        sleep 1
    done

    echo -e "${YELLOW}Waiting for Elasticsearch to be ready...${NC}"
    for i in $(seq 1 60); do
        if curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status"'; then
            echo -e "${GREEN}✓ Elasticsearch is ready${NC}"
            break
        fi
        if [[ $i -eq 60 ]]; then
            echo -e "${RED}✗ Elasticsearch failed to start in 60s${NC}"
            exit 1
        fi
        sleep 1
    done

    # Create topic (use fresh topic each run to avoid stale offsets)
    docker exec kafka-bench /opt/bitnami/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --delete --topic "$KAFKA_TOPIC" 2>/dev/null || true
    sleep 1
    docker exec kafka-bench /opt/bitnami/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --create --topic "$KAFKA_TOPIC" \
        --partitions 3 \
        --replication-factor 1 \
        --if-not-exists 2>/dev/null || true

    echo -e "${GREEN}✓ Infrastructure ready${NC}"
    echo ""
else
    echo -e "${YELLOW}━━━ Step 1: Skipping infrastructure (--skip-infra) ━━━${NC}"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
#  STEP 2: Build RustLogger
# ═══════════════════════════════════════════════════════════════════════

if [[ "$SKIP_BUILD" == false ]]; then
    echo -e "${CYAN}━━━ Step 2: Building RustLogger (release mode) ━━━${NC}"
    cargo build --release --bin kafka_pipeline 2>&1 | tail -5
    echo -e "${GREEN}✓ Build complete${NC}"
    echo ""
else
    echo -e "${YELLOW}━━━ Step 2: Skipping build (--skip-build) ━━━${NC}"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
#  STEP 3: Delete old ES index (clean slate)
# ═══════════════════════════════════════════════════════════════════════

echo -e "${CYAN}━━━ Step 3: Cleaning ES index ━━━${NC}"
curl -s -X DELETE "http://localhost:9200/$ES_INDEX" 2>/dev/null | grep -v "index_not_found" || true
echo -e "${GREEN}✓ Index '$ES_INDEX' cleaned${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════
#  STEP 4: Produce logs into Kafka
# ═══════════════════════════════════════════════════════════════════════

echo -e "${CYAN}━━━ Step 4: Producing ${TOTAL_EVENTS} events into Kafka ━━━${NC}"

PRODUCE_START=$(date +%s%N)

for i in $(seq 1 "$MULTIPLIER"); do
    echo -ne "\r  Sending batch $i/$MULTIPLIER..."
    cat "$LOG_FILE" | docker exec -i kafka-bench /opt/bitnami/kafka/bin/kafka-console-producer.sh \
        --bootstrap-server localhost:9092 \
        --topic "$KAFKA_TOPIC" \
        2>/dev/null
done

PRODUCE_END=$(date +%s%N)
PRODUCE_MS=$(( (PRODUCE_END - PRODUCE_START) / 1000000 ))
PRODUCE_SEC=$(echo "scale=2; $PRODUCE_MS / 1000" | bc)
PRODUCE_EPS=$(echo "scale=0; $TOTAL_EVENTS / ($PRODUCE_MS / 1000)" | bc 2>/dev/null || echo "N/A")

echo ""
echo -e "${GREEN}✓ All $TOTAL_EVENTS events produced in ${PRODUCE_SEC}s (Producer EPS: ~${PRODUCE_EPS})${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════
#  STEP 5: Start RustLogger native Kafka consumer
# ═══════════════════════════════════════════════════════════════════════

echo -e "${CYAN}━━━ Step 5: Starting RustLogger native Kafka consumer ━━━${NC}"
echo -e "${YELLOW}  (native rdkafka — no JVM, no pipe bottleneck)${NC}"

CONSUMER_LOG="/tmp/rustlogger_bench_$$.log"

# Use a unique group ID per run so we always consume from earliest
KAFKA_BROKER="localhost:9092" \
KAFKA_TOPIC="$KAFKA_TOPIC" \
KAFKA_GROUP="rustlogger-bench-$$" \
ES_HOST="http://127.0.0.1:9200" \
ES_INDEX="$ES_INDEX" \
BULK_SIZE="$BULK_SIZE" \
    ./target/release/kafka_pipeline "$YAML_CONFIG" \
    2>"$CONSUMER_LOG" &

CONSUMER_PID=$!
echo -e "${GREEN}✓ RustLogger consumer started (PID: $CONSUMER_PID)${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════
#  STEP 6: Wait for RustLogger to finish processing
# ═══════════════════════════════════════════════════════════════════════

echo -e "${CYAN}━━━ Step 6: Waiting for RustLogger to process all events ━━━${NC}"
echo -e "${YELLOW}Live stats from RustLogger:${NC}"
echo ""

# Tail the consumer log to show live EPS
tail -f "$CONSUMER_LOG" &
TAIL_PID=$!

# Wait for the consumer process to exit (it auto-exits after 9s of no messages)
WAIT_TIMEOUT=300
for i in $(seq 1 $WAIT_TIMEOUT); do
    sleep 2

    # Check if consumer is still running
    if ! kill -0 $CONSUMER_PID 2>/dev/null; then
        echo ""
        echo -e "${GREEN}✓ RustLogger consumer finished${NC}"
        break
    fi

    if [[ $i -eq $WAIT_TIMEOUT ]]; then
        echo ""
        echo -e "${YELLOW}⚠ Timeout waiting for consumer — killing${NC}"
        kill $CONSUMER_PID 2>/dev/null || true
    fi
done

# Stop the tail
kill $TAIL_PID 2>/dev/null || true
wait $TAIL_PID 2>/dev/null || true
wait $CONSUMER_PID 2>/dev/null || true

echo ""

# ═══════════════════════════════════════════════════════════════════════
#  STEP 7: Final Results
# ═══════════════════════════════════════════════════════════════════════

echo -e "${CYAN}━━━ Step 7: Final Results ━━━${NC}"
echo ""

# Get ES doc count
ES_FINAL=$(curl -s "http://localhost:9200/$ES_INDEX/_count" 2>/dev/null | \
    grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo "0")

# Check Kafka consumer lag
echo -e "${BOLD}Kafka Consumer Lag:${NC}"
docker exec kafka-bench /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
    --bootstrap-server localhost:9092 \
    --describe \
    --group "rustlogger-bench-$$" 2>/dev/null || echo "  (unable to read)"
echo ""

# Collect process stats from log
echo -e "${BOLD}RustLogger Final Report:${NC}"
if [[ -f "$CONSUMER_LOG" ]]; then
    # Show the final benchmark results block
    grep -A 20 "BENCHMARK RESULTS" "$CONSUMER_LOG" 2>/dev/null || cat "$CONSUMER_LOG" | tail -20
fi
echo ""

# ES stats
echo -e "${BOLD}Elasticsearch Stats:${NC}"
echo -e "  Documents indexed : ${GREEN}$ES_FINAL${NC} / $TOTAL_EVENTS"
if [[ "$ES_FINAL" -ge "$TOTAL_EVENTS" ]]; then
    echo -e "  Status            : ${GREEN}✓ RustLogger kept up!${NC}"
else
    DEFICIT=$((TOTAL_EVENTS - ES_FINAL))
    PCT=$(echo "scale=1; $ES_FINAL * 100 / $TOTAL_EVENTS" | bc 2>/dev/null || echo "?")
    echo -e "  Status            : ${YELLOW}⚠ $DEFICIT events missing ($PCT% indexed)${NC}"
fi
echo ""

# Sample some documents
echo -e "${BOLD}Sample ECS Document:${NC}"
curl -s "http://localhost:9200/$ES_INDEX/_search?size=1&pretty" 2>/dev/null | head -50
echo ""

# Field distribution
echo -e "${BOLD}Event Category Distribution:${NC}"
curl -s "http://localhost:9200/$ES_INDEX/_search" -H 'Content-Type: application/json' -d '{
    "size": 0,
    "aggs": {
        "categories": { "terms": { "field": "event.category", "size": 20 } },
        "actions":    { "terms": { "field": "event.action",   "size": 20 } },
        "outcomes":   { "terms": { "field": "event.outcome",  "size": 10 } }
    }
}' 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (install python3 for pretty output)"
echo ""

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Kibana:${NC} Open ${CYAN}http://localhost:5601${NC}"
echo -e "  → Go to ${BOLD}Discover${NC}"
echo -e "  → Create data view for index pattern: ${GREEN}$ES_INDEX${NC}"
echo -e "  → View: event.category, source.ip, user.name, host.name"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# ─── Cleanup ──────────────────────────────────────────────────────────
rm -f "$CONSUMER_LOG"

if [[ "$TEARDOWN" == true ]]; then
    echo ""
    echo -e "${YELLOW}Tearing down containers...${NC}"
    docker compose down
    echo -e "${GREEN}✓ Containers stopped${NC}"
fi
