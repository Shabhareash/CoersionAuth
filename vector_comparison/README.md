# Benchmark Details & Reproducibility

Thanks for the feedback, Pavlos. I've added a dedicated `benchmarks/` folder to the repo with all experiment scripts, configs, and topology details. Here's a summary of what's included and what the data shows.

---

## Topology

The setup is designed to isolate **CPU parsing throughput** and remove disk/network bottlenecks:

| Component | Detail |
|---|---|
| **Source data** | Real-world Linux `auth.log` (syslog format) |
| **Message queue** | Apache Kafka — 3 partitions, replication factor 1 |
| **Consumer** | Vector or RustLogger reading from `raw-logs` topic |
| **Transform** | VRL `remap`: syslog → ECS field mapping (see below) |
| **Sink** | `blackhole` — throughput measured via `Collected events` log output |

Using a blackhole sink deliberately removes disk I/O as a variable so the comparison reflects pure parsing and pipeline CPU cost.

---

## Traffic Generation

Two methods were used:

**1. Head-to-Head Lag Clearance (`compare_daemons.sh`)**
- Pre-populates Kafka with exactly **1,000,000 events** via `kafka-console-producer.sh`
- Starts the daemon (Vector or RustLogger) and measures wall-clock time to drain consumer group lag to zero
- This gives a clean, reproducible single-pass throughput number

**2. Steady-State Saturation (`vector.sh`)**
- Continuously blasts the 1M event file into Kafka in a loop
- Allows a warm-up period before measurement begins
- Scrapes Vector log output every second to calculate sustained **Events Per Second (EPS)**, **CPU %**, and **Memory (RSS)**

---

## VRL Transform (Vector)

The `vector.yaml` `remap` transform does the following on every event:

1. **Syslog parsing** — `parse_regex` extracts timestamp, host, process name, PID, and raw message body
2. **Timestamp normalisation** — `parse_timestamp` converts to a structured datetime
3. **Regex routing** — the message body is matched against multiple `parse_regex` conditions to identify specific Linux auth events:
   - SSH logins
   - PAM sessions
   - `sudo` executions
   - Cron jobs
4. **ECS mapping** — matched fields are written to ECS paths (e.g. `event.category = "authentication"`, `user.name`, `process.name`)

The equivalent pipeline for RustLogger is in `auth.yaml`.

---

## Flame Graphs

Both processes were profiled under identical load (steady-state Kafka saturation) using `cargo flamegraph` / `perf`.

### RustLogger
![RustLogger Flame Graph](/rustlogger_flamegraph.png)

The stack is shallow and narrow. CPU time is concentrated in the core parsing and Kafka consumer poll loop with minimal overhead above it.

### Vector
![Vector Flame Graph](/vector_flamegraph.png)

The stack is significantly deeper. Visible hotspots include:
- `vrl::compiler::expression::Expr` evaluation
- `vector_core::transform::SyncTransform` dispatch
- `tracing::instrument` overhead on the hot path
- Tokio runtime scheduler contention across multiple threads (`multi_thread`)

The depth and breadth of Vector's flame graph reflects the cost of its general-purpose architecture — runtime VRL compilation/evaluation, tracing instrumentation, and async task scheduling — which RustLogger avoids by compiling the equivalent logic statically.

---

## Repo Contents

```
benchmarks/
├── vector.yaml            # Exact Vector config used
├── auth.yaml              # Equivalent RustLogger pipeline config
├── vector.sh              # Steady-state saturation benchmark script
└── compare_daemons.sh     # Head-to-head Kafka lag clearance script
```

Happy to clarify any part of the setup or add additional profiling data if that would help.
