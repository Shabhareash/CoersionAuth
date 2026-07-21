# Vector vs RustLogger Benchmarks

This folder contains the experiment scripts and configuration files used to benchmark Vector against RustLogger for log ingestion and parsing.

## Topology

The benchmarking setup is designed to evaluate raw parsing and ingestion throughput by isolating network/disk bottlenecks as much as possible:

1.  **Source Data**: Real-world Linux authentication logs (`auth.log` format).
2.  **Message Queue**: Apache Kafka (3 partitions, 1 replication factor).
3.  **Consumer (Vector)**: Reads from Kafka `raw-logs` topic.
4.  **Transform**: A VRL `remap` transform parses the raw syslog format and maps it into Elastic Common Schema (ECS).
5.  **Sink**: `blackhole` sink. We measure throughput via the logged output (`Collected events`) of the blackhole sink to strictly test CPU parsing bounds without being bottlenecked by disk I/O.

## Traffic Generator

There are two primary methods we use to test throughput:

1.  **Head-to-Head Lag Clearance (`compare_daemons.sh`)**:
    *   Pre-populates a Kafka topic with exactly 1,000,000 events using `kafka-console-producer.sh`.
    *   Starts the daemon (Vector or RustLogger) and measures exactly how long it takes to bring consumer group lag down to zero.
2.  **Steady-State Saturation (`vector.sh`)**:
    *   Starts Vector first.
    *   Starts a continuous shell loop that blasts the 1M event log file repeatedly into Kafka.
    *   A warm-up period is allowed.
    *   We scrape the Vector log output every second to calculate steady-state Events Per Second (EPS), CPU usage, and Memory (RSS) over a sustained measurement window.

## Transforms Used (VRL)

The Vector configuration (`vector.yaml`) uses a `remap` transform to process each log line. The pipeline does the following:

1.  **Syslog Parsing**: Uses `parse_regex` to extract the timestamp, host, process name, PID, and the remaining message.
2.  **Timestamp Parsing**: Uses `parse_timestamp`.
3.  **Regex Routing**: The message is subsequently matched against multiple `parse_regex` conditions to identify specific Linux authentication events (SSH logins, PAM sessions, sudo executions, cron jobs) and map them to ECS fields (e.g., `event.category = "authentication"`, `user.name`).

## Running the Experiments

*   `vector.yaml`: The exact configuration file used for Vector during the benchmark.
*   `vector.sh`: Script for continuous steady-state Vector benchmark.
*   `compare_daemons.sh`: Script for head-to-head Kafka lag clearance benchmark.
*   `auth.yaml`: The equivalent parsing pipeline configuration used by RustLogger.
