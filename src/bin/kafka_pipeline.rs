//! Kafka Consumer → Pipeline → Elasticsearch Bulk Indexer
//!
//! Native rdkafka consumer — no JVM, no shell pipes, no bottleneck.
//! Decoupled ingestion and asynchronous bulk writing.
//!
//! Usage:
//!   cargo run --release --bin kafka_pipeline -- <yaml-config>
//!
//! Environment:
//!   KAFKA_BROKER   (default: localhost:9092)
//!   KAFKA_TOPIC    (default: raw-logs)
//!   KAFKA_GROUP    (default: rustlogger)
//!   ES_HOST        (default: http://127.0.0.1:9200)
//!   ES_INDEX       (default: logs-ecs)
//!   BULK_SIZE      (default: 5000)  — docs per bulk request
//!   DAEMON         (default: unset) — set to "1" for daemon mode (no idle exit, HTTP metrics)
//!   METRICS_PORT   (default: 9090)  — HTTP metrics port (daemon mode only)
//!

use my_scanner::pipeline::Pipeline;
use my_scanner::yaml_config::load_yaml_config;
use my_scanner::{FieldVec, FieldValue};

use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, BaseConsumer};
use rdkafka::message::Message;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use serde_json::json;
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use std::borrow::Cow;

// ─── RawBatch: Contiguous zero-copy byte buffer ────────────────────
//
// At 24M EPS, the old Vec<String> approach forced the single ingestion
// thread to:
//   1. Validate UTF-8 on every byte (O(n) scan per message)
//   2. Heap-allocate a String per message (24M mallocs/sec)
//
// RawBatch stores all messages in a single contiguous Vec<u8> with an
// offset index. The ingestion thread does only raw memcpy (no validation,
// no per-message alloc). UTF-8 conversion is deferred to Rayon workers.

struct RawBatch {
    /// Contiguous byte buffer holding all messages back-to-back.
    data: Vec<u8>,
    /// Byte offset marking the start of each message.
    /// Message[i] spans data[offsets[i]..offsets[i+1]] (or ..data.len() for the last).
    offsets: Vec<u32>,
}

impl RawBatch {
    fn with_capacity(msg_count: usize, byte_capacity: usize) -> Self {
        RawBatch {
            data: Vec::with_capacity(byte_capacity),
            offsets: Vec::with_capacity(msg_count),
        }
    }

    /// Append raw bytes. No UTF-8 validation, no per-message allocation.
    #[inline]
    fn push(&mut self, payload: &[u8]) {
        self.offsets.push(self.data.len() as u32);
        self.data.extend_from_slice(payload);
    }

    #[inline]
    fn len(&self) -> usize {
        self.offsets.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Get message at index as a raw byte slice.
    #[inline]
    fn get(&self, idx: usize) -> &[u8] {
        let start = self.offsets[idx] as usize;
        let end = if idx + 1 < self.offsets.len() {
            self.offsets[idx + 1] as usize
        } else {
            self.data.len()
        };
        &self.data[start..end]
    }
}

/// Trim ASCII whitespace from both ends of a byte slice.
/// Equivalent to str::trim() but operates on raw bytes — no UTF-8 required.
#[inline]
fn trim_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map(|p| p + 1).unwrap_or(start);
    &bytes[start..end]
}

// ─── Throughput counters ────────────────────────────────────────────

static PROCESSED: AtomicU64 = AtomicU64::new(0);
static INDEXED: AtomicU64 = AtomicU64::new(0);
static PARSE_SUCCESS: AtomicU64 = AtomicU64::new(0);
static TOTAL_CONSUMED: AtomicU64 = AtomicU64::new(0);
static BULK_ERRORS: AtomicU64 = AtomicU64::new(0);
static PEAK_EPS: AtomicU64 = AtomicU64::new(0);

const CONCURRENT_REQUESTS: u32 = 16;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let daemon_mode = env::var("DAEMON").unwrap_or_default() == "1";
    let metrics_port: u16 = env::var("METRICS_PORT")
        .unwrap_or_else(|_| "9090".to_string())
        .parse()
        .unwrap_or(9090);

    // ── Graceful shutdown flag (for daemon mode, SIGINT/SIGTERM) ──────
    let shutdown = Arc::new(AtomicBool::new(false));
    if daemon_mode {
        let shutdown_sig = shutdown.clone();
        ctrlc_handler(shutdown_sig);
    }

    let yaml_path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: kafka_pipeline <yaml-config>");
        std::process::exit(1);
    });

    let kafka_broker = env::var("KAFKA_BROKER").unwrap_or_else(|_| "localhost:9092".to_string());
    let kafka_topic = env::var("KAFKA_TOPIC").unwrap_or_else(|_| "raw-logs".to_string());
    let kafka_group = env::var("KAFKA_GROUP").unwrap_or_else(|_| "rustlogger".to_string());
    let es_host = env::var("ES_HOST").unwrap_or_else(|_| "http://127.0.0.1:9200".to_string());
    let es_index = env::var("ES_INDEX").unwrap_or_else(|_| "logs-ecs".to_string());
    let bulk_size: usize = env::var("BULK_SIZE")
        .unwrap_or_else(|_| "5000".to_string())
        .parse()
        .unwrap_or(5000);
    let bulk_url = format!("{}/_bulk", es_host);

    // ── Load YAML config and compile pipeline ────────────────────────
    let yaml_cfg = load_yaml_config(Path::new(&yaml_path))
        .unwrap_or_else(|e| { eprintln!("[ERROR] {}", e); std::process::exit(1); });
    let pipeline = Arc::new(Pipeline::from_config(&yaml_cfg));
    let log_family = yaml_cfg.log_family.clone();

    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║    RustLogger Kafka Pipeline — Decoupled Async Consumer    ║");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    eprintln!("║  Kafka   : {:<48}║", kafka_broker);
    eprintln!("║  Topic   : {:<48}║", kafka_topic);
    eprintln!("║  Group   : {:<48}║", kafka_group);
    eprintln!("║  ES Host : {:<48}║", es_host);
    eprintln!("║  ES Index: {:<48}║", es_index);
    eprintln!("║  Bulk    : {:<48}║", format!("{} docs", bulk_size));
    eprintln!("║  YAML    : {:<48}║", yaml_path);
    eprintln!("║  Family  : {:<48}║", log_family);
    eprintln!("║  Mode    : {:<48}║", if daemon_mode { "DAEMON (continuous)" } else { "BATCH (idle-exit)" });
    if daemon_mode {
        eprintln!("║  Metrics : {:<48}║", format!("http://0.0.0.0:{}/metrics", metrics_port));
    }
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // ── Create ES index ──────────────────────────────────────────────
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(CONCURRENT_REQUESTS as usize)
        .build()
        .unwrap();

    create_es_index(&client, &es_host, &es_index).await;

    // ── Create native Kafka consumer ─────────────────────────────────
    let consumer: BaseConsumer = ClientConfig::new()
        .set("bootstrap.servers", &kafka_broker)
        .set("group.id", &kafka_group)
        .set("auto.offset.reset", "earliest")
        .set("enable.auto.commit", "true")
        .set("auto.commit.interval.ms", "1000")
        .set("fetch.min.bytes", "1048576") // 1MB batch min fetch size
        .set("fetch.wait.max.ms", "50")
        .set("max.partition.fetch.bytes", "10485760")  // 10 MB per partition
        .set("queued.max.messages.kbytes", "131072")    // 128 MB buffer
        .set("session.timeout.ms", "60000")
        .create()
        .expect("Failed to create Kafka consumer");

    if let Ok(part_str) = env::var("KAFKA_PARTITION") {
        let partition: i32 = part_str.parse().expect("Invalid KAFKA_PARTITION value");
        let mut tpl = rdkafka::TopicPartitionList::new();
        tpl.add_partition(&kafka_topic, partition);
        tpl.set_partition_offset(&kafka_topic, partition, rdkafka::Offset::Beginning)
            .expect("Failed to set partition offset");
        consumer.assign(&tpl).expect("Failed to assign partition");
        eprintln!("[KAFKA] Assigned to partition {} on topic '{}' — consuming...", partition, &kafka_topic);
    } else {
        consumer.subscribe(&[&kafka_topic])
            .expect("Failed to subscribe to topic");
        eprintln!("[KAFKA] Subscribed to topic '{}' — consuming...", kafka_topic);
    }

    // ── Spawn EPS reporter thread ────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    let stats_handle = std::thread::spawn(move || {
        let mut peak_eps: u64 = 0;
        let mut second = 0u64;
        let start = Instant::now();
        let mut active_seconds_count = 0u64;

        while running_clone.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            second += 1;

            let eps = PROCESSED.swap(0, Ordering::Relaxed);
            let idx = INDEXED.swap(0, Ordering::Relaxed);
            let total = TOTAL_CONSUMED.load(Ordering::Relaxed);
            let errors = BULK_ERRORS.load(Ordering::Relaxed);
            let success = PARSE_SUCCESS.load(Ordering::Relaxed);

            if eps > peak_eps {
                peak_eps = eps;
                PEAK_EPS.store(peak_eps, Ordering::Relaxed);
            }
            if total > 0 && eps > 0 {
                active_seconds_count += 1;
            }

            let avg_eps = if active_seconds_count > 0 { total / active_seconds_count } else { 0 };
            let parse_pct = if total > 0 {
                (success as f64 / total as f64) * 100.0
            } else { 0.0 };

            eprintln!(
                "[{:>4}s] EPS: {:>8} | Indexed: {:>8} | Total: {:>10} | Avg EPS: {:>8} | Peak: {:>8} | Parse%: {:>5.1}% | Errors: {}",
                second, eps, idx, total, avg_eps, peak_eps, parse_pct, errors
            );
        }

        let _elapsed = start.elapsed();
        let total = TOTAL_CONSUMED.load(Ordering::Relaxed);
        let success = PARSE_SUCCESS.load(Ordering::Relaxed);
        let errors = BULK_ERRORS.load(Ordering::Relaxed);
        let parse_pct = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else { 0.0 };

        // Calculate active-only average
        let active_eps = if active_seconds_count > 0 {
            total / active_seconds_count
        } else {
            total
        };

        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║                    BENCHMARK RESULTS                       ║");
        eprintln!("╠══════════════════════════════════════════════════════════════╣");
        eprintln!("║  Total Consumed  : {:<40}║", format!("{} events", total));
        eprintln!("║  Average EPS     : {:<40}║", format!("{}", active_eps));
        eprintln!("║  Peak EPS        : {:<40}║", format!("{}", peak_eps));
        eprintln!("║  Parse Success   : {:<40}║", format!("{:.1}%", parse_pct));
        eprintln!("║  Bulk Errors     : {:<40}║", format!("{}", errors));
        eprintln!("║  Duration        : {:<40}║", format!("{}s (active)", active_seconds_count));
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
    });

    // ── Spawn HTTP metrics server (daemon mode only) ─────────────────
    if daemon_mode {
        std::thread::spawn(move || {
            let listener = TcpListener::bind(format!("0.0.0.0:{}", metrics_port))
                .unwrap_or_else(|e| {
                    eprintln!("[METRICS] Failed to bind port {}: {}", metrics_port, e);
                    std::process::exit(1);
                });
            eprintln!("[METRICS] HTTP server listening on 0.0.0.0:{}", metrics_port);

            for stream in listener.incoming() {
                if let Ok(mut stream) = stream {
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf);

                    let total = TOTAL_CONSUMED.load(Ordering::Relaxed);
                    let success = PARSE_SUCCESS.load(Ordering::Relaxed);
                    let errors = BULK_ERRORS.load(Ordering::Relaxed);
                    let peak = PEAK_EPS.load(Ordering::Relaxed);

                    let body = format!(
                        r#"{{"total_consumed":{},"parse_success":{},"bulk_errors":{},"peak_eps":{}}}"#,
                        total, success, errors, peak
                    );

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        });
    }

    // ── Consume from Kafka natively and dispatch writes ──────────────
    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENT_REQUESTS as usize));
    let handle = tokio::runtime::Handle::current();

    // Check WRITE_TO_STDOUT once at startup, not per-batch (avoids env lookup overhead).
    let write_stdout = env::var("WRITE_TO_STDOUT").is_ok();

    let shutdown_clone = shutdown.clone();
    let total_processing_duration = tokio::task::spawn_blocking(move || {
        let shutdown_flag = shutdown_clone;
        let is_daemon = env::var("DAEMON").unwrap_or_default() == "1";
        // Pre-allocate contiguous buffer: ~512 bytes avg per message × bulk_size
        let mut batch = RawBatch::with_capacity(bulk_size, bulk_size * 512);
        let mut no_msg_count = 0u32;
        let mut first_dispatch: Option<Instant> = None;
        let action_line = format!("{{\"index\":{{\"_index\":\"{}\"}}}}\n", es_index);

        loop {
            match consumer.poll(Duration::from_millis(100)) {
                Some(Ok(msg)) => {
                    no_msg_count = 0;
                    // Raw bytes — NO UTF-8 validation, NO String allocation.
                    // Just memcpy into the contiguous buffer.
                    if let Some(payload) = msg.payload() {
                        let trimmed = trim_bytes(payload);
                        if !trimmed.is_empty() {
                            batch.push(trimmed);
                        }
                    }

                    if batch.len() >= bulk_size {
                        let full_batch = std::mem::replace(
                            &mut batch,
                            RawBatch::with_capacity(bulk_size, bulk_size * 512),
                        );
                        let pipeline_clone = Arc::clone(&pipeline);
                        let log_family_clone = log_family.clone();
                        let action_line_clone = action_line.clone();
                        let sem_clone = Arc::clone(&sem);

                        if first_dispatch.is_none() {
                            first_dispatch = Some(Instant::now());
                        }

                        // Acquire permit SYNCHRONOUSLY before spawning.
                        // This backpressures the ingestion loop if all 16 slots
                        // are busy — prevents unbounded memory growth.
                        let permit = handle.block_on(async {
                            sem_clone.acquire_owned().await.unwrap()
                        });

                        // Spawn the CPU-heavy work onto a dedicated blocking thread.
                        // This NEVER touches Tokio's async worker threads, so they
                        // stay free for IO (metrics HTTP, future ES bulk sends).
                        std::thread::spawn(move || {
                            let _permit = permit; // held until this scope drops
                            process_batch_sync(
                                &pipeline_clone,
                                &log_family_clone,
                                &action_line_clone,
                                &full_batch,
                                write_stdout,
                            );
                        });
                    }
                }
                Some(Err(e)) => {
                    eprintln!("[KAFKA ERROR] {}", e);
                }
                None => {
                    // Timeout — no messages for 100ms. Flush remaining if any.
                    if !batch.is_empty() {
                        let full_batch = std::mem::replace(
                            &mut batch,
                            RawBatch::with_capacity(bulk_size, bulk_size * 512),
                        );
                        let pipeline_clone = Arc::clone(&pipeline);
                        let log_family_clone = log_family.clone();
                        let action_line_clone = action_line.clone();
                        let sem_clone = Arc::clone(&sem);

                        if first_dispatch.is_none() {
                            first_dispatch = Some(Instant::now());
                        }

                        let permit = handle.block_on(async {
                            sem_clone.acquire_owned().await.unwrap()
                        });

                        std::thread::spawn(move || {
                            let _permit = permit;
                            process_batch_sync(
                                &pipeline_clone,
                                &log_family_clone,
                                &action_line_clone,
                                &full_batch,
                                write_stdout,
                            );
                        });
                    }

                    no_msg_count += 1;

                    // In daemon mode, check shutdown flag instead of idle timeout
                    if shutdown_flag.load(Ordering::Relaxed) {
                        eprintln!("[DAEMON] Shutdown signal received — stopping consumer...");
                        break;
                    }

                    if !is_daemon {
                        let total = TOTAL_CONSUMED.load(Ordering::Relaxed);
                        // 60 timeouts * 100ms = 6 seconds of total silence after processing data -> stop
                        if total > 0 && no_msg_count >= 60 {
                            eprintln!("[KAFKA] No messages for {}ms after processing {} events — stopping",
                                no_msg_count * 100, total);
                            break;
                        }
                    }
                }
            }
        }

        // Wait for all background workers to complete (all permits returned).
        handle.block_on(async {
            let _ = sem.acquire_many(CONCURRENT_REQUESTS).await.unwrap();
        });

        first_dispatch.map(|fd| {
            let elapsed = fd.elapsed();
            let silence = Duration::from_millis((no_msg_count as u64) * 100);
            if elapsed > silence {
                elapsed - silence
            } else {
                elapsed
            }
        }).unwrap_or(Duration::from_secs(0))
    }).await.unwrap();

    // Signal stats thread to stop and print final report
    running.store(false, Ordering::Relaxed);
    let _ = stats_handle.join();

    let total = TOTAL_CONSUMED.load(Ordering::Relaxed);
    let active_eps = if total_processing_duration.as_secs_f64() > 0.0 {
        (total as f64 / total_processing_duration.as_secs_f64()) as u64
    } else {
        total
    };

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║             ACTUAL ACTIVE PARSING PERFORMANCE              ║");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    eprintln!("║  True Active Duration: {:<38}║", format!("{:.3?}", total_processing_duration));
    eprintln!("║  True Active EPS     : {:<38}║", format!("{} events/sec", active_eps));
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}

/// Register SIGINT/SIGTERM handler for graceful daemon shutdown
fn ctrlc_handler(flag: Arc<AtomicBool>) {
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
    }
    let ptr = Box::into_raw(Box::new(flag)) as usize;
    SHUTDOWN_FLAG.store(ptr as u64, Ordering::SeqCst);
}

static SHUTDOWN_FLAG: AtomicU64 = AtomicU64::new(0);

extern "C" fn signal_handler(_sig: libc::c_int) {
    let ptr = SHUTDOWN_FLAG.load(Ordering::SeqCst) as *const Arc<AtomicBool>;
    if !ptr.is_null() {
        unsafe { (*ptr).store(true, Ordering::SeqCst); }
    }
}

// ════════════════════════════════════════════════════════════════════
//  FULLY SYNCHRONOUS BATCH PROCESSOR
// ════════════════════════════════════════════════════════════════════
//
// This function runs on a dedicated OS thread (std::thread::spawn),
// NEVER on a Tokio worker. This is critical because:
//
//   1. Rayon's par_iter() blocks the calling thread until all workers
//      finish. If that thread is a Tokio worker (only 2 of them!),
//      the entire async runtime stalls — no metrics, no IO, nothing.
//
//   2. JSON serialization (serde_json::to_writer) is CPU-bound.
//      Running it sequentially after Rayon created a second bottleneck.
//      Now it runs INSIDE par_iter, parallelized across all cores.
//
// Data flow per batch:
//   RawBatch ──Rayon──→ [(FieldVec, Vec<u8>)] ──concat──→ bulk NDJSON
//                        ↑ parse + serialize
//                          all in one parallel pass

fn process_batch_sync(
    pipeline: &Pipeline,
    log_family: &str,
    action_line: &str,
    batch: &RawBatch,
    write_stdout: bool,
) {
    let msg_count = batch.len();

    // ── Parse + Serialize in ONE parallel pass ──────────────────────
    // Each Rayon worker: UTF-8 validate → parse → enrich → serialize to JSON bytes.
    // No intermediate Vec<FieldVec> allocation — we go straight to NDJSON fragments.
    let indices: Vec<usize> = (0..msg_count).collect();
    let results: Vec<(bool, Vec<u8>)> = indices
        .par_iter()
        .map(|&i| {
            let raw = batch.get(i);

            // UTF-8 validation distributed across Rayon cores.
            let line_cow: Cow<str> = match std::str::from_utf8(raw) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => String::from_utf8_lossy(raw),
            };

            let mut doc = pipeline.process_line(&line_cow);
            doc.insert("@version", FieldValue::StaticStr("1"));
            doc.insert("log_type", FieldValue::Str(log_family.to_string()));
            doc.insert("tags", FieldValue::Array(vec![
                FieldValue::StaticStr("rustlogger"),
                FieldValue::StaticStr("kafka-pipeline"),
            ]));
            doc.or_insert("event.dataset", FieldValue::StaticStr("generic"));

            let matched = doc.get("matched") == Some(&FieldValue::Bool(true));

            // Serialize to NDJSON fragment: action_line + json + newline
            // Each worker writes to its own buffer — no contention, no lock.
            let mut buf = Vec::with_capacity(768);
            buf.extend_from_slice(action_line.as_bytes());
            serde_json::to_writer(&mut buf, &doc).unwrap();
            buf.push(b'\n');

            (matched, buf)
        })
        .collect();

    // ── Aggregate results (single-threaded, but just counting + memcpy) ─
    let mut success = 0u64;
    let mut total_bytes = 0usize;
    for (matched, buf) in &results {
        if *matched { success += 1; }
        total_bytes += buf.len();
    }

    let doc_count = results.len() as u64;
    PROCESSED.fetch_add(doc_count, Ordering::Relaxed);
    TOTAL_CONSUMED.fetch_add(doc_count, Ordering::Relaxed);
    PARSE_SUCCESS.fetch_add(success, Ordering::Relaxed);
    INDEXED.fetch_add(doc_count, Ordering::Relaxed);

    // ── Write to stdout if requested ────────────────────────────────
    if write_stdout {
        let mut bulk_body = Vec::with_capacity(total_bytes);
        for (_, buf) in &results {
            bulk_body.extend_from_slice(buf);
        }
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(&bulk_body);
    }
}

async fn create_es_index(client: &reqwest::Client, es_host: &str, index: &str) {
    let url = format!("{}/{}", es_host, index);

    let exists = client.head(&url).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if exists {
        eprintln!("[ES] Index '{}' already exists", index);
        return;
    }

    let mapping = json!({
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s"
        },
        "mappings": {
            "properties": {
                "@timestamp":        { "type": "date" },
                "message":           { "type": "text" },
                "event.original":    { "type": "text", "index": false },
                "event.category":    { "type": "keyword" },
                "event.action":      { "type": "keyword" },
                "event.outcome":     { "type": "keyword" },
                "event.dataset":     { "type": "keyword" },
                "event.type_id":     { "type": "keyword" },
                "event.kind":        { "type": "keyword" },
                "source.ip":         { "type": "ip" },
                "source.port":       { "type": "integer" },
                "user.name":         { "type": "keyword" },
                "host.name":         { "type": "keyword" },
                "host.hostname":     { "type": "keyword" },
                "process.name":      { "type": "keyword" },
                "process.pid":       { "type": "integer" },
                "log_type":          { "type": "keyword" },
                "_parse_stage":      { "type": "keyword" },
                "matched":           { "type": "boolean" },
                "log.file.path":     { "type": "keyword" }
            }
        }
    });

    match client.put(&url).json(&mapping).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                eprintln!("[ES] Created index '{}' with ECS mappings", index);
            } else {
                let body = resp.text().await.unwrap_or_default();
                eprintln!("[ES] Failed to create index: {}", body);
            }
        }
        Err(e) => eprintln!("[ES] Connection failed: {}", e),
    }
}
