use my_scanner::log_types::{detect_log_type, build_grok_for_type};
use my_scanner::extraction::{extract_fields, ensure_index, try_match_patterns, send_bulk};
use my_scanner::processors::{Processor, TimestampFallback, NormalizeMessage, DefaultFields};
use my_scanner::yaml_config::load_yaml_config;
use my_scanner::pipeline::Pipeline;

use my_scanner::{FieldVec, FieldValue};

use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::env;
use std::path::Path;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use reqwest::Client;

/// Process 8192 lines at a time — large enough for good rayon parallelism,
/// small enough to keep resident memory low (~tens of MB per chunk).
const CHUNK_SIZE: usize = 8192;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let username = env::var("ES_USERNAME").unwrap_or("elastic".to_string());
    let password = env::var("ES_PASSWORD").unwrap_or("changeme".to_string());
    let es_base  = env::var("ES_HOST").unwrap_or("http://127.0.0.1:9200".to_string());
    let bulk_url = format!("{}/logs/_bulk", es_base);

    let log_file_path = env::args().nth(1).expect("Usage: my_scanner <log-file> [yaml-config | patterns-root]");
    let config_or_patterns = env::args().nth(2);

    // ── Check if a YAML pipeline config was provided ─────────────────
    let yaml_config = config_or_patterns.as_ref().and_then(|path| {
        if path.ends_with(".yaml") || path.ends_with(".yml") {
            match load_yaml_config(Path::new(path)) {
                Ok(cfg) => {
                    println!("[YAML]   Loaded pipeline config: {} (family: {})",
                        path, cfg.log_family);
                    Some(cfg)
                }
                Err(e) => {
                    eprintln!("[ERROR]  {}", e);
                    None
                }
            }
        } else {
            None
        }
    });

    // ── Output configuration ─────────────────────────────────────────
    println!("[INIT]   Output set to local file: rustlogger.json");

    // ── Read all lines into memory ───────────────────────────────────
    let t0 = Instant::now();
    let file = fs::File::open(&log_file_path).unwrap();
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines()
        .filter_map(|r| r.ok())
        .filter(|l| !l.trim().is_empty())
        .collect();
    let total_lines = lines.len();
    println!("[READ]   {} lines in {:?}", total_lines, t0.elapsed());

    // ── Prepare output file ──────────────────────────────────────────
    let out_file = fs::File::create("rustlogger.json").expect("Failed to create rustlogger.json");
    let mut writer = BufWriter::with_capacity(1 << 20, out_file);

    // ── Choose pipeline mode ─────────────────────────────────────────
    let abs_path = fs::canonicalize(&log_file_path)
        .unwrap_or_else(|_| Path::new(&log_file_path).to_path_buf());
    let abs_path_str = abs_path.to_string_lossy().to_string();

    let mut success_count = 0usize;
    let mut parse_dur = Duration::ZERO;
    let mut write_dur = Duration::ZERO;

    if let Some(ref yaml_cfg) = yaml_config {
        // ══════════════════════════════════════════════════════════════
        //  YAML-driven pipeline — chunked streaming
        // ══════════════════════════════════════════════════════════════
        let t1 = Instant::now();
        let pipeline = Pipeline::from_config(yaml_cfg);
        println!("[INIT]   Pipeline compiled in {:?}", t1.elapsed());
        println!("[INIT]   Signatures: {}, Specialized parsers: {}, Generic patterns: {}",
            yaml_cfg.pipeline.signatures.len(),
            yaml_cfg.pipeline.specialized_parsers.len(),
            yaml_cfg.pipeline.generic_parser.patterns.len(),
        );

        let log_family = yaml_cfg.log_family.clone();

        let mut specialized_matched = 0usize;
        let mut specialized_succeeded = 0usize;
        let mut generic_count = 0usize;
        let mut raw_count = 0usize;

        for chunk in lines.chunks(CHUNK_SIZE) {
            // ── Parse chunk in parallel ──────────────────────────────
            let tp = Instant::now();
            let chunk_docs: Vec<FieldVec> = chunk
                .par_iter()
                .map(|line| {
                    let mut doc = pipeline.process_line(line);

                    doc.insert("log.file.path", FieldValue::Str(abs_path_str.clone()));
                    doc.insert("@version", FieldValue::StaticStr("1"));
                    doc.insert("log_type", FieldValue::Str(log_family.clone()));
                    doc.insert("tags", FieldValue::Array(vec![
                        FieldValue::StaticStr("fast-parser"),
                        FieldValue::StaticStr("yaml-pipeline"),
                    ]));

                    doc.or_insert("event.dataset", FieldValue::StaticStr("generic"));

                    doc
                })
                .collect();
            parse_dur += tp.elapsed();

            // ── Accumulate stats ─────────────────────────────────────
            for doc in &chunk_docs {
                if doc.contains_key("event.type_id") {
                    specialized_matched += 1;
                }
                match doc.get("_parse_stage").and_then(|v| v.as_str()) {
                    Some("specialized") => specialized_succeeded += 1,
                    Some("generic") => generic_count += 1,
                    Some("raw") => raw_count += 1,
                    _ => {}
                }
            }

            // ── Serialize in parallel, write sequentially ────────────
            let tw = Instant::now();
            let buffers: Vec<Vec<u8>> = chunk_docs.par_iter().map(|doc| {
                let mut buf = Vec::with_capacity(512);
                serde_json::to_writer(&mut buf, doc).unwrap();
                buf.push(b'\n');
                buf
            }).collect();

            for buf in &buffers {
                writer.write_all(buf).unwrap();
            }
            success_count += buffers.len();
            write_dur += tw.elapsed();
            // chunk_docs + buffers dropped here — memory freed
        }

        let specialized_failed = specialized_matched.saturating_sub(specialized_succeeded);

        println!("[PARSE]  {} docs in {:?}", total_lines, parse_dur);
        println!("   ├─ Specialized matched:   {:>9}", specialized_matched);
        println!("   ├─ Specialized succeeded: {:>9}", specialized_succeeded);
        println!("   ├─ Specialized failed:    {:>9}", specialized_failed);
        println!("   ├─ Generic fallback:      {:>9}", generic_count);
        println!("   └─ Raw only:              {:>9}", raw_count);

    } else {
        // ══════════════════════════════════════════════════════════════
        //  LEGACY: Grok-based pipeline — chunked streaming
        // ══════════════════════════════════════════════════════════════
        let t1 = Instant::now();

        let patterns_root = config_or_patterns.unwrap_or_else(|| {
            format!("{}/logstash-patterns-core/patterns/ecs-v1",
                env::var("HOME").unwrap())
        });

        let log_type = detect_log_type(&log_file_path, 20);
        println!("[DETECT] Log type: {:?} (sampled in {:?})", log_type, t1.elapsed());

        let (_grok, patterns) = build_grok_for_type(log_type, &patterns_root);
        println!("[INIT]   Compiled {} pattern(s) in {:?}", patterns.len(), t1.elapsed());

        let processors: Vec<Box<dyn Processor + Send + Sync>> = vec![
            Box::new(NormalizeMessage),
            Box::new(TimestampFallback),
            Box::new(DefaultFields),
        ];

        let mut matched_count = 0usize;

        for chunk in lines.chunks(CHUNK_SIZE) {
            let tp = Instant::now();
            let chunk_docs: Vec<FieldVec> = chunk
                .par_iter()
                .map(|line| {
                    let trimmed = line.trim();
                    let mut doc = FieldVec::new();

                    doc.insert("event.original", FieldValue::Str(trimmed.to_string()));
                    doc.insert("log.file.path", FieldValue::Str(abs_path_str.clone()));
                    doc.insert("@version", FieldValue::StaticStr("1"));
                    doc.insert("log_type", FieldValue::Str(log_type.as_str().to_string()));
                    doc.insert("tags", FieldValue::Array(vec![
                        FieldValue::StaticStr("fast-parser"),
                    ]));

                    if let Some(m) = try_match_patterns(&patterns, trimmed) {
                        extract_fields(&m, &mut doc, log_type);
                        doc.insert("matched", FieldValue::Bool(true));
                    } else {
                        doc.insert("matched", FieldValue::Bool(false));
                        doc.insert("message", FieldValue::Str(trimmed.to_string()));
                    }

                    for p in &processors {
                        p.process(&mut doc);
                    }

                    doc
                })
                .collect();
            parse_dur += tp.elapsed();

            for doc in &chunk_docs {
                if doc.get("matched") == Some(&FieldValue::Bool(true)) {
                    matched_count += 1;
                }
            }

            let tw = Instant::now();
            let buffers: Vec<Vec<u8>> = chunk_docs.par_iter().map(|doc| {
                let mut buf = Vec::with_capacity(512);
                serde_json::to_writer(&mut buf, doc).unwrap();
                buf.push(b'\n');
                buf
            }).collect();

            for buf in &buffers {
                writer.write_all(buf).unwrap();
            }
            success_count += buffers.len();
            write_dur += tw.elapsed();
        }

        println!("[PARSE]  {} docs ({} matched, {} unmatched) in {:?}",
            total_lines, matched_count, total_lines - matched_count, parse_dur);
    }

    // ── Flush remaining buffered data ────────────────────────────────
    writer.flush().unwrap();
    println!("[WRITE]  {} docs to rustlogger.json in {:?}", success_count, write_dur);

    // ── Summary ──────────────────────────────────────────────────────
    println!();
    println!("✅ Done: {} logs processed in {:?} total", total_lines, t0.elapsed());
    if yaml_config.is_some() {
        println!("   └─ Pipeline: YAML three-tier (SIMD classifier → state-machine → regex fallback)");
    } else {
        println!("   └─ Pipeline: Legacy Grok");
    }
    println!("   └─ Written : {} docs to rustlogger.json", success_count);
}