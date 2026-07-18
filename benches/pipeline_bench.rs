/// Benchmarks: Three-tier YAML pipeline vs legacy Grok pipeline.
///
/// Run with: cargo bench

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

use my_scanner::yaml_config::load_yaml_config;
use my_scanner::pipeline::Pipeline;
use my_scanner::log_types::{detect_log_type, build_grok_for_type, LogType};
use my_scanner::extraction::{extract_fields, try_match_patterns};

use my_scanner::{FieldVec, FieldValue};

use rayon::prelude::*;

fn load_lines(path: &str) -> Vec<String> {
    let f = fs::File::open(path).expect("Cannot open log file for benchmark");
    BufReader::new(f)
        .lines()
        .filter_map(|r| r.ok())
        .filter(|l| !l.trim().is_empty())
        .collect()
}

fn bench_yaml_pipeline(c: &mut Criterion) {
    let yaml_path = "ssh.yaml";
    let log_path_env = std::env::var("BENCH_LOG_FILE")
        .unwrap_or_else(|_| "/home/shabh/Downloads/OpenSSH_2k.log".to_string());

    if !Path::new(&log_path_env).exists() {
        eprintln!("[SKIP] Benchmark log file not found: {}", log_path_env);
        return;
    }
    if !Path::new(yaml_path).exists() {
        eprintln!("[SKIP] YAML config not found: {}", yaml_path);
        return;
    }

    let lines = load_lines(&log_path_env);
    let config = load_yaml_config(Path::new(yaml_path)).expect("Cannot load YAML");
    let pipeline = Pipeline::from_config(&config);

    let mut group = c.benchmark_group("parse_pipeline");
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(lines.len() as u64));

    // ── YAML Pipeline (single-threaded) ──
    group.bench_with_input(
        BenchmarkId::new("yaml_single_thread", lines.len()),
        &lines,
        |b, lines| {
            b.iter(|| {
                let mut count = 0;
                for line in lines {
                    let _doc = pipeline.process_line(line);
                    count += 1;
                }
                count
            });
        },
    );

    // ── YAML Pipeline (parallel / rayon) ──
    group.bench_with_input(
        BenchmarkId::new("yaml_parallel", lines.len()),
        &lines,
        |b, lines| {
            b.iter(|| {
                let docs: Vec<_> = lines
                    .par_iter()
                    .map(|line| pipeline.process_line(line))
                    .collect();
                docs.len()
            });
        },
    );

    // ── Legacy Grok (single-threaded) ──
    let log_type = detect_log_type(&log_path_env, 20);
    let patterns_root = format!(
        "{}/logstash-patterns-core/patterns/ecs-v1",
        std::env::var("HOME").unwrap()
    );
    let (_grok, patterns) = build_grok_for_type(log_type, &patterns_root);

    group.bench_with_input(
        BenchmarkId::new("grok_single_thread", lines.len()),
        &lines,
        |b, lines| {
            b.iter(|| {
                let mut count = 0;
                for line in lines {
                    let trimmed = line.trim();
                    let mut doc = FieldVec::new();
                    doc.insert("event.original", FieldValue::Str(trimmed.to_string()));
                    if let Some(m) = try_match_patterns(&patterns, trimmed) {
                        extract_fields(&m, &mut doc, log_type);
                    }
                    count += 1;
                }
                count
            });
        },
    );

    // ── Legacy Grok (parallel / rayon) ──
    group.bench_with_input(
        BenchmarkId::new("grok_parallel", lines.len()),
        &lines,
        |b, lines| {
            b.iter(|| {
                let docs: Vec<_> = lines
                    .par_iter()
                    .map(|line| {
                        let trimmed = line.trim();
                        let mut doc = FieldVec::new();
                        doc.insert("event.original", FieldValue::Str(trimmed.to_string()));
                        if let Some(m) = try_match_patterns(&patterns, trimmed) {
                            extract_fields(&m, &mut doc, log_type);
                        }
                        doc
                    })
                    .collect();
                docs.len()
            });
        },
    );

    group.finish();
}

criterion_group!(benches, bench_yaml_pipeline);
criterion_main!(benches);
