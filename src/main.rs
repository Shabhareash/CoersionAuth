use my_scanner::log_types::{detect_log_type, build_grok_for_type};
use my_scanner::extraction::{extract_fields, ensure_index};
use my_scanner::processors::{Processor, TimestampFallback, NormalizeMessage, DefaultFields};

use serde_json::{json, Map};
use std::fs;
use std::io::{BufRead, BufReader};
use std::env;
use reqwest::blocking::Client;
use std::path::Path;

fn main() {
    dotenv::dotenv().ok();

    let username = env::var("ES_USERNAME").unwrap_or("elastic".to_string());
    let password = env::var("ES_PASSWORD").unwrap_or("changeme".to_string());
    let es_base  = env::var("ES_HOST").unwrap_or("http://127.0.0.1:9200".to_string());
    let bulk_url = format!("{}/logs/_bulk", es_base);

    let log_file_path = env::args().nth(1).expect("log file required");

    let patterns_root = env::args().nth(2).unwrap_or_else(|| {
        format!("{}/logstash-patterns-core/patterns/ecs-v1",
            env::var("HOME").unwrap())
    });

    let log_type = detect_log_type(&log_file_path, 20);
    let (_grok, pattern) = build_grok_for_type(log_type, &patterns_root);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    ensure_index(&client, &es_base, &username, &password);

    let processors: Vec<Box<dyn Processor>> = vec![
        Box::new(NormalizeMessage),
        Box::new(TimestampFallback),
        Box::new(DefaultFields),
    ];

    let file = fs::File::open(&log_file_path).unwrap();
    let reader = BufReader::new(file);

    let mut bulk_body = String::new();
    let batch_size = 500;
    let mut sent = 0;

    for line in reader.lines() {
        let line = line.unwrap();
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let mut doc = Map::new();

        // RAW
        doc.insert("event.original".to_string(), json!(trimmed));

        // ✅ ABSOLUTE PATH
        let abs_path = fs::canonicalize(&log_file_path)
            .unwrap_or_else(|_| Path::new(&log_file_path).to_path_buf());

        doc.insert(
            "log.file.path".to_string(),
            json!(abs_path.to_string_lossy())
        );

        doc.insert("@version".to_string(), json!("1"));
        doc.insert("log_type".to_string(), json!(log_type.as_str()));

        // ✅ TAGS
        doc.insert("tags".to_string(), json!(["fast-parser"]));

        // GROK
        if let Some(m) = pattern.match_against(trimmed) {
            extract_fields(&m, &mut doc, log_type);
            doc.insert("matched".to_string(), json!(true));
        } else {
            doc.insert("matched".to_string(), json!(false));
            doc.insert("message".to_string(), json!(trimmed));
        }

        // PROCESSORS
        for p in &processors {
            p.process(&mut doc);
        }

        // BULK
        bulk_body.push_str("{\"index\":{}}\n");
        bulk_body.push_str(&serde_json::to_string(&doc).unwrap());
        bulk_body.push('\n');

        sent += 1;

        if sent % batch_size == 0 {
            let _ = client.post(&bulk_url)
                .basic_auth(&username, Some(&password))
                .header("Content-Type", "application/x-ndjson")
                .body(bulk_body.clone())
                .send();
            bulk_body.clear();
        }
    }

    if !bulk_body.is_empty() {
        let _ = client.post(&bulk_url)
            .basic_auth(&username, Some(&password))
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_body)
            .send();
    }

    println!("✅ Done: {} logs", sent);
}