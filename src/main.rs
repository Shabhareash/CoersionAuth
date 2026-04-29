use my_scanner::log_types::{detect_log_type, build_grok_for_type};
use my_scanner::extraction::{extract_fields, ensure_index};
use serde_json::{json, Map};
use std::fs;
use std::io::{BufRead, BufReader};
use std::env;
use reqwest::blocking::Client;

// ─── main ─────────────────────────────────────────────────────────────────────
fn main() {
    dotenv::dotenv().ok();

    let username  = env::var("ES_USERNAME")
        .unwrap_or_else(|_| "elastic".to_string());
    let password  = env::var("ES_PASSWORD")
        .unwrap_or_else(|_| "changeme".to_string());
    let es_base   = env::var("ES_HOST")
        .unwrap_or_else(|_| "http://127.0.0.1:9200".to_string());
    // Note: We use the /_bulk endpoint for high-speed ingestion
    let bulk_url  = format!("{}/logs/_bulk", es_base);

    let log_file_path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: cargo run -- /path/to/logfile.log [/path/to/patterns/ecs-v1]");
        std::process::exit(1);
    });

    let patterns_root = env::args().nth(2).unwrap_or_else(|| {
        env::var("PATTERNS_DIR").unwrap_or_else(|_| {
            format!("{}/logstash-patterns-core/patterns/ecs-v1",
                env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
        })
    });

    println!("[INIT] Log file    : {}", log_file_path);
    println!("[INIT] Patterns dir: {}", patterns_root);

    let log_type = detect_log_type(&log_file_path, 20);
    println!("[INIT] Detected log type: {:?} ({})", log_type, log_type.as_str());

    let (_grok, pattern) = build_grok_for_type(log_type, &patterns_root);
    println!("[INIT] Compiled top pattern: {}", log_type.top_pattern());

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    ensure_index(&client, &es_base, &username, &password);

    let file = fs::File::open(&log_file_path).expect("Cannot open log file");
    let reader = BufReader::new(file);

    let mut sent = 0usize;
    let mut failed = 0usize;
    let mut bulk_body = String::new();
    let batch_size = 500; // Optimal for balancing memory and network overhead

    println!("[START] Ingesting logs...");

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => { eprintln!("Read error: {}", e); continue; }
        };
        
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let mut doc = Map::new();
        doc.insert("event.original".to_string(), json!(line));
        doc.insert("message".to_string(),        json!(line));
        doc.insert("log.file.path".to_string(),  json!(log_file_path));
        doc.insert("@version".to_string(),       json!("1"));
        doc.insert("log_type".to_string(),       json!(log_type.as_str()));
        doc.insert("event.dataset".to_string(),  json!(log_type.as_str()));

        // Apply Grok extraction
        if let Some(m) = pattern.match_against(&line) {
            extract_fields(&m, &mut doc, log_type);
            doc.insert("matched".to_string(), json!(true));
        } else {
            doc.insert("matched".to_string(), json!(false));
            doc.insert("tags".to_string(),    json!(["_grokparsefailure"]));
        }

        // --- BULK FORMATTING ---
        // 1. Action line: telling ES to index this document
        bulk_body.push_str("{\"index\":{}}\n");
        // 2. Data line: the actual JSON document
        bulk_body.push_str(&serde_json::to_string(&doc).unwrap());
        bulk_body.push('\n');

        sent += 1;

        // Ship the batch once it hits the threshold
        if sent % batch_size == 0 {
            match client.post(&bulk_url)
                .basic_auth(&username, Some(&password))
                .header("Content-Type", "application/x-ndjson")
                .body(bulk_body.clone())
                .send() 
            {
                Ok(resp) if resp.status().is_success() => {
                    println!("[BATCH OK] Processed {} logs", sent);
                }
                Ok(resp) => {
                    eprintln!("[BATCH FAIL] Status: {} - {}", resp.status(), resp.text().unwrap_or_default());
                    failed += batch_size;
                }
                Err(e) => {
                    eprintln!("[BATCH ERR] Network Error: {}", e);
                    failed += batch_size;
                }
            }
            bulk_body.clear();
        }
    }

    // Final "Cleanup" batch for the remaining lines
    if !bulk_body.is_empty() {
        let _ = client.post(&bulk_url)
            .basic_auth(&username, Some(&password))
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_body)
            .send();
        println!("[FINISH] Final batch sent.");
    }

    println!("\n✅ Processing Complete — {} total logs processed, approx {} failed.", sent, failed);
}