use serde_json::{json, Map, Value};
use reqwest::blocking::Client;
use crate::log_types::LogType;
use crate::{as_int, as_float, set, set_str};

// ─── Timestamp Conversion ─────────────────────────────────────────────────────

pub fn to_timestamp(raw: &str) -> String {
    // RFC 3339 / ISO 8601 with timezone
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return dt.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    }
    // ISO 8601 without timezone
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f") {
        return dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    }
    // Apache common log format: "27/Apr/2026:15:24:57 +0000"
    if let Ok(dt) = chrono::DateTime::parse_from_str(raw, "%d/%b/%Y:%H:%M:%S %z") {
        return dt.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    }
    // Syslog legacy "Apr 27 15:24:57" — append current year
    let year = chrono::Local::now().format("%Y").to_string();
    for fmt in &["%b %e %H:%M:%S %Y", "%b %d %H:%M:%S %Y"] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&format!("{} {}", raw, year), fmt) {
            return dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        }
    }
    raw.to_string()
}

// ─── Field Extraction ─────────────────────────────────────────────────────────
//
// Rules applied uniformly across all log types:
//
//  1. event.original = full raw line  (set in main, never changed here)
//     message        = cleaned human payload only (program message, HTTP
//                      summary line, DB message — per-type logic below)
//
//  2. ECS dot-notation keys everywhere:
//       host.name / process.name / process.pid /
//       source.ip / url.original / http.request.method …
//
//  3. Proper Rust → JSON types:
//       integers  → i64  via as_int()   (pid, status code, bytes, ports)
//       floats    → f64  via as_float() (duration, lease time)
//       timestamps→ ISO-8601 string     (ES date type)
//       everything else → &str

pub fn extract_fields(m: &grok::Matches, doc: &mut Map<String, Value>, log_type: LogType) {
    // ── Timestamp (universal) ─────────────────────────────────────────────────
    let ts_candidates = [
        "[log][syslog][timestamp]",        // SYSLOGLINE (linux-syslog ECS)
        "[apache2][access][time]",          // HTTPD_COMBINEDLOG (httpd ECS)
        "[postgresql][log][timestamp]",
        "[mongodb][log][timestamp]",
        "[redis][log][timestamp]",
        "timestamp",                        // generic fallback
    ];
    for cand in &ts_candidates {
        if let Some(v) = m.get(cand) {
            if !v.is_empty() {
                let iso = to_timestamp(v);
                doc.insert("@timestamp".to_string(), json!(iso));
                // event.created = when the event was observed (same as @timestamp here)
                doc.insert("event.created".to_string(), json!(iso));
                break;
            }
        }
    }

    // ── Per-type field extraction ─────────────────────────────────────────────
    match log_type {

        // ── Syslog family ─────────────────────────────────────────────────────
        LogType::Systemd | LogType::Syslog | LogType::Auth
        | LogType::Kernel | LogType::Dhcp | LogType::Firewall => {

            // ECS: host object
            if let Some(v) = m.get("[log][syslog][hostname]").or_else(|| m.get("host_name")) {
                set_str(doc, "host.name", v);
            }

            // ECS: process object — name + pid as integer
            if let Some(v) = m.get("[log][syslog][appname]").or_else(|| m.get("program")) {
                set_str(doc, "process.name", v);
            }
            if let Some(v) = m.get("[log][syslog][procid]").or_else(|| m.get("pid")) {
                let int_val = as_int(v);
                if int_val != Value::Null {
                    set(doc, "process.pid", int_val);
                } else {
                    // "-" or non-numeric procid — keep as keyword so it's not lost
                    set_str(doc, "process.pid_raw", v);
                }
            }

            // ECS: log.syslog.severity / facility when present
            if let Some(v) = m.get("[log][syslog][severity][name]") {
                set_str(doc, "log.syslog.severity.name", v);
            }
            if let Some(v) = m.get("[log][syslog][facility][name]") {
                set_str(doc, "log.syslog.facility.name", v);
            }

            // message = payload only (everything after "program[pid]: ")
            if let Some(v) = m.get("[log][syslog][message]").or_else(|| m.get("log_message")) {
                set_str(doc, "message", v);
            }

            // Auth-specific event classification
            if log_type == LogType::Auth {
                let payload = doc.get("message").and_then(|v| v.as_str()).unwrap_or("");
                if payload.contains("Accepted") {
                    set_str(doc, "event.outcome",  "success");
                    set_str(doc, "event.category", "authentication");
                    set_str(doc, "event.type",     "start");
                } else if payload.contains("Failed") || payload.contains("Invalid") {
                    set_str(doc, "event.outcome",  "failure");
                    set_str(doc, "event.category", "authentication");
                    set_str(doc, "event.type",     "start");
                }
            }
        }

        // ── Apache / HTTPD ────────────────────────────────────────────────────
        LogType::Apache => {

            // ECS: source object
            if let Some(v) = m.get("[source][address]").or_else(|| m.get("clientip")) {
                set_str(doc, "source.ip",      v);
                set_str(doc, "source.address", v);
            }

            // ECS: url object
            if let Some(v) = m.get("[url][original]").or_else(|| m.get("request")) {
                set_str(doc, "url.original", v);
            }

            // ECS: http object
            if let Some(v) = m.get("[http][request][method]").or_else(|| m.get("verb")) {
                set_str(doc, "http.request.method", v);
            }
            if let Some(v) = m.get("[http][version]").or_else(|| m.get("httpversion")) {
                set_str(doc, "http.version", v);
            }
            // status code → integer
            if let Some(v) = m.get("[http][response][status_code]").or_else(|| m.get("response")) {
                set(doc, "http.response.status_code", as_int(v));
            }
            // bytes → long
            if let Some(v) = m.get("[http][response][body][bytes]").or_else(|| m.get("bytes")) {
                set(doc, "http.response.body.bytes", as_int(v));
            }

            // ECS: user_agent object
            if let Some(v) = m.get("[user_agent][original]").or_else(|| m.get("agent")) {
                set_str(doc, "user_agent.original", v);
            }
            if let Some(v) = m.get("[http][request][referrer]").or_else(|| m.get("referrer")) {
                if v != "-" { set_str(doc, "http.request.referrer", v); }
            }

            // ECS: user object
            if let Some(v) = m.get("[apache2][access][user][name]").or_else(|| m.get("auth")) {
                if v != "-" { set_str(doc, "user.name", v); }
            }

            // message = concise human summary, NOT the raw line
            let method = doc.get("http.request.method").and_then(|v| v.as_str()).unwrap_or("-");
            let url    = doc.get("url.original").and_then(|v| v.as_str()).unwrap_or("-");
            let status = doc.get("http.response.status_code")
                .map(|v| v.to_string()).unwrap_or_else(|| "-".to_string());
            doc.insert("message".to_string(), json!(format!("{} {} -> {}", method, url, status)));

            // ECS event classification for HTTP
            set_str(doc, "event.category", "web");
            set_str(doc, "event.type",     "access");
        }

        // ── MongoDB ───────────────────────────────────────────────────────────
        LogType::Mongodb => {
            if let Some(v) = m.get("[mongodb][log][severity]") {
                set_str(doc, "log.level", v);
            }
            if let Some(v) = m.get("[mongodb][log][component]") {
                set_str(doc, "mongodb.log.component", v);
            }
            if let Some(v) = m.get("[mongodb][log][context]") {
                set_str(doc, "mongodb.log.context", v);
            }
            // message = the mongo log text, not the full line
            if let Some(v) = m.get("[mongodb][log][message]") {
                set_str(doc, "message",              v);
                set_str(doc, "mongodb.log.message",  v);
            }
            set_str(doc, "event.category", "database");
        }

        // ── Redis ─────────────────────────────────────────────────────────────
        LogType::Redis => {
            // process.pid → integer
            if let Some(v) = m.get("[process][pid]").or_else(|| m.get("pid")) {
                set(doc, "process.pid", as_int(v));
            }
            if let Some(v) = m.get("[redis][log][message]") {
                set_str(doc, "message",             v);
                set_str(doc, "redis.log.message",   v);
            }
            set_str(doc, "event.category", "database");
        }

        // ── PostgreSQL ────────────────────────────────────────────────────────
        LogType::Postgresql => {
            if let Some(v) = m.get("[postgresql][log][timezone]") {
                set_str(doc, "postgresql.log.timezone", v);
            }
            if let Some(v) = m.get("[postgresql][log][session_id]") {
                set_str(doc, "postgresql.log.session_id", v);
            }
            if let Some(v) = m.get("[postgresql][log][message]") {
                set_str(doc, "message",                   v);
                set_str(doc, "postgresql.log.message",    v);
            }
            set_str(doc, "event.category", "database");
        }

        // ── Zeek ──────────────────────────────────────────────────────────────
        LogType::Zeek | LogType::ZeekDhcp => {
            // Source / destination in ECS style
            if let Some(v) = m.get("id.orig_h") { set_str(doc, "source.ip",       v); }
            if let Some(v) = m.get("id.orig_p") { set(doc, "source.port",         as_int(v)); }
            if let Some(v) = m.get("id.resp_h") { set_str(doc, "destination.ip",  v); }
            if let Some(v) = m.get("id.resp_p") { set(doc, "destination.port",    as_int(v)); }
            if let Some(v) = m.get("proto")      { set_str(doc, "network.transport", v); }
            if let Some(v) = m.get("uid")        { set_str(doc, "zeek.session_id",   v); }

            // Zeek-specific extras
            if let Some(v) = m.get("assigned_ip") { set_str(doc, "zeek.dhcp.assigned_ip", v); }
            if let Some(v) = m.get("lease_time")  { set(doc, "zeek.dhcp.lease_time", as_float(v)); }

            // message = connection summary
            let src  = doc.get("source.ip").and_then(|v| v.as_str()).unwrap_or("-");
            let dst  = doc.get("destination.ip").and_then(|v| v.as_str()).unwrap_or("-");
            let port = doc.get("destination.port").map(|v| v.to_string()).unwrap_or_else(|| "-".to_string());
            doc.insert("message".to_string(), json!(format!("{} -> {}:{}", src, dst, port)));

            set_str(doc, "event.category", "network");
        }

        LogType::Unknown => {
            // message stays as the raw line (set in main) — nothing more to extract
        }
    }

    // ── ECS baseline (all types) ──────────────────────────────────────────────
    doc.entry("event.kind".to_string()).or_insert_with(|| json!("event"));
}

// ─── Elasticsearch Index Management ────────────────────────────────────────────

pub fn ensure_index(client: &Client, es_base: &str, username: &str, password: &str) {
    let index_url = format!("{}/logs", es_base);
    let exists = client.head(&index_url)
        .basic_auth(username, Some(password))
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if exists { return; }

    let mapping = json!({
        "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
        "mappings": {
            "dynamic_templates": [
                // Any field whose name contains "message" or "original" → text+keyword
                {
                    "text_message_fields": {
                        "match_mapping_type": "string",
                        "match": "*message*",
                        "mapping": { "type": "text",
                            "fields": { "keyword": { "type": "keyword", "ignore_above": 10000 } } }
                    }
                },
                {
                    "text_original_fields": {
                        "match_mapping_type": "string",
                        "match": "*original*",
                        "mapping": { "type": "text",
                            "fields": { "keyword": { "type": "keyword", "ignore_above": 10000 } } }
                    }
                },
                // All other strings → keyword (avoids useless text analysis on IPs, paths, etc.)
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": { "type": "keyword", "ignore_above": 1024 }
                    }
                }
            ],
            "properties": {
                // ── ECS base ─────────────────────────────────────────────────
                "@timestamp":          { "type": "date" },
                "event.created":       { "type": "date" },
                "event.original": {
                    "type": "text",
                    "fields": { "keyword": { "type": "keyword", "ignore_above": 10000 } }
                },
                "event.kind":          { "type": "keyword" },
                "event.category":      { "type": "keyword" },
                "event.type":          { "type": "keyword" },
                "event.outcome":       { "type": "keyword" },
                "event.dataset":       { "type": "keyword" },
                "@version":            { "type": "keyword" },
                "log_type":            { "type": "keyword" },
                "log.level":           { "type": "keyword" },
                "log.syslog.severity.name": { "type": "keyword" },
                "log.syslog.facility.name": { "type": "keyword" },
                "log.file.path":       { "type": "keyword" },
                "matched":             { "type": "boolean" },
                "tags":                { "type": "keyword" },

                // message = cleaned payload (NOT the raw line — that is event.original)
                "message": {
                    "type": "text",
                    "fields": { "keyword": { "type": "keyword", "ignore_above": 10000 } }
                },

                // ── host / process ────────────────────────────────────────────
                "host.name":           { "type": "keyword" },
                "process.name":        { "type": "keyword" },
                "process.pid":         { "type": "long" },
                "process.pid_raw":     { "type": "keyword" },

                // ── network / source / destination ────────────────────────────
                "source.ip":           { "type": "ip" },
                "source.address":      { "type": "keyword" },
                "source.port":         { "type": "integer" },
                "destination.ip":      { "type": "ip" },
                "destination.port":    { "type": "integer" },
                "network.transport":   { "type": "keyword" },

                // ── HTTP ──────────────────────────────────────────────────────
                "url.original":                  { "type": "keyword" },
                "http.request.method":           { "type": "keyword" },
                "http.request.referrer":         { "type": "keyword" },
                "http.version":                  { "type": "keyword" },
                "http.response.status_code":     { "type": "integer" },
                "http.response.body.bytes":      { "type": "long" },
                "user_agent.original": {
                    "type": "text",
                    "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 } }
                },
                "user.name": { "type": "keyword" },

                // ── MongoDB ───────────────────────────────────────────────────
                "mongodb.log.component": { "type": "keyword" },
                "mongodb.log.context":   { "type": "keyword" },
                "mongodb.log.message":   { "type": "text",
                    "fields": { "keyword": { "type": "keyword", "ignore_above": 10000 } } },

                // ── Redis ─────────────────────────────────────────────────────
                "redis.log.message": { "type": "text",
                    "fields": { "keyword": { "type": "keyword", "ignore_above": 10000 } } },

                // ── PostgreSQL ────────────────────────────────────────────────
                "postgresql.log.session_id": { "type": "keyword" },
                "postgresql.log.timezone":   { "type": "keyword" },
                "postgresql.log.message":    { "type": "text",
                    "fields": { "keyword": { "type": "keyword", "ignore_above": 10000 } } },

                // ── Zeek ──────────────────────────────────────────────────────
                "zeek.session_id":       { "type": "keyword" },
                "zeek.dhcp.assigned_ip": { "type": "ip" },
                "zeek.dhcp.lease_time":  { "type": "float" }
            }
        }
    });

    let res = client.put(&index_url)
        .basic_auth(username, Some(password))
        .json(&mapping)
        .send();

    match res {
        Ok(r) if r.status().is_success() =>
            println!("[INIT] Index 'logs' created with ECS mapping."),
        Ok(r) =>
            eprintln!("[INIT] Mapping warning: {} — {}", r.status(),
                r.text().unwrap_or_default()),
        Err(e) =>
            eprintln!("[INIT] Could not create index: {}", e),
    }
}
