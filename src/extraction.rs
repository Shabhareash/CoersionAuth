use serde_json::{json, Map, Value};
use reqwest::blocking::Client;
use crate::log_types::LogType;
use crate::{as_int, as_float, set, set_str};
use chrono::Utc;

// ─── Timestamp Conversion ───────────────────────────────────────────

pub fn to_timestamp(raw: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return dt.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f") {
        return dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    }
    if let Ok(dt) = chrono::DateTime::parse_from_str(raw, "%d/%b/%Y:%H:%M:%S %z") {
        return dt.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    }

    let year = chrono::Local::now().format("%Y").to_string();
    for fmt in &["%b %e %H:%M:%S %Y", "%b %d %H:%M:%S %Y"] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&format!("{} {}", raw, year), fmt) {
            return dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        }
    }
    raw.to_string()
}

// ─── Field Extraction ───────────────────────────────────────────────

pub fn extract_fields(m: &grok::Matches, doc: &mut Map<String, Value>, log_type: LogType) {

    // ── FAST ISO TIMESTAMP ───────────────────────────────────────────
    if let Some(raw) = doc.get("event.original").and_then(|v| v.as_str()) {
        if raw.len() > 20 && raw.as_bytes().get(4) == Some(&b'-') {
            if let Some(ts) = raw.split_whitespace().next() {
                let iso = to_timestamp(ts);
                doc.insert("@timestamp".to_string(), json!(iso));
                doc.insert("event.created".to_string(), json!(iso));
            }
        }
    }
// ── FAST PROCESS EXTRACTION ──────────────────────────────────────
let raw_opt = doc.get("event.original")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());   

if let Some(raw) = raw_opt {
    let parts: Vec<&str> = raw.split_whitespace().collect();

    if parts.len() >= 3 {
        let proc_part = parts[2];

        let proc_clean = proc_part.trim_end_matches(':');

        if let Some(start) = proc_clean.find('[') {
            if let Some(end) = proc_clean.find(']') {
                let name = &proc_clean[..start];
                let pid_str = &proc_clean[start + 1..end];

                doc.insert("process.name".to_string(), json!(name));

                if let Ok(pid) = pid_str.parse::<i64>() {
                    doc.insert("process.pid".to_string(), json!(pid));
                }
            }
        } else {
            doc.insert("process.name".to_string(), json!(proc_clean));
        }
    }
}

    // ── GROK TIMESTAMP FALLBACK ──────────────────────────────────────
    if !doc.contains_key("@timestamp") {
        let ts_candidates = [
            "[log][syslog][timestamp]",
            "[apache2][access][time]",
            "[postgresql][log][timestamp]",
            "[mongodb][log][timestamp]",
            "[redis][log][timestamp]",
            "timestamp",
        ];

        for cand in &ts_candidates {
            if let Some(v) = m.get(cand) {
                if !v.is_empty() {
                    let iso = to_timestamp(v);
                    doc.insert("@timestamp".to_string(), json!(iso));
                    doc.insert("event.created".to_string(), json!(iso));
                    break;
                }
            }
        }
    }

    // ── PER-TYPE EXTRACTION ──────────────────────────────────────────
    match log_type {

        LogType::Systemd | LogType::Syslog | LogType::Auth
        | LogType::Kernel | LogType::Dhcp | LogType::Firewall => {

            if let Some(v) = m.get("[host][hostname]")
                .or_else(|| m.get("[log][syslog][hostname]"))
                .or_else(|| m.get("logsource"))
                .or_else(|| m.get("host_name"))
            {
                set_str(doc, "host.name", v);
                set_str(doc, "host.hostname", v);
            }

            if let Some(v) = m.get("program")
                .or_else(|| m.get("[log][syslog][appname]"))
            {
                set_str(doc, "process.name", v);
            }

            if let Some(v) = m.get("pid")
                .or_else(|| m.get("[log][syslog][procid]"))
            {
                let int_val = as_int(v);
                if int_val != Value::Null {
                    set(doc, "process.pid", int_val);
                } else {
                    set_str(doc, "process.pid_raw", v);
                }
            }

            if let Some(v) = m.get("message")
                .or_else(|| m.get("[log][syslog][message]"))
            {
                set_str(doc, "message", v);
            }
        }

        LogType::Apache => {
            if let Some(v) = m.get("[source][address]").or_else(|| m.get("clientip")) {
                set_str(doc, "source.ip", v);
                set_str(doc, "source.address", v);
            }

            if let Some(v) = m.get("[url][original]").or_else(|| m.get("request")) {
                set_str(doc, "url.original", v);
            }

            if let Some(v) = m.get("[http][request][method]").or_else(|| m.get("verb")) {
                set_str(doc, "http.request.method", v);
            }

            if let Some(v) = m.get("[http][response][status_code]").or_else(|| m.get("response")) {
                set(doc, "http.response.status_code", as_int(v));
            }

            let method = doc.get("http.request.method").and_then(|v| v.as_str()).unwrap_or("-");
            let url = doc.get("url.original").and_then(|v| v.as_str()).unwrap_or("-");
            let status = doc.get("http.response.status_code")
                .map(|v| v.to_string()).unwrap_or_else(|| "-".to_string());

            doc.insert("message".to_string(), json!(format!("{} {} -> {}", method, url, status)));
        }

        _ => {}
    }

    // ── MESSAGE FALLBACK ─────────────────────────────────────────────
    if !doc.contains_key("message") {
        if let Some(raw) = doc.get("event.original") {
            doc.insert("message".to_string(), raw.clone());
        }
    }

    // ── FINAL TIMESTAMP FALLBACK ─────────────────────────────────────
    if !doc.contains_key("@timestamp") {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        doc.insert("@timestamp".to_string(), json!(now));
        doc.insert("event.created".to_string(), json!(now));
    }

    doc.entry("event.kind".to_string()).or_insert_with(|| json!("event"));
}

// ─── Elasticsearch Index ────────────────────────────────────────────

pub fn ensure_index(client: &Client, es_base: &str, username: &str, password: &str) {
    let index_url = format!("{}/logs", es_base);
    let exists = client.head(&index_url)
        .basic_auth(username, Some(password))
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if exists { return; }

    let mapping = json!({
        "settings": { "number_of_shards": 1, "number_of_replicas": 0 }
    });

    let _ = client.put(&index_url)
        .basic_auth(username, Some(password))
        .json(&mapping)
        .send();
}