use reqwest::Client;
use crate::log_types::LogType;
use crate::{as_int, set, set_str, FieldVec, FieldValue};
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

// ─── Multi-Pattern Matching ─────────────────────────────────────────

/// Tries each compiled pattern in order; returns the first successful match.
/// This mirrors Logstash's multi-pattern grok behavior (try alternatives,
/// use the first hit, fall through to the next on failure).
pub fn try_match_patterns<'a>(
    patterns: &'a [grok::Pattern],
    text: &'a str,
) -> Option<grok::Matches<'a>> {
    for pattern in patterns {
        if let Some(m) = pattern.match_against(text) {
            return Some(m);
        }
    }
    None
}

// ─── Field Extraction ───────────────────────────────────────────────

pub fn extract_fields(m: &grok::Matches, doc: &mut FieldVec, log_type: LogType) {

    // ── FAST ISO TIMESTAMP ───────────────────────────────────────────
    if let Some(raw) = doc.get("event.original").and_then(|v| v.as_str()) {
        if raw.len() > 20 && raw.as_bytes().get(4) == Some(&b'-') {
            if let Some(ts) = raw.split_whitespace().next() {
                let iso = to_timestamp(ts);
                doc.insert("@timestamp", FieldValue::Str(iso.clone()));
                doc.insert("event.created", FieldValue::Str(iso));
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
                    doc.insert("@timestamp", FieldValue::Str(iso.clone()));
                    doc.insert("event.created", FieldValue::Str(iso));
                    break;
                }
            }
        }
    }

    // ── DYNAMIC FIELD EXTRACTION ─────────────────────────────────────
    // Loop through all named captures from the pattern and insert them!
    for (key, value) in m.iter() {
        if !value.is_empty() && !key.starts_with("UNWANTED") && key != "message" && key != "@timestamp" {
            let int_val = as_int(value);
            if !int_val.is_null() {
                set(doc, key.to_string(), int_val);
            } else {
                set_str(doc, key.to_string(), value);
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
                if !int_val.is_null() {
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
                .map(|v| v.to_string_lossy()).unwrap_or_else(|| "-".to_string());

            doc.insert("message", FieldValue::Str(format!("{} {} -> {}", method, url, status)));
        }

        _ => {}
    }

    // ── MESSAGE FALLBACK ─────────────────────────────────────────────
    if !doc.contains_key("message") {
        let raw_clone = doc.get("event.original").cloned();
        if let Some(raw) = raw_clone {
            doc.insert("message", raw);
        }
    }

    // ── FINAL TIMESTAMP FALLBACK ─────────────────────────────────────
    if !doc.contains_key("@timestamp") {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        doc.insert("@timestamp", FieldValue::Str(now.clone()));
        doc.insert("event.created", FieldValue::Str(now));
    }

    doc.or_insert("event.kind", FieldValue::StaticStr("event"));
}

// ─── Elasticsearch Index (async) ────────────────────────────────────

pub async fn ensure_index(client: &Client, es_base: &str, username: &str, password: &str) {
    let index_url = format!("{}/logs", es_base);
    let exists = client.head(&index_url)
        .basic_auth(username, Some(password))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if exists { return; }

    let mapping = serde_json::json!({
        "settings": { "number_of_shards": 1, "number_of_replicas": 0 }
    });

    let _ = client.put(&index_url)
        .basic_auth(username, Some(password))
        .json(&mapping)
        .send()
        .await;
}

// ─── Async Bulk Send ────────────────────────────────────────────────

/// Sends a bulk NDJSON body to Elasticsearch asynchronously.
/// Returns Ok(count) of documents in the batch, or an error string.
pub async fn send_bulk(
    client: &Client,
    bulk_url: &str,
    username: &str,
    password: &str,
    body: String,
    doc_count: usize,
) -> Result<usize, String> {
    let resp = client
        .post(bulk_url)
        .basic_auth(username, Some(password))
        .header("Content-Type", "application/x-ndjson")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("HTTP send failed: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("ES responded {}: {}", status, body_text));
    }

    Ok(doc_count)
}