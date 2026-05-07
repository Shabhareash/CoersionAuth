use serde_json::{json, Map, Value};
use chrono::Utc;

pub trait Processor {
    fn process(&self, doc: &mut Map<String, Value>);
}

// ── Timestamp fallback ──
pub struct TimestampFallback;

impl Processor for TimestampFallback {
    fn process(&self, doc: &mut Map<String, Value>) {
        if !doc.contains_key("@timestamp") {
            let now = Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                .to_string();

            doc.insert("@timestamp".to_string(), json!(now));
            doc.insert("event.created".to_string(), json!(now));
        }
    }
}

// ── Fix duplicate message ──
pub struct NormalizeMessage;

impl Processor for NormalizeMessage {
    fn process(&self, doc: &mut Map<String, Value>) {
        if let Some(val) = doc.get("message") {
            if val.is_array() {
                if let Some(last) = val.as_array().and_then(|arr| arr.last()) {
                    doc.insert("message".to_string(), last.clone());
                }
            }
        }
    }
}

// ── Default ECS fields ──
pub struct DefaultFields;

impl Processor for DefaultFields {
    fn process(&self, doc: &mut Map<String, Value>) {
        doc.entry("event.kind".to_string())
            .or_insert_with(|| json!("event"));

        doc.entry("event.dataset".to_string())
            .or_insert_with(|| json!("generic"));
    }
}