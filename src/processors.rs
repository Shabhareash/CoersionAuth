use chrono::Utc;
use crate::{FieldVec, FieldValue};

pub trait Processor: Send + Sync {
    fn process(&self, doc: &mut FieldVec);
}

// ── Timestamp fallback ──
pub struct TimestampFallback;

impl Processor for TimestampFallback {
    fn process(&self, doc: &mut FieldVec) {
        if !doc.contains_key("@timestamp") {
            let now = Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                .to_string();

            doc.insert("@timestamp", FieldValue::Str(now.clone()));
            doc.insert("event.created", FieldValue::Str(now));
        }
    }
}

// ── Fix duplicate message ──
pub struct NormalizeMessage;

impl Processor for NormalizeMessage {
    fn process(&self, doc: &mut FieldVec) {
        if let Some(val) = doc.get("message") {
            if val.is_array() {
                if let Some(last) = val.as_array().and_then(|arr| arr.last()) {
                    let replacement = last.clone();
                    doc.insert("message", replacement);
                }
            }
        }
    }
}

// ── Default ECS fields ──
pub struct DefaultFields;

impl Processor for DefaultFields {
    fn process(&self, doc: &mut FieldVec) {
        doc.or_insert("event.kind", FieldValue::StaticStr("event"));
        doc.or_insert("event.dataset", FieldValue::StaticStr("generic"));
    }
}