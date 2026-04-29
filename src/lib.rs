#![recursion_limit = "256"]

use serde_json::{json, Map, Value};

pub mod log_types;
pub mod extraction;

// ─── Helper: Type Coercion ────────────────────────────────────────────────────

/// Parse a string to i64. Returns Value::Null on failure so callers can skip it.
pub fn as_int(s: &str) -> Value {
    match s.trim().parse::<i64>() {
        Ok(n)  => json!(n),
        Err(_) => Value::Null,
    }
}

/// Parse a string to f64. Returns Value::Null on failure.
pub fn as_float(s: &str) -> Value {
    match s.trim().parse::<f64>() {
        Ok(n)  => json!(n),
        Err(_) => Value::Null,
    }
}

/// Insert a value only when it is non-Null.
pub fn set(doc: &mut Map<String, Value>, key: &str, val: Value) {
    if val != Value::Null {
        doc.insert(key.to_string(), val);
    }
}

/// Insert a string value, skipping empty strings.
pub fn set_str(doc: &mut Map<String, Value>, key: &str, val: &str) {
    if !val.is_empty() {
        doc.insert(key.to_string(), json!(val));
    }
}
