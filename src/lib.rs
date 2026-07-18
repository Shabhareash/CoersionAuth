#![recursion_limit = "256"]

use serde::ser::{Serialize, Serializer, SerializeMap, SerializeSeq};
use std::borrow::Cow;
use std::fmt;

pub mod log_types;
pub mod extraction;
pub mod processors;
pub mod yaml_config;
pub mod pipeline;
pub mod dissect;

// ─── FieldValue: Lightweight replacement for serde_json::Value ───────────────
//
// serde_json::Value heap-allocates every string via Box<str> internally.
// FieldValue avoids this for static strings (&'static str) and keeps the
// enum compact (1 tag byte + 1 pointer or inline i64/f64/bool).
//
// At 24M logs/sec × ~20 fields, this eliminates ~480M heap allocs/sec
// compared to json!() wrapping.

#[derive(Clone)]
pub enum FieldValue {
    /// A static string known at compile time — zero heap allocation.
    StaticStr(&'static str),
    /// An owned string extracted at runtime (from log line parsing).
    Str(String),
    /// 64-bit signed integer (PIDs, ports, status codes).
    Int(i64),
    /// 64-bit float.
    Float(f64),
    /// Boolean (matched flags, etc.).
    Bool(bool),
    /// Null / absent value sentinel.
    Null,
    /// Small arrays (e.g. tags: ["fast-parser", "yaml-pipeline"]).
    Array(Vec<FieldValue>),
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::StaticStr(s) => write!(f, "\"{}\"", s),
            FieldValue::Str(s) => write!(f, "\"{}\"", s),
            FieldValue::Int(n) => write!(f, "{}", n),
            FieldValue::Float(n) => write!(f, "{}", n),
            FieldValue::Bool(b) => write!(f, "{}", b),
            FieldValue::Null => write!(f, "null"),
            FieldValue::Array(a) => f.debug_list().entries(a).finish(),
        }
    }
}

impl PartialEq for FieldValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // String comparisons are cross-variant: StaticStr == Str if contents match
            (FieldValue::StaticStr(a), FieldValue::StaticStr(b)) => a == b,
            (FieldValue::StaticStr(a), FieldValue::Str(b)) => *a == b.as_str(),
            (FieldValue::Str(a), FieldValue::StaticStr(b)) => a.as_str() == *b,
            (FieldValue::Str(a), FieldValue::Str(b)) => a == b,
            (FieldValue::Int(a), FieldValue::Int(b)) => a == b,
            (FieldValue::Float(a), FieldValue::Float(b)) => a == b,
            (FieldValue::Bool(a), FieldValue::Bool(b)) => a == b,
            (FieldValue::Null, FieldValue::Null) => true,
            (FieldValue::Array(a), FieldValue::Array(b)) => a == b,
            _ => false,
        }
    }
}

impl FieldValue {
    /// Returns the string content if this is a string variant, None otherwise.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::StaticStr(s) => Some(s),
            FieldValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns true if this is a Null variant.
    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }

    /// Returns true if this is an Array variant.
    #[inline]
    pub fn is_array(&self) -> bool {
        matches!(self, FieldValue::Array(_))
    }

    /// Returns the array contents if this is an Array variant.
    #[inline]
    pub fn as_array(&self) -> Option<&Vec<FieldValue>> {
        match self {
            FieldValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Returns the integer value if this is an Int variant.
    #[inline]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Display the value as a string for contexts that need it.
    pub fn to_string_lossy(&self) -> String {
        match self {
            FieldValue::StaticStr(s) => s.to_string(),
            FieldValue::Str(s) => s.clone(),
            FieldValue::Int(n) => n.to_string(),
            FieldValue::Float(n) => n.to_string(),
            FieldValue::Bool(b) => b.to_string(),
            FieldValue::Null => "null".to_string(),
            FieldValue::Array(_) => "[...]".to_string(),
        }
    }
}

impl Serialize for FieldValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            FieldValue::StaticStr(s) => serializer.serialize_str(s),
            FieldValue::Str(s) => serializer.serialize_str(s),
            FieldValue::Int(n) => serializer.serialize_i64(*n),
            FieldValue::Float(n) => serializer.serialize_f64(*n),
            FieldValue::Bool(b) => serializer.serialize_bool(*b),
            FieldValue::Null => serializer.serialize_none(),
            FieldValue::Array(arr) => {
                let mut seq = serializer.serialize_seq(Some(arr.len()))?;
                for item in arr {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
        }
    }
}

// ─── FieldVec: Vec-backed document (replaces BTreeMap) ───────────────────────

/// Lightweight ECS document backed by a flat Vec instead of BTreeMap.
///
/// For documents with ~15-25 fields, linear scan beats tree/hash lookups
/// thanks to cache locality, zero node allocations, and no pointer chasing.
/// The typical flow is: extract → store → serialize, with very few random
/// lookups, so hashmap semantics are overkill.
///
/// Keys use Cow<'static, str> so that compile-time-known field names
/// (the vast majority) are zero-cost borrows with no heap allocation.
#[derive(Debug, Clone)]
pub struct FieldVec {
    fields: Vec<(Cow<'static, str>, FieldValue)>,
}

impl FieldVec {
    #[inline]
    pub fn new() -> Self {
        FieldVec { fields: Vec::with_capacity(24) }
    }

    /// Insert or overwrite a field. Linear scan for dedup — fast for n < 30.
    /// Accepts any key type that converts to Cow<'static, str>:
    ///   - &'static str  → zero-alloc borrow  (most common case)
    ///   - String         → owned allocation    (dynamic YAML keys)
    #[inline]
    pub fn insert(&mut self, key: impl Into<Cow<'static, str>>, value: FieldValue) {
        let key = key.into();
        for (k, v) in self.fields.iter_mut() {
            if *k == key {
                *v = value;
                return;
            }
        }
        self.fields.push((key, value));
    }

    /// Get a field value by key.
    #[inline]
    pub fn get(&self, key: &str) -> Option<&FieldValue> {
        self.fields.iter().find(|(k, _)| k.as_ref() == key).map(|(_, v)| v)
    }

    /// Check if a field exists.
    #[inline]
    pub fn contains_key(&self, key: &str) -> bool {
        self.fields.iter().any(|(k, _)| k.as_ref() == key)
    }

    /// Insert only if the key is not already present (eager value).
    #[inline]
    pub fn or_insert(&mut self, key: impl Into<Cow<'static, str>>, value: FieldValue) {
        let key = key.into();
        if !self.contains_key(key.as_ref()) {
            self.fields.push((key, value));
        }
    }

    /// Insert only if the key is not already present (lazy value).
    #[inline]
    pub fn or_insert_with(&mut self, key: impl Into<Cow<'static, str>>, f: impl FnOnce() -> FieldValue) {
        let key = key.into();
        if !self.contains_key(key.as_ref()) {
            self.fields.push((key, f()));
        }
    }
}

impl Serialize for FieldVec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (k, v) in &self.fields {
            map.serialize_entry(k.as_ref(), v)?;
        }
        map.end()
    }
}

// ─── Helper: Type Coercion ────────────────────────────────────────────────────

/// Parse a string to i64. Returns FieldValue::Null on failure so callers can skip it.
pub fn as_int(s: &str) -> FieldValue {
    match s.trim().parse::<i64>() {
        Ok(n)  => FieldValue::Int(n),
        Err(_) => FieldValue::Null,
    }
}

/// Parse a string to f64. Returns FieldValue::Null on failure.
pub fn as_float(s: &str) -> FieldValue {
    match s.trim().parse::<f64>() {
        Ok(n)  => FieldValue::Float(n),
        Err(_) => FieldValue::Null,
    }
}

/// Insert a value only when it is non-Null.
pub fn set(doc: &mut FieldVec, key: impl Into<Cow<'static, str>>, val: FieldValue) {
    if !val.is_null() {
        doc.insert(key, val);
    }
}

/// Insert a string value, skipping empty strings.
pub fn set_str(doc: &mut FieldVec, key: impl Into<Cow<'static, str>>, val: &str) {
    if !val.is_empty() {
        doc.insert(key, FieldValue::Str(val.to_string()));
    }
}
