/// Three-tier parsing pipeline.
///
/// Architecture:
///   Raw Log Line
///     → Classifier (Aho-Corasick / memchr — SIMD)
///     → Specialized Parser (state-machine / token extraction — NO regex)
///     → Generic Parser (regex fallback)
///     → Raw Ingestion (never drops events)
///
/// All behavior is driven by the YAML config.

use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::HashMap;

use crate::yaml_config::{YamlConfig, ExtractRule};
use crate::dissect::{self, DissectPattern};
use crate::{as_int, set, set_str, FieldVec, FieldValue};

// ════════════════════════════════════════════════════════════════════
//  TRAITS
// ════════════════════════════════════════════════════════════════════

/// Stage 1: Classify a log line into an event type using SIMD search.
pub trait Classifier: Send + Sync {
    /// Returns the signature id (e.g. "ssh_success") or None.
    fn classify<'a>(&'a self, line: &str) -> Option<&'a str>;
}

/// Stage 2: Parse known event types WITHOUT regex.
pub trait SpecializedParser: Send + Sync {
    /// Extract fields into `doc` using token-based state-machine parsing.
    /// Returns true if it successfully parsed the line.
    fn parse(&self, event_type: &str, line: &str, doc: &mut FieldVec) -> bool;
}

/// Stage 3: Regex-based fallback for unclassified lines.
pub trait GenericParser: Send + Sync {
    /// Try regex patterns. Returns true if any matched.
    fn parse(&self, line: &str, doc: &mut FieldVec) -> bool;
}

/// Stage 4: Raw ingestion — always runs, never drops events.
pub trait RawIngestion: Send + Sync {
    /// Ensure baseline ECS fields are always present.
    fn ingest(&self, line: &str, doc: &mut FieldVec);
}

// ════════════════════════════════════════════════════════════════════
//  STAGE 1: AHO-CORASICK CLASSIFIER
// ════════════════════════════════════════════════════════════════════

pub struct AhoCorasickClassifier {
    /// Compiled automaton over all signature needles.
    ac: AhoCorasick,
    /// Maps pattern index → signature id.
    index_to_id: Vec<String>,
}

impl AhoCorasickClassifier {
    pub fn from_config(config: &YamlConfig) -> Self {
        let mut needles: Vec<String> = Vec::new();
        let mut index_to_id: Vec<String> = Vec::new();

        for sig in &config.pipeline.signatures {
            for needle in &sig.contains {
                needles.push(needle.clone());
                index_to_id.push(sig.id.clone());
            }
        }

        let ac = AhoCorasick::new(&needles)
            .expect("Failed to build Aho-Corasick automaton");

        AhoCorasickClassifier { ac, index_to_id }
    }
}

impl Classifier for AhoCorasickClassifier {
    fn classify<'a>(&'a self, line: &str) -> Option<&'a str> {
        // First match wins (signatures are in priority order in the YAML).
        if let Some(mat) = self.ac.find(line) {
            Some(&self.index_to_id[mat.pattern().as_usize()])
        } else {
            None
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  STAGE 2: STATE-MACHINE SPECIALIZED PARSER
// ════════════════════════════════════════════════════════════════════

/// A single compiled extraction rule: find text between delimiters.
#[derive(Debug, Clone)]
struct CompiledExtractRule {
    field: String,
    /// List of "after" needles to try (first match wins).
    after_needles: Vec<String>,
    /// Optional "before" delimiter.
    before_needle: Option<String>,
    /// Whether to parse the extracted value as an integer.
    is_int: bool,
}

/// Pre-compiled specialized parser for one event type.
#[derive(Debug, Clone)]
struct CompiledSpecialized {
    static_fields: Vec<(String, String)>,
    extract_rules: Vec<CompiledExtractRule>,
}

pub struct StateMachineParser {
    /// event_type → compiled parser
    parsers: HashMap<String, CompiledSpecialized>,
}

impl StateMachineParser {
    pub fn from_config(config: &YamlConfig) -> Self {
        let mut parsers = HashMap::new();

        for (event_type, parser_cfg) in &config.pipeline.specialized_parsers {
            // Only compile state_machine strategy parsers here.
            if parser_cfg.strategy == "dissect" {
                continue;
            }

            let static_fields: Vec<(String, String)> = parser_cfg.ecs.statics()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            let extract_rules: Vec<CompiledExtractRule> = parser_cfg.ecs.extract
                .iter()
                .map(|rule| compile_extract_rule(rule))
                .collect();

            parsers.insert(event_type.clone(), CompiledSpecialized {
                static_fields,
                extract_rules,
            });
        }

        StateMachineParser { parsers }
    }
}

fn compile_extract_rule(rule: &ExtractRule) -> CompiledExtractRule {
    let after_needles = if let Some(ref any) = rule.after_any {
        any.clone()
    } else if let Some(ref single) = rule.after {
        vec![single.clone()]
    } else {
        vec![]
    };

    CompiledExtractRule {
        field: rule.field.clone(),
        after_needles,
        before_needle: rule.before.clone(),
        is_int: rule.field_type.as_deref() == Some("int"),
    }
}

/// Find the first occurrence of `needle` in `haystack` that sits at a word
/// boundary.  When the needle starts with an alphanumeric byte we insist that
/// the preceding byte (if any) is **not** alphanumeric — this prevents
/// `"user="` from matching inside `"ruser="`.  Needles that start with a
/// special character (`[`, `=`, `"`, space, …) always match on the first hit.
///
/// Returns the byte offset **after** the needle (ready to start extracting).
fn find_with_word_boundary(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let needs_boundary = needle[0].is_ascii_alphanumeric();
    let mut search_start = 0;
    while search_start < haystack.len() {
        match memchr::memmem::find(&haystack[search_start..], needle) {
            Some(rel_pos) => {
                let abs_pos = search_start + rel_pos;
                if needs_boundary
                    && abs_pos > 0
                    && haystack[abs_pos - 1].is_ascii_alphanumeric()
                {
                    // Not at a word boundary — skip past and keep looking.
                    search_start = abs_pos + 1;
                    continue;
                }
                return Some(abs_pos + needle.len());
            }
            None => return None,
        }
    }
    None
}

fn extract_between<'a>(line: &'a str, rule: &CompiledExtractRule) -> Option<&'a str> {
    let start_pos;

    if rule.after_needles.is_empty() {
        // No after-needle: extract from start of line.
        start_pos = 0;
    } else {
        // Try each after-needle; first word-boundary match wins.
        let mut found = None;
        for needle in &rule.after_needles {
            if let Some(pos) = find_with_word_boundary(line.as_bytes(), needle.as_bytes()) {
                found = Some(pos);
                break;
            }
        }
        start_pos = found?;
    }

    // Trim leading spaces to cleanly handle `key= value` or `key="value"`
    let remaining = line[start_pos..].trim_start();
    if remaining.is_empty() {
        return None;
    }

    let bytes = remaining.as_bytes();
    let first_char = bytes[0];

    // 1. Quote Awareness: Safely extract strings wrapped in " or '
    if first_char == b'"' || first_char == b'\'' {
        let quote = first_char;
        let mut idx = 1;
        while idx < bytes.len() {
            if bytes[idx] == quote && bytes[idx - 1] != b'\\' {
                return Some(&remaining[1..idx]);
            }
            idx += 1;
        }
        // If no closing quote found, fall through to fallback logic
    }

    // 2. Bracket Awareness: Safely extract values wrapped in [], <>, or ()
    if first_char == b'[' || first_char == b'<' || first_char == b'(' {
        let closing_char = match first_char {
            b'[' => b']',
            b'<' => b'>',
            b'(' => b')',
            _ => unreachable!(),
        };
        if let Some(end_idx) = memchr::memchr(closing_char, &bytes[1..]) {
            return Some(&remaining[1..1 + end_idx]);
        }
    }

    // 3. Exact before-needle match (word-boundary aware)
    if let Some(ref before) = rule.before_needle {
        if let Some(end) = memchr::memmem::find(remaining.as_bytes(), before.as_bytes()) {
            return Some(&remaining[..end]);
        }
    }

    // 4. Fuzzy Fallback: Take until whitespace and strip trailing punctuation/garbage
    let val = remaining.split_whitespace().next().unwrap_or(remaining);
    let clean_val = val.trim_end_matches(&[',', ';', ':', '.', ')', ']', '}'][..]);
    
    Some(clean_val)
}

impl SpecializedParser for StateMachineParser {
    fn parse(&self, event_type: &str, line: &str, doc: &mut FieldVec) -> bool {
        let compiled = match self.parsers.get(event_type) {
            Some(c) => c,
            None => return false,
        };

        // Apply static ECS fields.
        for (key, value) in &compiled.static_fields {
            doc.insert(key.clone(), FieldValue::Str(value.clone()));
        }

        // Apply extraction rules.
        let mut extracted_any = false;
        for rule in &compiled.extract_rules {
            if let Some(val) = extract_between(line, rule) {
                if !val.is_empty() {
                    if rule.is_int {
                        let int_val = as_int(val);
                        if !int_val.is_null() {
                            set(doc, rule.field.clone(), int_val);
                        } else {
                            set_str(doc, rule.field.clone(), val);
                        }
                    } else {
                        set_str(doc, rule.field.clone(), val);
                    }
                    extracted_any = true;
                }
            }
        }

        extracted_any
    }
}

// ════════════════════════════════════════════════════════════════════
//  STAGE 2b: DISSECT SPECIALIZED PARSER
// ════════════════════════════════════════════════════════════════════

/// Pre-compiled dissect parser for one event type.
#[derive(Debug, Clone)]
struct CompiledDissect {
    static_fields: Vec<(String, String)>,
    patterns: Vec<DissectPattern>,
}

pub struct DissectSpecializedParser {
    /// event_type → compiled dissect patterns
    parsers: HashMap<String, CompiledDissect>,
}

impl DissectSpecializedParser {
    pub fn from_config(config: &YamlConfig) -> Self {
        let mut parsers = HashMap::new();

        for (event_type, parser_cfg) in &config.pipeline.specialized_parsers {
            if parser_cfg.strategy != "dissect" {
                continue;
            }

            let static_fields: Vec<(String, String)> = parser_cfg.ecs.statics()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            let mut compiled_patterns = Vec::new();
            for pat_str in &parser_cfg.patterns {
                match dissect::compile_pattern(pat_str) {
                    Ok(p) => compiled_patterns.push(p),
                    Err(e) => eprintln!("[WARN] Cannot compile dissect pattern '{}': {}", pat_str, e),
                }
            }

            if !compiled_patterns.is_empty() {
                parsers.insert(event_type.clone(), CompiledDissect {
                    static_fields,
                    patterns: compiled_patterns,
                });
            }
        }

        DissectSpecializedParser { parsers }
    }
}

impl SpecializedParser for DissectSpecializedParser {
    fn parse(&self, event_type: &str, line: &str, doc: &mut FieldVec) -> bool {
        let compiled = match self.parsers.get(event_type) {
            Some(c) => c,
            None => return false,
        };

        // Apply static ECS fields.
        for (key, value) in &compiled.static_fields {
            doc.insert(key.clone(), FieldValue::Str(value.clone()));
        }

        // Try each dissect pattern in priority order.
        for pattern in &compiled.patterns {
            if let Some(pairs) = dissect::execute(pattern, line) {
                for (field, val) in pairs {
                    if !val.is_empty() {
                        let int_val = as_int(val);
                        if !int_val.is_null() {
                            set(doc, field.to_string(), int_val);
                        } else {
                            set_str(doc, field.to_string(), val);
                        }
                    }
                }
                return true;
            }
        }

        false
    }
}

// ════════════════════════════════════════════════════════════════════
//  STAGE 3: REGEX GENERIC PARSER
// ════════════════════════════════════════════════════════════════════

struct CompiledGenericPattern {
    #[allow(dead_code)]
    name: String,
    regex: Regex,
    ecs_mapping: HashMap<String, String>,
}

pub struct RegexGenericParser {
    patterns: Vec<CompiledGenericPattern>,
}

impl RegexGenericParser {
    pub fn from_config(config: &YamlConfig) -> Self {
        let mut patterns = Vec::new();

        if config.pipeline.generic_parser.enabled {
            for pat in &config.pipeline.generic_parser.patterns {
                match Regex::new(&pat.regex) {
                    Ok(compiled) => {
                        patterns.push(CompiledGenericPattern {
                            name: pat.name.clone(),
                            regex: compiled,
                            ecs_mapping: pat.ecs.clone(),
                        });
                    }
                    Err(e) => {
                        eprintln!("[WARN] Cannot compile generic regex '{}': {}", pat.name, e);
                    }
                }
            }
        }

        RegexGenericParser { patterns }
    }
}

impl GenericParser for RegexGenericParser {
    fn parse(&self, line: &str, doc: &mut FieldVec) -> bool {
        for pat in &self.patterns {
            if let Some(caps) = pat.regex.captures(line) {
                for (capture_name, ecs_field) in &pat.ecs_mapping {
                    if let Some(m) = caps.name(capture_name) {
                        let val = m.as_str();
                        let int_val = as_int(val);
                        if !int_val.is_null() {
                            set(doc, ecs_field.clone(), int_val);
                        } else {
                            set_str(doc, ecs_field.clone(), val);
                        }
                    }
                }
                return true;
            }
        }
        false
    }
}

// ════════════════════════════════════════════════════════════════════
//  STAGE 4: RAW INGESTION (NEVER DROP)
// ════════════════════════════════════════════════════════════════════

pub struct DefaultRawIngestion;

impl RawIngestion for DefaultRawIngestion {
    fn ingest(&self, line: &str, doc: &mut FieldVec) {
        // Always set event.original.
        doc.or_insert_with("event.original", || FieldValue::Str(line.to_string()));

        // Always set message.
        doc.or_insert_with("message", || FieldValue::Str(line.to_string()));

        // Parse syslog header for host.name, process.name, process.pid.
        // Handles both BSD ("Dec 10 06:55:46 host prog[pid]: msg")
        // and ISO ("2026-06-28T18:33:54... host prog[pid]: msg") formats.
        if !doc.contains_key("process.name") {
            parse_syslog_header(line, doc);
        }

        // Ensure event.kind is present.
        doc.or_insert_with("event.kind", || FieldValue::StaticStr("event"));
    }
}

/// Parse the syslog header to extract host.name, process.name, process.pid.
/// Supports both BSD and ISO-8601 syslog formats.
///
/// Instead of relying on fixed field offsets (which break when hostnames contain
/// spaces), we anchor on the process marker `name[pid]:` — the one unambiguous
/// token in a syslog line — and derive the hostname from everything between the
/// timestamp and that marker.
fn parse_syslog_header(line: &str, doc: &mut FieldVec) {
    let bytes = line.as_bytes();

    if bytes.len() <= 15 {
        return;
    }

    // ── Step 1: Detect format and find end-of-timestamp ─────────────
    let is_bsd = bytes[0].is_ascii_alphabetic()
        && bytes[1].is_ascii_alphabetic()
        && bytes[2].is_ascii_alphabetic()
        && bytes[3] == b' ';
    let is_iso = bytes.len() > 10
        && bytes[4] == b'-'
        && bytes[7] == b'-';

    if !is_bsd && !is_iso {
        return;
    }

    // Skip past timestamp fields to get to "HOSTNAME ... PROCESS[PID]: body"
    let ts_fields_to_skip = if is_bsd { 3 } else { 1 }; // BSD=3 (Mon DD HH:MM:SS), ISO=1
    let mut pos = 0;
    for _ in 0..ts_fields_to_skip {
        // Skip non-space characters (field content)
        while pos < bytes.len() && bytes[pos] != b' ' {
            pos += 1;
        }
        // Skip spaces between fields
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }
    }

    if pos >= bytes.len() {
        return;
    }

    let after_ts = &line[pos..]; // "HOSTNAME ... PROCESS[PID]: body"

    // ── Step 2: Find the process marker — anchor on `word[digits]:` ─
    // Scan for the pattern: non-space chars followed by [digits]:
    // e.g. "sshd[12069]:" or "CRON[4321]:"
    let after_ts_bytes = after_ts.as_bytes();
    let mut proc_marker_start = None; // byte offset within after_ts
    let mut proc_name = "";
    let mut proc_pid: Option<i64> = None;

    // Find "[" followed by digits followed by "]:"
    let mut scan = 0;
    while scan < after_ts_bytes.len() {
        if after_ts_bytes[scan] == b'[' {
            // Check if digits follow, then "]:"
            let digit_start = scan + 1;
            let mut digit_end = digit_start;
            while digit_end < after_ts_bytes.len() && after_ts_bytes[digit_end].is_ascii_digit() {
                digit_end += 1;
            }
            // Need at least one digit, then "]", then ":"
            if digit_end > digit_start
                && digit_end + 1 < after_ts_bytes.len()
                && after_ts_bytes[digit_end] == b']'
                && after_ts_bytes[digit_end + 1] == b':'
            {
                // Found "word[digits]:" — now find the start of the process name
                // (walk backwards from '[' to the last space)
                let mut name_start = scan;
                while name_start > 0 && after_ts_bytes[name_start - 1] != b' ' {
                    name_start -= 1;
                }
                proc_marker_start = Some(name_start);
                proc_name = &after_ts[name_start..scan];
                let pid_str = &after_ts[digit_start..digit_end];
                proc_pid = pid_str.parse::<i64>().ok();
                break;
            }
        }
        scan += 1;
    }

    // ── Step 3: Extract hostname = everything before the process marker ─
    if let Some(marker_start) = proc_marker_start {
        let hostname = after_ts[..marker_start].trim();
        if !hostname.is_empty() {
            doc.or_insert_with("host.name", || FieldValue::Str(hostname.to_string()));
            doc.or_insert_with("host.hostname", || FieldValue::Str(hostname.to_string()));
        }
    }

    // ── Step 4: Set process fields ──────────────────────────────────
    if !proc_name.is_empty() {
        doc.or_insert_with("process.name", || FieldValue::Str(proc_name.to_string()));
    }
    if let Some(pid) = proc_pid {
        doc.or_insert_with("process.pid", || FieldValue::Int(pid));
    }

    // Fallback: if we didn't find a process marker at all, try the simple
    // "word:" pattern (process without PID).
    if proc_marker_start.is_none() {
        // Look for the first "word:" after the timestamp.
        if let Some(colon_pos) = after_ts.find(':') {
            let before_colon = &after_ts[..colon_pos];
            // Last space-separated token before the colon is the process name
            if let Some(last_space) = before_colon.rfind(' ') {
                let hostname = before_colon[..last_space].trim();
                let name = &before_colon[last_space + 1..];
                if !hostname.is_empty() {
                    doc.or_insert_with("host.name", || FieldValue::Str(hostname.to_string()));
                    doc.or_insert_with("host.hostname", || FieldValue::Str(hostname.to_string()));
                }
                if !name.is_empty() {
                    doc.or_insert_with("process.name", || FieldValue::Str(name.to_string()));
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  COMPILED PIPELINE
// ════════════════════════════════════════════════════════════════════

/// The fully compiled three-tier pipeline. Thread-safe, immutable after
/// construction. Passed by reference into rayon's parallel iterator.
pub struct Pipeline {
    pub classifier: AhoCorasickClassifier,
    pub specialized: StateMachineParser,
    pub dissect: DissectSpecializedParser,
    pub generic: RegexGenericParser,
    pub raw: DefaultRawIngestion,
}

impl Pipeline {
    pub fn from_config(config: &YamlConfig) -> Self {
        let classifier = AhoCorasickClassifier::from_config(config);
        let specialized = StateMachineParser::from_config(config);
        let dissect = DissectSpecializedParser::from_config(config);
        let generic = RegexGenericParser::from_config(config);
        let raw = DefaultRawIngestion;

        Pipeline { classifier, specialized, dissect, generic, raw }
    }

    /// Process a single log line through all four stages.
    /// Returns the finished ECS document.
    pub fn process_line(&self, line: &str) -> FieldVec {
        let trimmed = line.trim();
        let mut doc = FieldVec::new();

        // ── Stage 1: Classify ───────────────────────────────────────
        let event_type = self.classifier.classify(trimmed);

        // ── Stage 2: Specialized parse (no regex) ───────────────────
        let specialized_ok = if let Some(etype) = event_type {
            doc.insert("event.type_id", FieldValue::Str(etype.to_string()));
            // Try dissect first, then fall back to state-machine.
            let ok = self.dissect.parse(etype, trimmed, &mut doc);
            if ok { true } else { self.specialized.parse(etype, trimmed, &mut doc) }
        } else {
            false
        };

        // ── Stage 3: Generic regex fallback ─────────────────────────
        let generic_ok = if !specialized_ok {
            self.generic.parse(trimmed, &mut doc)
        } else {
            false
        };

        // Track which stage matched.
        let stage: &'static str = if specialized_ok {
            "specialized"
        } else if generic_ok {
            "generic"
        } else {
            "raw"
        };
        doc.insert("_parse_stage", FieldValue::StaticStr(stage));
        doc.insert("matched", FieldValue::Bool(specialized_ok || generic_ok));

        // ── Stage 4: Raw ingestion (always runs) ────────────────────
        self.raw.ingest(trimmed, &mut doc);

        // ── Timestamp ───────────────────────────────────────────────
        if !doc.contains_key("@timestamp") {
            extract_timestamp(trimmed, &mut doc);
        }

        doc
    }
}

// ─── Timestamp extraction ───────────────────────────────────────────

fn extract_timestamp(line: &str, doc: &mut FieldVec) {
    use crate::extraction::to_timestamp;

    let bytes = line.as_bytes();

    // Try ISO-8601 first (e.g. "2026-06-28T18:33:54.179055+05:30")
    if bytes.len() > 10 && bytes[4] == b'-' && bytes[7] == b'-' {
        if let Some(ts_str) = line.split_whitespace().next() {
            let iso = to_timestamp(ts_str);
            doc.insert("@timestamp", FieldValue::Str(iso.clone()));
            doc.insert("event.created", FieldValue::Str(iso));
            return;
        }
    }

    // Try BSD syslog ("Dec 10 06:55:46") — use split_whitespace to handle
    // double-space before single-digit days (e.g. "Aug  1 18:27:45").
    let months = ["Jan","Feb","Mar","Apr","May","Jun",
                   "Jul","Aug","Sep","Oct","Nov","Dec"];
    if bytes.len() > 15 && months.iter().any(|m| line.starts_with(m)) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let ts_raw = format!("{} {} {}", parts[0], parts[1], parts[2]);
            let iso = to_timestamp(&ts_raw);
            doc.insert("@timestamp", FieldValue::Str(iso.clone()));
            doc.insert("event.created", FieldValue::Str(iso));
            return;
        }
    }

    // Final fallback: current time.
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    doc.insert("@timestamp", FieldValue::Str(now.clone()));
    doc.insert("event.created", FieldValue::Str(now));
}
