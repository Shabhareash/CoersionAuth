/// YAML configuration loader for the three-tier parsing pipeline.
///
/// Deserializes `ssh.yaml` (or any log-family YAML) into strongly-typed
/// Rust structs that drive the classifier, specialized parsers, generic
/// parser, and raw ingestion layers.

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ─── Top-Level Config ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct YamlConfig {
    pub version: u32,
    pub log_family: String,
    pub pipeline: PipelineConfig,
    #[serde(default)]
    pub syslog: Option<SyslogConfig>,
}

// ─── Pipeline ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PipelineConfig {
    pub classifier: ClassifierConfig,
    pub signatures: Vec<SignatureEntry>,
    pub specialized_parsers: HashMap<String, SpecializedParserConfig>,
    pub generic_parser: GenericParserConfig,
    pub raw_ingestion: RawIngestionConfig,
}

// ─── Classifier ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ClassifierConfig {
    pub strategy: String,
    pub fallback: String,
}

#[derive(Debug, Deserialize)]
pub struct SignatureEntry {
    pub id: String,
    pub contains: Vec<String>,
}

// ─── Specialized Parsers ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SpecializedParserConfig {
    pub strategy: String,
    pub ecs: EcsConfig,
    /// Dissect-style patterns (used when strategy = "dissect").
    /// Multiple patterns are tried in order; first match wins.
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct EcsConfig {
    #[serde(default)]
    pub static_fields: HashMap<String, String>,
    #[serde(default, rename = "static")]
    pub static_: HashMap<String, String>,
    #[serde(default)]
    pub extract: Vec<ExtractRule>,
}

impl EcsConfig {
    /// Get the static fields (handles both `static_fields` and `static` keys).
    pub fn statics(&self) -> &HashMap<String, String> {
        if !self.static_.is_empty() {
            &self.static_
        } else {
            &self.static_fields
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExtractRule {
    pub field: String,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub after_any: Option<Vec<String>>,
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default, rename = "type")]
    pub field_type: Option<String>,
}

// ─── Generic Parser ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GenericParserConfig {
    pub enabled: bool,
    pub strategy: String,
    #[serde(default)]
    pub patterns: Vec<GenericPattern>,
}

#[derive(Debug, Deserialize)]
pub struct GenericPattern {
    pub name: String,
    pub regex: String,
    #[serde(default)]
    pub ecs: HashMap<String, String>,
}

// ─── Raw Ingestion ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RawIngestionConfig {
    pub enabled: bool,
    #[serde(default)]
    pub preserve_original: bool,
    #[serde(default)]
    pub fields: Vec<String>,
}

// ─── Syslog Format Hints ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SyslogConfig {
    #[serde(default)]
    pub bsd_format: Option<SyslogFormatConfig>,
    #[serde(default)]
    pub iso_format: Option<SyslogFormatConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SyslogFormatConfig {
    pub timestamp_fields: usize,
    pub hostname_offset: usize,
    pub process_offset: usize,
}

// ─── Loader ─────────────────────────────────────────────────────────

pub fn load_yaml_config(path: &Path) -> Result<YamlConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {:?}: {}", path, e))?;
    serde_yaml::from_str(&content)
        .map_err(|e| format!("YAML parse error in {:?}: {}", path, e))
}
