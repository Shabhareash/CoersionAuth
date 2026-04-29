use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use grok::Grok;

// ─── LogType Enum and Methods ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogType {
    Systemd,
    Syslog,
    Auth,
    Kernel,
    Apache,
    Firewall,
    Dhcp,
    Mongodb,
    Redis,
    Postgresql,
    Zeek,
    ZeekDhcp,
    Unknown,
}

impl LogType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogType::Systemd    => "systemd",
            LogType::Syslog     => "syslog",
            LogType::Auth       => "auth",
            LogType::Kernel     => "kernel",
            LogType::Apache     => "apache",
            LogType::Firewall   => "firewall",
            LogType::Dhcp       => "dhcp",
            LogType::Mongodb    => "mongodb",
            LogType::Redis      => "redis",
            LogType::Postgresql => "postgresql",
            LogType::Zeek       => "zeek",
            LogType::ZeekDhcp   => "zeek_dhcp",
            LogType::Unknown    => "unknown",
        }
    }

    pub fn pattern_files(&self) -> &'static [&'static str] {
        match self {
            LogType::Systemd              => &["grok-patterns", "linux-syslog"],
            LogType::Syslog               => &["grok-patterns", "linux-syslog"],
            LogType::Auth                 => &["grok-patterns", "linux-syslog"],
            LogType::Kernel               => &["grok-patterns", "linux-syslog"],
            LogType::Firewall             => &["grok-patterns", "linux-syslog", "firewalls"],
            LogType::Dhcp                 => &["grok-patterns", "linux-syslog"],
            LogType::Apache               => &["grok-patterns", "httpd"],
            LogType::Mongodb              => &["grok-patterns", "mongodb"],
            LogType::Redis                => &["grok-patterns", "redis"],
            LogType::Postgresql           => &["grok-patterns", "postgresql"],
            LogType::Zeek | LogType::ZeekDhcp => &["grok-patterns", "zeek"],
            LogType::Unknown              => &["grok-patterns"],
        }
    }

    pub fn top_pattern(&self) -> &'static str {
        match self {
            LogType::Systemd    => "SYSLOGLINE",
            LogType::Syslog     => "SYSLOGLINE",
            LogType::Auth       => "SYSLOGLINE",
            LogType::Kernel     => "SYSLOGLINE",
            LogType::Firewall   => "SYSLOGLINE",
            LogType::Dhcp       => "SYSLOGLINE",
            LogType::Apache     => "HTTPD_COMBINEDLOG",
            LogType::Mongodb    => "MONGO3_LOG",
            LogType::Redis      => "REDISLOG",
            LogType::Postgresql => "POSTGRESQL",
            LogType::Zeek       => "ZEEK_HTTP",
            LogType::ZeekDhcp   => "ZEEK_DHCP",
            LogType::Unknown    => "GREEDYDATA",
        }
    }
}

// ─── Log Type Detection ────────────────────────────────────────────────────────

/// Reads the first `sample_size` non-empty lines, votes on type, returns winner.
pub fn detect_log_type(file_path: &str, sample_size: usize) -> LogType {
    let f = match fs::File::open(file_path) {
        Ok(f)  => f,
        Err(_) => return LogType::Unknown,
    };
    let reader = BufReader::new(f);
    let mut votes: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    let mut checked = 0;
    for line_result in reader.lines() {
        let line = match line_result { Ok(l) => l, Err(_) => continue };
        let line = line.trim();
        if line.is_empty() { continue; }
        *votes.entry(classify_line(line)).or_insert(0) += 1;
        checked += 1;
        if checked >= sample_size { break; }
    }
    match votes.into_iter().max_by_key(|(_, c)| *c).map(|(t, _)| t) {
        Some("systemd")    => LogType::Systemd,
        Some("syslog")     => LogType::Syslog,
        Some("auth")       => LogType::Auth,
        Some("kernel")     => LogType::Kernel,
        Some("apache")     => LogType::Apache,
        Some("firewall")   => LogType::Firewall,
        Some("dhcp")       => LogType::Dhcp,
        Some("mongodb")    => LogType::Mongodb,
        Some("redis")      => LogType::Redis,
        Some("postgresql") => LogType::Postgresql,
        Some("zeek_dhcp")  => LogType::ZeekDhcp,
        Some("zeek")       => LogType::Zeek,
        _                  => LogType::Unknown,
    }
}

/// Classify a single line (used internally by detect_log_type)
fn classify_line(line: &str) -> &'static str {
    if line.len() > 10
        && line.as_bytes().get(4) == Some(&b'-')
        && line.as_bytes().get(7) == Some(&b'-')
        && line.contains('T')
    {
        if line.contains("kernel:") { return "kernel"; }
        return "systemd";
    }
    let months = ["Jan","Feb","Mar","Apr","May","Jun",
                  "Jul","Aug","Sep","Oct","Nov","Dec"];
    if months.iter().any(|m| line.starts_with(m)) {
        if line.contains("sshd")
            || line.contains("Accepted password")
            || line.contains("Failed password") { return "auth"; }
        if line.contains("kernel:")             { return "kernel"; }
        if line.contains("dhclient") || line.contains("dhcpd") || line.contains("DHCPACK")
                                                { return "dhcp"; }
        if line.contains("IN=") && line.contains("OUT=")
                                                { return "firewall"; }
        return "syslog";
    }
    if line.contains("mongodb") || line.contains("mongo") { return "mongodb"; }
    if line.contains("redis")                              { return "redis"; }
    if line.contains("postgres")                           { return "postgresql"; }
    if line.contains("GET ") || line.contains("POST ") || line.contains("HTTP/1.1")
                                                           { return "apache"; }
    if line.contains('\t') && (line.contains("\t67\t") || line.contains("\t68\t"))
                                                           { return "zeek_dhcp"; }
    if line.contains("zeek")                               { return "zeek"; }
    "unknown"
}

// ─── Load Pattern Files ────────────────────────────────────────────────────────

fn load_pattern_file(grok: &mut Grok, path: &Path) {
    let content = match fs::read_to_string(path) {
        Ok(c)  => c,
        Err(e) => { eprintln!("[WARN] Cannot read {:?}: {}", path, e); return; }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some(pos) = line.find(|c: char| c.is_ascii_whitespace()) {
            let name = line[..pos].trim();
            let def  = line[pos..].trim();
            if !name.is_empty() && !def.is_empty() {
                grok.add_pattern(name, def);
            }
        }
    }
    println!("[INIT] Loaded: {}", path.display());
}

// ─── Build Grok Compiler ──────────────────────────────────────────────────────

pub fn build_grok_for_type(log_type: LogType, patterns_root: &str) -> (Grok, grok::Pattern) {
    let mut grok = Grok::default();
    let root = Path::new(patterns_root);
    for &fname in log_type.pattern_files() {
        load_pattern_file(&mut grok, &root.join(fname));
    }
    let top     = log_type.top_pattern();
    let pat_str = format!("%{{{}}}", top);
    let pattern = grok
        .compile(&pat_str, false)
        .or_else(|e| {
            eprintln!("[WARN] Could not compile '{}': {}. Falling back to GREEDYDATA.", top, e);
            grok.compile("%{GREEDYDATA:raw_line}", false)
        })
        .expect("Even GREEDYDATA fallback failed — grok is broken.");
    (grok, pattern)
}
