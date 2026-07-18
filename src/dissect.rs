/// Dissect-style pattern engine: typed token captures with zero regex.
///
/// Pattern syntax:
///   - Literal text is matched exactly
///   - `%{field:type}` captures into `field` with type constraint
///   - `%{?name}`      captures and discards (skip)
///   - `%{field}`      captures with default type (data = greedy until next literal)
///
/// Supported types:
///   - `notspace` — scan until whitespace
///   - `word`     — `[a-zA-Z0-9._-]+`
///   - `int`      — digits only
///   - `ip`       — digits, dots, colons (IPv4/IPv6)
///   - `data`     — greedy until next literal (default)


// ─── Compiled Representation ────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum TokenType {
    NotSpace,
    Word,
    Int,
    Ip,
    Data,
}

#[derive(Debug, Clone)]
pub enum DissectStep {
    Literal(String),
    Capture {
        field: String,
        token_type: TokenType,
        skip: bool,
    },
}

#[derive(Debug, Clone)]
pub struct DissectPattern {
    pub steps: Vec<DissectStep>,
}

// ─── Compilation ────────────────────────────────────────────────────

pub fn compile_pattern(pattern: &str) -> Result<DissectPattern, String> {
    let mut steps = Vec::new();
    let bytes = pattern.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() {
        if pos + 1 < bytes.len() && bytes[pos] == b'%' && bytes[pos + 1] == b'{' {
            // Find closing brace
            let start = pos + 2;
            let end = bytes[start..]
                .iter()
                .position(|&b| b == b'}')
                .map(|p| start + p)
                .ok_or_else(|| format!("Unclosed '{{' in pattern at pos {}", pos))?;

            let token_str = &pattern[start..end];
            let (field, token_type, skip) = parse_token(token_str);

            steps.push(DissectStep::Capture {
                field,
                token_type,
                skip,
            });
            pos = end + 1;
        } else {
            // Literal text
            let start = pos;
            while pos < bytes.len() {
                if pos + 1 < bytes.len() && bytes[pos] == b'%' && bytes[pos + 1] == b'{' {
                    break;
                }
                pos += 1;
            }
            steps.push(DissectStep::Literal(pattern[start..pos].to_string()));
        }
    }

    Ok(DissectPattern { steps })
}

fn parse_token(token: &str) -> (String, TokenType, bool) {
    let skip = token.starts_with('?');
    let body = if skip { &token[1..] } else { token };

    let (field, ttype) = if let Some((f, t)) = body.split_once(':') {
        let tt = match t {
            "notspace" => TokenType::NotSpace,
            "word" => TokenType::Word,
            "int" => TokenType::Int,
            "ip" => TokenType::Ip,
            "data" => TokenType::Data,
            _ => TokenType::Data,
        };
        (f.to_string(), tt)
    } else {
        (body.to_string(), TokenType::Data)
    };

    (field, ttype, skip)
}

// ─── Type Validators (byte-level, no regex) ─────────────────────────

/// Extract a value from the start of `span` according to the token type.
fn extract_typed<'a>(span: &'a str, tt: &TokenType) -> &'a str {
    let bytes = span.as_bytes();
    match tt {
        TokenType::NotSpace => {
            let end = bytes.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(bytes.len());
            &span[..end]
        }
        TokenType::Word => {
            let end = bytes
                .iter()
                .position(|b| {
                    !b.is_ascii_alphanumeric() && *b != b'.' && *b != b'_' && *b != b'-'
                })
                .unwrap_or(bytes.len());
            &span[..end]
        }
        TokenType::Int => {
            let end = bytes.iter().position(|b| !b.is_ascii_digit()).unwrap_or(bytes.len());
            &span[..end]
        }
        TokenType::Ip => {
            let end = bytes
                .iter()
                .position(|b| !b.is_ascii_digit() && *b != b'.' && *b != b':' && *b != b'%')
                .unwrap_or(bytes.len());
            &span[..end]
        }
        TokenType::Data => span,
    }
}

/// For adjacent captures: `%{?skip}%{field:typed}` before a literal boundary.
/// Split the span so the typed capture claims from the right.
fn split_adjacent<'a>(span: &'a str, tt: &TokenType) -> (&'a str, &'a str) {
    let trimmed = span.trim_end();
    match tt {
        TokenType::NotSpace | TokenType::Word => {
            // Last whitespace-separated token
            match trimmed.rfind(|c: char| c.is_ascii_whitespace()) {
                Some(ws) => (&span[..ws + 1], trimmed[ws + 1..].trim()),
                None => ("", trimmed), // entire span is the value
            }
        }
        TokenType::Int => {
            // Last run of digits from the right
            let end = trimmed.len();
            let start = trimmed
                .as_bytes()
                .iter()
                .rposition(|b| !b.is_ascii_digit())
                .map(|p| p + 1)
                .unwrap_or(0);
            (&span[..start], &trimmed[start..end])
        }
        TokenType::Ip => {
            // Last whitespace-separated token (IPs are always space-delimited)
            match trimmed.rfind(|c: char| c.is_ascii_whitespace()) {
                Some(ws) => (&span[..ws + 1], trimmed[ws + 1..].trim()),
                None => ("", trimmed),
            }
        }
        TokenType::Data => {
            // Can't split two data captures meaningfully
            (span, "")
        }
    }
}

// ─── Execution ──────────────────────────────────────────────────────

/// Execute a compiled dissect pattern against input.
/// Returns field→value pairs on success, None if the pattern doesn't match.
pub fn execute<'a>(pattern: &'a DissectPattern, input: &'a str) -> Option<Vec<(&'a str, &'a str)>> {
    let steps = &pattern.steps;
    let mut results = Vec::new();
    let mut pos = 0;
    let mut i = 0;

    while i < steps.len() {
        if pos > input.len() {
            return None;
        }

        match &steps[i] {
            DissectStep::Literal(lit) => {
                let remaining = &input[pos..];
                let offset = remaining.find(lit.as_str())?;
                pos += offset + lit.len();
                i += 1;
            }

            DissectStep::Capture {
                field,
                token_type,
                skip,
            } => {
                // Check: is the next step ALSO a capture? (adjacent captures)
                let next_is_data_adjacent =
                    matches!(token_type, TokenType::Data)
                        && i + 1 < steps.len()
                        && matches!(&steps[i + 1], DissectStep::Capture { .. });

                if next_is_data_adjacent {
                    // Adjacent captures: data + typed.
                    // Find the span boundary (next literal after the typed capture).
                    let typed_step = &steps[i + 1];
                    let boundary = find_next_literal_pos(steps, i + 2, input, pos);
                    let span = &input[pos..boundary];

                    if let DissectStep::Capture {
                        field: tf,
                        token_type: tt,
                        skip: ts,
                    } = typed_step
                    {
                        let (prefix_val, typed_val) = split_adjacent(span, tt);
                        if !*skip && !field.is_empty() {
                            results.push((field.as_str(), prefix_val.trim()));
                        }
                        if !*ts && !tf.is_empty() {
                            results.push((tf.as_str(), typed_val.trim()));
                        }
                    }

                    pos = boundary;
                    i += 2;
                } else {
                    // Single capture: bounded by next literal or end of input.
                    let boundary = find_next_literal_pos(steps, i + 1, input, pos);
                    let span = &input[pos..boundary];

                    let value = extract_typed(span, token_type);
                    if !*skip && !field.is_empty() {
                        results.push((field.as_str(), value.trim()));
                    }

                    // Advance: typed captures advance by value length, data by span length
                    pos += match token_type {
                        TokenType::Data => span.len(),
                        _ => value.len(),
                    };
                    i += 1;
                }
            }
        }
    }

    Some(results)
}

/// Find the byte position where the next literal starts in the input.
fn find_next_literal_pos(steps: &[DissectStep], from_step: usize, input: &str, search_from: usize) -> usize {
    for step in &steps[from_step..] {
        if let DissectStep::Literal(lit) = step {
            if let Some(offset) = input[search_from..].find(lit.as_str()) {
                return search_from + offset;
            }
        }
    }
    input.len() // no more literals → rest of input
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn run(pattern: &str, input: &str) -> Option<HashMap<String, String>> {
        let p = compile_pattern(pattern).unwrap();
        execute(&p, input).map(|pairs| {
            pairs.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        })
    }

    #[test]
    fn test_simple_ssh_failed() {
        let r = run(
            "Failed password for %{user.name:notspace} from %{source.ip:ip} port %{source.port:int}",
            "Failed password for admin from 218.49.183.17 port 49266 ssh2",
        ).unwrap();
        assert_eq!(r["user.name"], "admin");
        assert_eq!(r["source.ip"], "218.49.183.17");
        assert_eq!(r["source.port"], "49266");
    }

    #[test]
    fn test_ssh_failed_with_prefix() {
        let r = run(
            "Failed %{?method} for %{?prefix}%{user.name:notspace} from %{source.ip:ip} port %{source.port:int} %{?proto}",
            "Failed password for illegal user test from 218.49.183.17 port 48849 ssh2",
        ).unwrap();
        assert_eq!(r["user.name"], "test");
        assert_eq!(r["source.ip"], "218.49.183.17");
        assert_eq!(r["source.port"], "48849");
    }

    #[test]
    fn test_ssh_failed_no_prefix() {
        let r = run(
            "Failed %{?method} for %{?prefix}%{user.name:notspace} from %{source.ip:ip} port %{source.port:int} %{?proto}",
            "Failed password for root from 218.49.183.17 port 49869 ssh2",
        ).unwrap();
        assert_eq!(r["user.name"], "root");
        assert_eq!(r["source.ip"], "218.49.183.17");
        assert_eq!(r["source.port"], "49869");
    }

    #[test]
    fn test_invalid_user() {
        let r = run(
            "%{?adjective} user %{user.name:notspace} from %{source.ip:ip}",
            "Illegal user test from 218.49.183.17",
        ).unwrap();
        assert_eq!(r["user.name"], "test");
        assert_eq!(r["source.ip"], "218.49.183.17");
    }

    #[test]
    fn test_pam_kv() {
        let r = run(
            "%{?head}rhost=%{source.ip:notspace} %{?mid}user=%{user.name:notspace}",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=1.2.3.4  user=root",
        ).unwrap();
        assert_eq!(r["source.ip"], "1.2.3.4");
        assert_eq!(r["user.name"], "root");
    }

    #[test]
    fn test_no_match() {
        let r = run(
            "Failed password for %{user:notspace}",
            "Accepted publickey for root",
        );
        assert!(r.is_none());
    }
}
