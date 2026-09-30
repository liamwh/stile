//! Minimal dotenv parse/serialize for SOPS files and deployed env files.
//! Preserves ordering and unknown keys; SOPS metadata lines (`sops_*`) are
//! ordinary lines we never generate but must round-trip on parse/re-emit
//! only for plaintext staging (SOPS regenerates metadata on encrypt).

/// Parse a dotenv file into ordered key/value pairs. Later duplicates
/// overwrite earlier ones but keep the earlier position.
pub fn parse(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..eq].trim().to_string();
        if key.is_empty() {
            continue;
        }
        let value = unquote(trimmed[eq + 1..].trim());
        if let Some(existing) = out.iter_mut().find(|(k, _)| *k == key) {
            existing.1 = value;
        } else {
            out.push((key, value));
        }
    }
    out
}

/// Serialize pairs back to dotenv text. Values containing whitespace or
/// quotes are double-quoted with escaped inner quotes and backslashes;
/// other values are emitted bare.
pub fn serialize(pairs: &[(String, String)]) -> String {
    let mut out = String::new();
    for (key, value) in pairs {
        if needs_quoting(value) {
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            out.push_str(&format!("{key}=\"{escaped}\"\n"));
        } else {
            out.push_str(&format!("{key}={value}\n"));
        }
    }
    out
}

/// Update (or append) a key, returning the new pair list.
pub fn set(pairs: &[(String, String)], key: &str, value: &str) -> Vec<(String, String)> {
    let mut out = pairs.to_vec();
    if let Some(existing) = out.iter_mut().find(|(k, _)| k == key) {
        existing.1 = value.to_string();
    } else {
        out.push((key.to_string(), value.to_string()));
    }
    out
}

/// Look up a key.
pub fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn unquote(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    } else if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.to_string()
    }
}

fn needs_quoting(value: &str) -> bool {
    value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == '#' || c == '\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_plain_values() {
        let text = "A=1\nB=plain-value.underscore\n# comment\n\nC=x\n";
        let pairs = parse(text);
        assert_eq!(get(&pairs, "A"), Some("1"));
        assert_eq!(get(&pairs, "C"), Some("x"));
        let re = serialize(&pairs);
        assert_eq!(parse(&re), pairs);
    }

    #[test]
    fn roundtrips_quoted_values() {
        let text = "A=\"has spaces and \\\"quotes\\\"\"\nB='single'\n";
        let pairs = parse(text);
        assert_eq!(get(&pairs, "A"), Some("has spaces and \"quotes\""));
        assert_eq!(get(&pairs, "B"), Some("single"));
        assert_eq!(parse(&serialize(&pairs)), pairs);
    }

    #[test]
    fn set_updates_in_place_and_appends() {
        let pairs = vec![("A".into(), "1".into()), ("B".into(), "2".into())];
        let updated = set(&pairs, "A", "9");
        assert_eq!(get(&updated, "A"), Some("9"));
        assert_eq!(updated.len(), 2);
        let appended = set(&updated, "C", "3");
        assert_eq!(get(&appended, "C"), Some("3"));
        assert_eq!(appended.len(), 3);
    }

    #[test]
    fn later_duplicate_wins() {
        let pairs = parse("A=1\nA=2\n");
        assert_eq!(pairs.len(), 1);
        assert_eq!(get(&pairs, "A"), Some("2"));
    }

    #[test]
    fn sops_metadata_lines_are_ignored_as_keys_we_never_touch() {
        // sops dotenv metadata appears as sops_* keys; we treat them as
        // data lines but never generate, log or modify them.
        let pairs = parse("REAL=1\nsops_version=3.13.3\n");
        assert_eq!(get(&pairs, "REAL"), Some("1"));
        assert!(get(&pairs, "sops_version").is_some());
    }
}
