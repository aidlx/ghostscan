use crate::ScanOutcome;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
};

pub fn run() -> ScanOutcome {
    let trace_root =
        find_tracefs_root().map_err(|err| format!("failed to locate tracefs: {err}"))?;

    let events_path = trace_root.join("kprobe_events");
    let events_content = fs::read_to_string(&events_path)
        .map_err(|err| format!("failed to read {}: {err}", events_path.display()))?;

    if events_content.trim().is_empty() {
        return Ok(None);
    }

    let profile_path = trace_root.join("kprobe_profile");
    let profile_content = fs::read_to_string(&profile_path)
        .map_err(|err| format!("failed to read {}: {err}", profile_path.display()))?;

    let events = parse_kprobe_events(&events_content);
    if events.is_empty() {
        return Ok(None);
    }

    let profile_hits = parse_kprobe_profile(&profile_content);

    let mut findings = Vec::new();

    for event in events {
        if !is_sensitive_symbol(&event.symbol) {
            continue;
        }

        let hits = profile_hits
            .get(&(event.probe_type, event.event_name.clone()))
            .copied()
            .unwrap_or(0);

        findings.push(format!(
            "type={}, target={}, hits={}, raw={}",
            event.probe_type.as_str(),
            event.symbol,
            hits,
            event.raw
        ));
    }

    if findings.is_empty() {
        return Ok(None);
    }

    findings.sort();
    Ok(Some(findings.join("\n")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ProbeType {
    Kprobe,
    Kretprobe,
    Other(char),
}

impl ProbeType {
    fn from_char(c: char) -> Self {
        match c {
            'p' | 'P' => ProbeType::Kprobe,
            'r' | 'R' => ProbeType::Kretprobe,
            other => ProbeType::Other(other),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ProbeType::Kprobe => "kprobe",
            ProbeType::Kretprobe => "kretprobe",
            ProbeType::Other(_) => "unknown",
        }
    }
}

#[derive(Debug)]
struct KprobeEvent {
    probe_type: ProbeType,
    event_name: String,
    symbol: String,
    raw: String,
}

fn parse_kprobe_events(content: &str) -> Vec<KprobeEvent> {
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let first = match parts.next() {
            Some(value) => value,
            None => continue,
        };

        let (type_char, event_name) = parse_event_token(first);
        let probe_type = ProbeType::from_char(type_char);

        let symbol_token = match parts.next() {
            Some(value) => value,
            None => continue,
        };

        let symbol = normalize_symbol(symbol_token);
        if symbol.is_empty() {
            continue;
        }

        let key = (probe_type, event_name.clone(), symbol.clone());
        if seen.insert(key.clone()) {
            events.push(KprobeEvent {
                probe_type,
                event_name,
                symbol,
                raw: trimmed.to_string(),
            });
        }
    }

    events
}

fn parse_event_token(token: &str) -> (char, String) {
    let mut chars = token.chars();
    let type_char = chars.next().unwrap_or('p');
    if let Some(idx) = token.find(':') {
        let rest = &token[idx + 1..];
        (type_char, rest.to_string())
    } else {
        (type_char, token[1..].to_string())
    }
}

fn normalize_symbol(token: &str) -> String {
    let base = token
        .split(|c| matches!(c, '+' | '@' | '/'))
        .next()
        .unwrap_or(token)
        .trim();
    base.to_string()
}

fn parse_kprobe_profile(content: &str) -> BTreeMap<(ProbeType, String), u64> {
    let mut map = BTreeMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let probe_token = match parts.next() {
            Some(token) => token,
            None => continue,
        };

        let type_char = probe_token.chars().next().unwrap_or('p');
        let probe_type = ProbeType::from_char(type_char);

        let event_name = match parts.next() {
            Some(name) => name.to_string(),
            None => continue,
        };

        let hits = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);

        map.insert((probe_type, event_name), hits);
    }

    map
}

fn is_sensitive_symbol(symbol: &str) -> bool {
    const PREFIXES: [&str; 4] = ["sys_", "vfs_", "tcp_", "security_"];
    PREFIXES.iter().any(|prefix| symbol.starts_with(prefix))
}

fn find_tracefs_root() -> io::Result<PathBuf> {
    const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];
    for root in TRACEFS_ROOTS {
        let path = Path::new(root);
        if path.exists() {
            return Ok(path.to_path_buf());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "tracefs not mounted in expected locations",
    ))
}
