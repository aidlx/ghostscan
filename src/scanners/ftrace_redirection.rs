use crate::ScanOutcome;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

pub fn run() -> ScanOutcome {
    let trace_root =
        find_tracefs_root().map_err(|err| format!("failed to locate tracefs: {err}"))?;

    let tracer = read_trimmed(trace_root.join("current_tracer"))
        .map_err(|err| format!("failed to read current_tracer: {err}"))?;

    let filter_content = read_file(trace_root.join("set_ftrace_filter"))
        .map_err(|err| format!("failed to read set_ftrace_filter: {err}"))?;

    let sensitive_matches = collect_sensitive_matches(&filter_content);

    let tracer_is_redirected = tracer != "nop" && !tracer.is_empty();
    if !tracer_is_redirected && sensitive_matches.is_empty() {
        return Ok(None);
    }

    let matches = if sensitive_matches.is_empty() {
        "none".to_string()
    } else {
        sensitive_matches.into_iter().collect::<Vec<_>>().join(",")
    };

    Ok(Some(format!(
        "tracer={tracer}, sensitive_matches={matches}"
    )))
}

fn collect_sensitive_matches(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let symbol = trimmed.split_whitespace().next().unwrap_or(trimmed);
            if is_sensitive_symbol(symbol) {
                Some(symbol.to_string())
            } else {
                None
            }
        })
        .collect()
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

fn read_trimmed(path: PathBuf) -> io::Result<String> {
    let content = fs::read_to_string(&path)?;
    Ok(content.trim().to_string())
}

fn read_file(path: PathBuf) -> io::Result<String> {
    let mut file = fs::File::open(&path)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    Ok(buf)
}
