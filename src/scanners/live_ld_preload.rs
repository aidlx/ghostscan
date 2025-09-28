use crate::ScanOutcome;
use std::{collections::HashSet, fs, os::unix::fs::MetadataExt, path::PathBuf};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let proc = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(err) => return Err(format!("failed to read /proc: {err}")),
    };

    for entry in proc.flatten() {
        let name = entry.file_name();
        let pid: i32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };

        if let Ok(Some(record)) = inspect_process(pid) {
            findings.push(record);
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn inspect_process(pid: i32) -> Result<Option<String>, String> {
    let environ_path = format!("/proc/{pid}/environ");
    let env_bytes = fs::read(&environ_path).map_err(|err| format!("{environ_path}: {err}"))?;
    let mut preload_paths = Vec::new();
    for entry in env_bytes.split(|b| *b == 0) {
        if entry.starts_with(b"LD_PRELOAD=") {
            let value = String::from_utf8_lossy(&entry[11..]).into_owned();
            preload_paths.extend(value.split(':').map(|s| s.to_string()));
        }
    }

    if preload_paths.is_empty() {
        return Ok(None);
    }

    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let mut anomalies = HashSet::new();
    let mapped_paths = collect_mapped_paths(pid);

    for path in preload_paths.iter() {
        if path.is_empty() {
            continue;
        }
        let target = if path.contains("(deleted)") {
            anomalies.insert("mapped_from=deleted".to_string());
            continue;
        } else {
            PathBuf::from(path)
        };

        if target.is_absolute() && !target.exists() {
            anomalies.insert(format!("missing={}", path));
            continue;
        }

        if let Some(parent) = target.parent() {
            if let Ok(meta) = fs::metadata(parent) {
                if meta.mode() & 0o002 != 0 {
                    anomalies.insert(format!("mapped_from=writable_dir({})", parent.display()));
                }
            }
        }

        if mapped_paths.contains(path) {
            if path.contains("(deleted)") {
                anomalies.insert("mapped_from=deleted".to_string());
            }
        }
    }

    if anomalies.is_empty() {
        return Ok(None);
    }

    let mut anomalies_vec: Vec<_> = anomalies.into_iter().collect();
    anomalies_vec.sort();

    Ok(Some(format!(
        "pid={}, comm={}, LD_PRELOAD={}, {}",
        pid,
        comm,
        preload_paths.join("|"),
        anomalies_vec.join(", ")
    )))
}

fn collect_mapped_paths(pid: i32) -> HashSet<String> {
    let mut set = HashSet::new();
    let path = format!("/proc/{pid}/maps");
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            if let Some(path) = line.split_whitespace().nth(5) {
                if !path.is_empty() && !path.starts_with('[') {
                    set.insert(path.to_string());
                }
            }
        }
    }
    set
}
