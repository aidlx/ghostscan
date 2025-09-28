use crate::ScanOutcome;
use std::{fs, path::Path};

const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    for dir in UNIT_DIRS {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("service") {
                        continue;
                    }
                    match analyze_unit(&path) {
                        Ok(mut list) => findings.append(&mut list),
                        Err(err) => errors.push(err),
                    }
                }
            }
            Err(err) => errors.push(format!("failed to read {}: {err}", path.display())),
        }
    }

    if findings.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Err(errors.join(", "))
        }
    } else {
        findings.sort();
        if !errors.is_empty() {
            findings.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(findings.join("\n")))
    }
}

fn analyze_unit(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("ExecStart=")
            || line.starts_with("ExecStartPre=")
            || line.starts_with("ExecStop=")
        {
            if let Some(cmd) = line.splitn(2, '=').nth(1) {
                if let Some(anomaly) = evaluate_exec(cmd) {
                    findings.push(format!(
                        "unit={}, exec={}, anomaly={}",
                        path.display(),
                        cmd.trim(),
                        anomaly
                    ));
                }
            }
        }
    }

    Ok(findings)
}

fn evaluate_exec(command: &str) -> Option<&'static str> {
    let token = command.split_whitespace().next()?;
    let token = token.trim_matches(['"', '\'']);
    if token.starts_with('/') {
        if !Path::new(token).exists() {
            if token.contains("(deleted)") {
                return Some("exec_deleted");
            }
            return Some("exec_missing");
        }
        if token.starts_with("/tmp/") || token.starts_with("/var/tmp/") {
            return Some("exec_in_tmp");
        }
    } else if token.contains("/tmp/") {
        return Some("exec_in_tmp");
    }
    None
}
