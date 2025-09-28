use crate::ScanOutcome;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    process::{Command, Stdio},
};

pub fn run() -> ScanOutcome {
    if Command::new("bpftool")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Err("bpftool not available to inspect kfunc usage".to_string());
    }

    let output = Command::new("bpftool")
        .args(["-j", "prog", "show"])
        .output()
        .map_err(|err| format!("failed to execute bpftool prog show: {err}"))?;

    if !output.status.success() {
        return Err(format!("bpftool prog show exited with {}", output.status));
    }

    let progs: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse bpftool prog output: {err}"))?;

    let mut findings = Vec::new();
    let mut errors = Vec::new();

    if let Some(array) = progs.as_array() {
        for prog in array {
            let id = prog.get("id").and_then(|v| v.as_u64());
            let name = prog
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let Some(id) = id else {
                continue;
            };

            match inspect_program(id) {
                Ok(kfuncs) if !kfuncs.is_empty() => {
                    let joined = kfuncs.into_iter().collect::<Vec<_>>().join("|");
                    findings.push(format!("prog_id={}, name={}, kfuncs={}", id, name, joined));
                }
                Ok(_) => {}
                Err(err) => errors.push(format!("prog_id={}: {}", id, err)),
            }
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

fn inspect_program(id: u64) -> Result<BTreeSet<String>, String> {
    let id_str = id.to_string();
    let output = Command::new("bpftool")
        .args(["prog", "dump", "xlated", "id", &id_str])
        .output()
        .map_err(|err| format!("failed to dump program: {err}"))?;

    if !output.status.success() {
        return Err(format!("dump failed with status {}", output.status));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut matches = BTreeSet::new();

    for line in text.lines() {
        if let Some(symbol) = extract_called_symbol(line) {
            if is_sensitive_symbol(&symbol) {
                matches.insert(symbol);
            }
        }
    }

    Ok(matches)
}

fn extract_called_symbol(line: &str) -> Option<String> {
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "call" {
            if let Some(target) = tokens.next() {
                let cleaned = target.trim_matches(',');
                if cleaned.chars().all(|c| c.is_numeric()) {
                    return None;
                }
                if cleaned.is_empty() {
                    return None;
                }
                return Some(cleaned.trim().to_string());
            }
        }
    }
    None
}

fn is_sensitive_symbol(symbol: &str) -> bool {
    let lower = symbol.to_ascii_lowercase();
    lower.contains("task")
        || lower.contains("cred")
        || lower.starts_with("security_")
        || (lower.starts_with("bpf_") && lower.contains("_override"))
}
