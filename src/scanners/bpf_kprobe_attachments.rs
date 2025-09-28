use crate::ScanOutcome;
use std::process::Command;

pub fn run() -> ScanOutcome {
    if Command::new("bpftool").arg("--version").output().is_err() {
        return Err("bpftool not available to inspect BPF links".to_string());
    }

    let output = Command::new("bpftool")
        .args(["-j", "link", "show"])
        .output()
        .map_err(|err| format!("failed to execute bpftool link show: {err}"))?;

    if !output.status.success() {
        return Err(format!("bpftool link show exited with {}", output.status));
    }

    let links: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse bpftool link output: {err}"))?;

    let mut findings = Vec::new();

    if let Some(array) = links.as_array() {
        for link in array {
            let link_type = link
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            let attach_type = link
                .get("attach_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            let is_kprobe = link_type.contains("kprobe") || attach_type.contains("kprobe");
            let is_kretprobe = link_type.contains("kretprobe") || attach_type.contains("kretprobe");

            if !is_kprobe && !is_kretprobe {
                continue;
            }

            let target = extract_target_symbol(link).unwrap_or_else(|| "unknown".to_string());
            if !is_sensitive_symbol(&target) {
                continue;
            }

            let link_id = link
                .get("id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let prog_id = link
                .get("prog_id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let attach_kind = if is_kretprobe { "kretprobe" } else { "kprobe" };

            findings.push(format!(
                "link_id={}, prog_id={}, attach={}, target={}",
                link_id, prog_id, attach_kind, target
            ));
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn extract_target_symbol(link: &serde_json::Value) -> Option<String> {
    const CANDIDATES: [&str; 5] = ["target_name", "func", "function", "kprobe", "attach_name"];
    for key in &CANDIDATES {
        if let Some(value) = link.get(key).and_then(|v| v.as_str()) {
            let cleaned = value.trim();
            if !cleaned.is_empty() {
                return Some(cleaned.to_string());
            }
        }
    }

    if let Some(map) = link.as_object() {
        for (key, value) in map {
            if key.contains("func") || key.contains("symbol") {
                if let Some(v) = value.as_str() {
                    let cleaned = v.trim();
                    if !cleaned.is_empty() {
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
    }

    None
}

fn is_sensitive_symbol(symbol: &str) -> bool {
    const PREFIXES: [&str; 4] = ["sys_", "vfs_", "tcp_", "security_"];
    PREFIXES.iter().any(|prefix| symbol.starts_with(prefix))
}
