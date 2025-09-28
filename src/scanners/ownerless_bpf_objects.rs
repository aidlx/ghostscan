use crate::ScanOutcome;
use std::process::Command;

pub fn run() -> ScanOutcome {
    if Command::new("bpftool").arg("--version").output().is_err() {
        return Err("bpftool not available to enumerate BPF objects".to_string());
    }

    let output = Command::new("bpftool")
        .args(["-j", "prog", "show"])
        .output()
        .map_err(|err| format!("failed to execute bpftool prog show: {err}"))?;
    if !output.status.success() {
        return Err(format!("bpftool prog show exited with {}", output.status));
    }

    let progs: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse bpftool prog output: {err}"))?;

    let mut findings = Vec::new();

    if let Some(programs) = progs.as_array() {
        for prog in programs {
            if let Some(id) = prog.get("id").and_then(|v| v.as_u64()) {
                let has_pinned = prog
                    .get("pinned")
                    .and_then(|v| v.as_array())
                    .map(|arr| !arr.is_empty())
                    .unwrap_or(false);
                let has_fd = prog
                    .get("pids")
                    .and_then(|v| v.as_array())
                    .map(|arr| !arr.is_empty())
                    .unwrap_or(false);
                if !has_pinned && !has_fd {
                    let name = prog
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    findings.push(format!(
                        "object=prog, id={}, name={}, pinned=false, owner_pids=∅",
                        id, name
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}
