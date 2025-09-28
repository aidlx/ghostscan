use crate::ScanOutcome;
use std::process::Command;

pub fn run() -> ScanOutcome {
    if Command::new("bpftool").arg("--version").output().is_err() {
        return Err("bpftool not available to enumerate BPF programs".to_string());
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

    if let Some(array) = progs.as_array() {
        for prog in array {
            let prog_type = prog
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if !prog_type.contains("lsm") {
                continue;
            }

            let prog_id = prog
                .get("id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let attach_point = prog
                .get("attach_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let name = prog
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let tag = prog
                .get("tag")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            findings.push(format!(
                "prog_id={}, attach_point={}, name={}, tag={}",
                prog_id, attach_point, name, tag
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
