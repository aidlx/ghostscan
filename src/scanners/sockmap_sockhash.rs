use crate::ScanOutcome;
use std::process::Command;

pub fn run() -> ScanOutcome {
    if Command::new("bpftool").arg("--version").output().is_err() {
        return Err("bpftool not available to inspect SOCKMAP/SOCKHASH state".to_string());
    }

    let output = Command::new("bpftool")
        .args(["-j", "map", "show"])
        .output()
        .map_err(|err| format!("failed to execute bpftool map show: {err}"))?;

    if !output.status.success() {
        return Err(format!("bpftool map show exited with {}", output.status));
    }

    let maps: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse bpftool map output: {err}"))?;

    let mut findings = Vec::new();

    if let Some(array) = maps.as_array() {
        for map in array {
            let map_type = map
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if map_type != "sockmap" && map_type != "sockhash" {
                continue;
            }

            let map_id = map
                .get("id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let has_pin = map.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false);

            let owner_pids = map
                .get("pids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|pid| pid.as_u64())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if has_pin || !owner_pids.is_empty() {
                continue;
            }

            let verdict_prog = map
                .get("verdict_prog_id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            findings.push(format!(
                "map_id={}, type={}, verdict_prog_id={}, has_pin=false, owner_pids=∅",
                map_id, map_type, verdict_prog
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
