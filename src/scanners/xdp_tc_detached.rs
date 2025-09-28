use crate::ScanOutcome;
use serde_json::Value;
use std::process::Command;

fn value_has_meaningful_data(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(items) => items.iter().any(value_has_meaningful_data),
        Value::Object(map) => map.values().any(value_has_meaningful_data),
    }
}

pub fn run() -> ScanOutcome {
    if Command::new("bpftool").arg("--version").output().is_err() {
        return Err("bpftool not available to inspect XDP/TC programs".to_string());
    }

    let output = Command::new("bpftool")
        .args(["-j", "net", "list"])
        .output()
        .map_err(|err| format!("failed to execute bpftool net list: {err}"))?;

    if !output.status.success() {
        return Err(format!("bpftool net list exited with {}", output.status));
    }

    let payload = String::from_utf8_lossy(&output.stdout);
    let payload = payload.trim();
    if payload.is_empty() {
        Ok(None)
    } else {
        match serde_json::from_str::<Value>(payload) {
            Ok(value) if !value_has_meaningful_data(&value) => Ok(None),
            _ => Ok(Some(payload.to_string())),
        }
    }
}
