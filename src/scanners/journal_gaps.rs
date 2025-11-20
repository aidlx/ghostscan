use crate::ScanOutcome;
use serde::Deserialize;
use std::process::Command;

const GAP_THRESHOLD_SECS: u64 = 3600;

#[derive(Deserialize)]
struct JournalLine {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    timestamp: Option<String>,
}

pub fn run() -> ScanOutcome {
    let output = Command::new("journalctl")
        // Use -b to scope to current boot; more portable than --since=boot.
        .args(["-b", "--output=json", "--no-pager", "-n", "2000"])
        .output()
        .map_err(|err| format!("failed to execute journalctl: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "journalctl exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let mut timestamps = Vec::new();
    for line in output.stdout.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_slice::<JournalLine>(line) {
            if let Some(ts) = entry.timestamp.as_deref() {
                if let Ok(value) = ts.parse::<u64>() {
                    timestamps.push(value);
                }
            }
        }
    }

    timestamps.sort_unstable();
    if timestamps.len() < 2 {
        return Ok(None);
    }

    let mut findings = Vec::new();
    for window in timestamps.windows(2) {
        let gap = window[1].saturating_sub(window[0]);
        if gap / 1_000_000 > GAP_THRESHOLD_SECS {
            findings.push(format!(
                "gap_start={} gap_end={} gap_secs={}",
                window[0],
                window[1],
                gap / 1_000_000
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
