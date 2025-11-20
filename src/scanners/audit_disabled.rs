use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let enabled = match fs::read_to_string("/proc/sys/kernel/audit_enabled") {
        Ok(value) => value.trim().to_string(),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!("failed to read audit_enabled: {err}"));
        }
    };

    let mut findings = Vec::new();
    if enabled == "0" {
        findings.push("enabled=0".to_string());
    }

    let mut backlog_limit: Option<u64> = None;

    if let Ok(content) = fs::read_to_string("/proc/net/audit") {
        for line in content.lines() {
            for token in line.split_whitespace() {
                if let Some(rest) = token.strip_prefix("lost=") {
                    if rest != "0" {
                        findings.push(format!("lost_events={}", rest));
                    }
                }
                if let Some(rest) = token.strip_prefix("backlog_limit=") {
                    if let Ok(value) = rest.parse::<u64>() {
                        backlog_limit = Some(value);
                    }
                }
            }
        }
    }

    const MIN_BACKLOG_LIMIT: u64 = 32;
    if let Some(limit) = backlog_limit {
        if limit < MIN_BACKLOG_LIMIT {
            findings.push(format!("backlog_limit_small={}", limit));
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        Ok(Some(findings.join(", ")))
    }
}
