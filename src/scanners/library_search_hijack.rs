use crate::ScanOutcome;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(err) => return Err(format!("failed to read /proc: {err}")),
    };

    for entry in proc_dir.flatten() {
        let pid: i32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };

        match inspect_process(pid) {
            Ok(mut list) => findings.append(&mut list),
            Err(_) => {}
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn inspect_process(pid: i32) -> Result<Vec<String>, String> {
    let stat_path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(&stat_path).map_err(|err| format!("{stat_path}: {err}"))?;

    let mut euid = 0u32;
    let mut cap_eff = String::new();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(uid) = rest.split_whitespace().nth(1) {
                euid = uid.parse().unwrap_or(0);
            }
        }
        if let Some(rest) = line.strip_prefix("CapEff:") {
            cap_eff = rest.trim().to_string();
        }
    }

    if euid != 0 && cap_eff == "0000000000000000" {
        return Ok(Vec::new());
    }

    let maps_path = format!("/proc/{pid}/maps");
    let content = fs::read_to_string(&maps_path).map_err(|err| format!("{maps_path}: {err}"))?;
    let mut findings = Vec::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let _range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");
        let _offset = parts.next();
        let _dev = parts.next();
        let _inode = parts.next();
        let path = parts.next().unwrap_or("");
        if path.is_empty() || path.starts_with('[') {
            continue;
        }
        if !perms.contains('r') {
            continue;
        }
        if let Some(parent) = Path::new(path).parent() {
            if let Ok(meta) = fs::metadata(parent) {
                if meta.mode() & 0o002 != 0 {
                    findings.push(format!(
                        "pid={}, comm={}, lib={}, dir_writable=true",
                        pid,
                        command(pid),
                        path
                    ));
                }
            }
        }
    }

    Ok(findings)
}

fn command(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}
