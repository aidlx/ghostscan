use crate::ScanOutcome;
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    match fs::read_dir("/proc") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let pid_str = name.to_string_lossy();
                if let Ok(pid) = pid_str.parse::<i32>() {
                    match inspect_process(pid) {
                        Ok(Some(record)) => findings.push(record),
                        Ok(None) => {}
                        Err(err) => errors.push(format!("pid={pid}: {err}")),
                    }
                }
            }
        }
        Err(err) => return Err(format!("failed to read /proc: {err}")),
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

fn inspect_process(pid: i32) -> std::io::Result<Option<String>> {
    let proc_path = PathBuf::from("/proc").join(pid.to_string());
    let exe = fs::read_link(proc_path.join("exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    if !is_suspicious_exe(&exe) {
        return Ok(None);
    }

    let comm = fs::read_to_string(proc_path.join("comm"))?
        .trim()
        .to_string();
    let cwd = fs::read_link(proc_path.join("cwd"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let exe_meta = fs::metadata(&exe).ok();
    let mtime = exe_meta
        .as_ref()
        .and_then(|meta| meta.mtime().try_into().ok())
        .unwrap_or(0);

    let sockets = collect_listening_sockets(pid);

    if sockets.is_empty() {
        return Ok(None);
    }

    let socket_info = sockets.join("|");

    Ok(Some(format!(
        "pid={}, comm={}, laddr={}, exe_path={}, cwd={}, exe_mtime={}",
        pid, comm, socket_info, exe, cwd, mtime
    )))
}

fn is_suspicious_exe(path: &str) -> bool {
    path.contains("/tmp/") || path.contains("/home/") || path.contains("(deleted)")
}

fn collect_listening_sockets(pid: i32) -> Vec<String> {
    let mut sockets = Vec::new();
    if let Ok(content) = fs::read_to_string(format!("/proc/{pid}/net/tcp")) {
        sockets.extend(parse_listeners(&content));
    }
    if let Ok(content) = fs::read_to_string(format!("/proc/{pid}/net/tcp6")) {
        sockets.extend(parse_listeners(&content));
    }
    sockets
}

fn parse_listeners(content: &str) -> Vec<String> {
    let mut listeners = Vec::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        if parts[3] != "0A" {
            continue;
        }
        if let Some(endpoint) = parts.get(1) {
            listeners.push(endpoint.to_string());
        }
    }
    listeners
}
