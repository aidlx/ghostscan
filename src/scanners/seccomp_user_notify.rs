use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let proc_entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(err) => return Err(format!("failed to read /proc: {err}")),
    };

    for entry in proc_entries.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };

        match scan_pid(pid) {
            Ok(Some(f)) => findings.push(f),
            Ok(None) => {}
            Err(err) => errors.push(err),
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

fn scan_pid(pid: u32) -> Result<Option<String>, String> {
    let fd_dir = format!("/proc/{pid}/fd");
    let entries = match fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(None);
            }
            return Err(format!("pid={pid} fd: {err}"));
        }
    };

    let mut notify_fds = 0u32;

    for fd in entries.flatten() {
        let target = match fs::read_link(fd.path()) {
            Ok(link) => match link.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            },
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    continue;
                }
                return Err(format!("pid={pid} fd {}: {err}", fd.path().display()));
            }
        };

        if target.contains("seccomp") && target.contains("notify") {
            notify_fds += 1;
        }
    }

    if notify_fds == 0 {
        return Ok(None);
    }

    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_else(|_| "?".to_string())
        .trim()
        .to_string();
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let root = fs::read_link(format!("/proc/{pid}/root"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/".to_string());

    let mut issues = Vec::new();
    if notify_fds > 1 {
        issues.push("multiple_listeners".to_string());
    }
    if exe.contains("(deleted)") {
        issues.push("exe_deleted".to_string());
    }
    if exe.starts_with("/tmp/") || exe.starts_with("/var/tmp/") || exe.starts_with("/dev/shm/") {
        issues.push("exe_temporary".to_string());
    }
    if root != "/" {
        issues.push("containerized_root".to_string());
    }

    Ok(Some(format!(
        "pid={} comm={} exe={} root={} seccomp_notify_fds={} issues={}",
        pid,
        comm,
        exe,
        root,
        notify_fds,
        issues.join("|")
    )))
}
