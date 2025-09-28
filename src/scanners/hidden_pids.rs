use crate::ScanOutcome;
use std::{fs, thread, time::Duration};

pub fn run() -> ScanOutcome {
    let first = snapshot();
    thread::sleep(Duration::from_millis(100));
    let second = snapshot();

    if first.is_empty() || second.is_empty() {
        return Err("failed to enumerate /proc tasks".to_string());
    }

    let mut findings = Vec::new();

    for (pid, comm) in &first {
        if !second.contains(pid) {
            findings.push(format!("pid={}, comm={}, seen_by=bpf_only", pid, comm));
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn snapshot() -> Vec<(i32, String)> {
    let mut entries = Vec::new();
    let dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return entries,
    };

    for entry in dir.flatten() {
        let name = entry.file_name();
        let pid_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let pid: i32 = match pid_str.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        if let Ok(comm) = fs::read_to_string(entry.path().join("comm")) {
            entries.push((pid, comm.trim().to_string()));
        }
    }
    entries
}

trait ContainsPid {
    fn contains(&self, pid: &i32) -> bool;
}

impl ContainsPid for Vec<(i32, String)> {
    fn contains(&self, pid: &i32) -> bool {
        self.iter().any(|(p, _)| p == pid)
    }
}
