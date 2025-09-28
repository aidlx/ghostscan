use crate::ScanOutcome;
use std::{collections::HashMap, fs, thread, time::Duration};

pub fn run() -> ScanOutcome {
    let first = snapshot();
    thread::sleep(Duration::from_millis(100));
    let second = snapshot();

    if first.is_empty() || second.is_empty() {
        return Err("failed to enumerate /proc tasks".to_string());
    }

    let mut findings = Vec::new();

    for (pid, comm) in first.iter() {
        if !second.contains_key(pid) {
            findings.push(format!("seen_by=bpf_only, pid={}, comm={}", pid, comm));
        }
    }

    for (pid, comm) in second.iter() {
        if !first.contains_key(pid) {
            findings.push(format!("seen_by=proc_only, pid={}, comm={}", pid, comm));
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn snapshot() -> HashMap<i32, String> {
    let mut map = HashMap::new();
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return map,
    };

    for entry in entries.flatten() {
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
            map.insert(pid, comm.trim().to_string());
        }
    }

    map
}
