use super::container_utils::collect_container_states;
use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let host_ns = match fs::read_link("/proc/1/ns/pid") {
        Ok(link) => link,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(None);
            }
            return Err(format!("failed to read host pid ns: {err}"));
        }
    };

    let states = match collect_container_states(1024) {
        Ok(states) => states,
        Err(err) => return Err(err),
    };

    let mut findings = Vec::new();

    for state in states {
        if let Some(pid) = state.pid {
            match fs::read_link(format!("/proc/{pid}/ns/pid")) {
                Ok(link) => {
                    if link == host_ns {
                        findings.push(format!("container_id={}, host_pid_ns=true", state.id));
                    }
                }
                Err(err) => {
                    if err.kind() != std::io::ErrorKind::PermissionDenied {
                        continue;
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}
