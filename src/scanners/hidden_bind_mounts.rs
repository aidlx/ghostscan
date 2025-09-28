use crate::ScanOutcome;
use std::fs;

const CRITICAL_PATHS: &[&str] = &["/etc", "/bin", "/sbin", "/usr", "/proc"];

pub fn run() -> ScanOutcome {
    let mountinfo = match fs::read_to_string("/proc/self/mountinfo") {
        Ok(content) => content,
        Err(err) => return Err(format!("failed to read mountinfo: {err}")),
    };

    let mut findings = Vec::new();

    for line in mountinfo.lines() {
        let mut parts = line.split(" - ");
        let prefix = match parts.next() {
            Some(p) => p,
            None => continue,
        };
        let suffix = match parts.next() {
            Some(s) => s,
            None => continue,
        };

        let prefix_fields: Vec<&str> = prefix.split_whitespace().collect();
        if prefix_fields.len() < 7 {
            continue;
        }
        let mount_point = prefix_fields[4];
        let optional = &prefix_fields[6..];

        let mut has_bind = false;
        for field in optional {
            if *field == "bind" {
                has_bind = true;
                break;
            }
        }

        let suffix_fields: Vec<&str> = suffix.split_whitespace().collect();
        if suffix_fields.len() < 3 {
            continue;
        }
        let fstype = suffix_fields[0];
        let _source = suffix_fields[1];
        let super_opts = suffix_fields[2];

        if has_bind {
            for critical in CRITICAL_PATHS {
                if mount_point == *critical || mount_point.starts_with(&format!("{}/", critical)) {
                    findings.push(format!(
                        "mount_point={}, covering={}, anomaly=bind_over_system_path",
                        mount_point, critical
                    ));
                }
            }
        }

        if fstype == "proc" && super_opts.contains("hidepid=2") {
            findings.push(format!(
                "mount_point={}, covering=/proc, anomaly=hidepid=2_on_/proc",
                mount_point
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
