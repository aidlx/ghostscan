use crate::ScanOutcome;
use std::{fs, path::Path};

const SYSTEM_LIB_DIRS: &[&str] = &["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();

    if let Ok(entries) = fs::read_dir("/etc/pam.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(mut list) = analyse_pam_file(&path) {
                    findings.append(&mut list);
                }
            }
        }
    }

    if let Ok(content) = fs::read_to_string("/etc/nsswitch.conf") {
        if let Some(mut list) = analyse_nsswitch(&content) {
            for entry in list.drain(..) {
                findings.push(entry);
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

fn analyse_pam_file(path: &Path) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let module_path = parts[2];
        if module_path.starts_with('/') && !is_system_lib(module_path) {
            findings.push(format!(
                "file={}, line_no={}, line={}, anomaly=module_outside_system_libdirs",
                path.display(),
                idx + 1,
                line.trim()
            ));
        }
    }

    Ok(findings)
}

fn analyse_nsswitch(content: &str) -> Option<Vec<String>> {
    let mut findings = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(fields) = trimmed.split_once(':') {
            let services = fields.1.trim().split_whitespace();
            for service in services {
                if service.starts_with('/') && !is_system_lib(service) {
                    findings.push(format!(
                        "file=/etc/nsswitch.conf, line_no={}, line={}, anomaly=module_outside_system_libdirs",
                        idx + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
}

fn is_system_lib(path: &str) -> bool {
    SYSTEM_LIB_DIRS.iter().any(|dir| path.starts_with(dir))
}
