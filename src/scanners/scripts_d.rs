use crate::ScanOutcome;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

const ROOT: &str = "/etc";

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    if let Ok(entries) = fs::read_dir(ROOT) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".d") {
                        if let Ok(mut list) = inspect_dir(&path) {
                            findings.append(&mut list);
                        }
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

fn inspect_dir(path: &Path) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    let entries =
        fs::read_dir(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    for entry in entries.flatten() {
        let file = entry.path();
        if file.is_file() {
            if let Ok(meta) = fs::metadata(&file) {
                let mode = meta.mode() & 0o777;
                let owner = meta.uid();
                let insecure = owner != 0 || mode & 0o002 != 0;
                let tmp = file.to_string_lossy().contains("/tmp/");
                if insecure || tmp {
                    let mut reasons = Vec::new();
                    if owner != 0 {
                        reasons.push(format!("owner={}", owner));
                    }
                    if mode & 0o002 != 0 {
                        reasons.push(format!("world_writable=true (mode={:o})", mode));
                    }
                    if tmp {
                        reasons.push("path_in_tmp=true".to_string());
                    }
                    findings.push(format!("script={}, {}", file.display(), reasons.join(", ")));
                }
            }
        }
    }
    Ok(findings)
}
