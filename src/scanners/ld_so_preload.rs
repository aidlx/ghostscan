use crate::ScanOutcome;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub fn run() -> ScanOutcome {
    let path = Path::new("/etc/ld.so.preload");
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!("failed to read {}: {err}", path.display()));
        }
    };

    let mut findings = Vec::new();

    for line in content.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }

        let path = Path::new(entry);
        let mut parts = Vec::new();

        if !path.exists() {
            parts.push("exists=false".to_string());
        } else if let Ok(metadata) = path.metadata() {
            if let Some(parent) = path.parent() {
                if let Ok(parent_meta) = parent.metadata() {
                    if parent_meta.mode() & 0o002 != 0 {
                        parts.push(format!("parent_writable=true (dir={})", parent.display()));
                    }
                }
            }
            if metadata.uid() != 0 {
                parts.push("owner!=root".to_string());
            }
            if metadata.mode() & 0o777 != 0o644 {
                parts.push(format!("mode={:o}", metadata.mode() & 0o777));
            }
        }

        if parts.is_empty() {
            continue;
        }

        findings.push(format!("entry={}, {}", entry, parts.join(", ")));
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        Ok(Some(findings.join("\n")))
    }
}
