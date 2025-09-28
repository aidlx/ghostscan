use crate::ScanOutcome;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let paths = vec![PathBuf::from("/etc/sudoers")];
    for path in paths {
        match analyze_file(&path) {
            Ok(mut list) => findings.append(&mut list),
            Err(err) => errors.push(err),
        }
    }

    let dir = Path::new("/etc/sudoers.d");
    if dir.exists() {
        match fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if entry.path().is_file() {
                        match analyze_file(&entry.path()) {
                            Ok(mut list) => findings.append(&mut list),
                            Err(err) => errors.push(err),
                        }
                    }
                }
            }
            Err(err) => errors.push(format!("failed to read {}: {err}", dir.display())),
        }
    }

    if findings.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Ok(Some(format!("collection_errors={}", errors.join(", "))))
        }
    } else {
        findings.sort();
        if !errors.is_empty() {
            findings.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(findings.join("\n")))
    }
}

fn analyze_file(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains("NOPASSWD: ALL") {
            findings.push(format!(
                "file={}, line_no={}, entry='{}'",
                path.display(),
                idx + 1,
                trimmed
            ));
        }
        if trimmed.contains("ALL=(ALL) ALL") && trimmed.contains("!authenticate") {
            findings.push(format!(
                "file={}, line_no={}, entry='{}'",
                path.display(),
                idx + 1,
                trimmed
            ));
        }
    }

    Ok(findings)
}
