use crate::ScanOutcome;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    analyze_proc_path(
        "/proc/sys/kernel/modprobe",
        Some("/sbin/modprobe"),
        "modprobe",
        &mut findings,
        &mut errors,
    );

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

fn analyze_proc_path(
    proc_path: &str,
    default: Option<&str>,
    label: &str,
    findings: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    let raw = match fs::read_to_string(proc_path) {
        Ok(content) => content,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound && default.is_none() {
                return;
            }
            errors.push(format!("{label}: failed to read {proc_path}: {err}"));
            return;
        }
    };

    let value = raw.trim();

    if value.is_empty() {
        if default.is_some() {
            findings.push(format!("{label} path=∅ issues=empty_value"));
        }
        return;
    }

    let mut issues = Vec::new();

    if let Some(default_path) = default {
        if value != default_path {
            issues.push("non_default");
        }
    }

    if !value.starts_with('/') {
        issues.push("non_absolute");
    }

    if value.starts_with("/tmp/")
        || value.starts_with("/var/tmp/")
        || value.starts_with("/dev/shm/")
        || value.contains("(deleted)")
    {
        issues.push("suspicious_location");
    }

    match investigate_target(value) {
        Ok(target_issues) => issues.extend(target_issues),
        Err(err) => errors.push(format!("{label}: {err}")),
    }

    if !issues.is_empty() {
        findings.push(format!(
            "{label} path={} issues={}",
            value,
            issues.join("|")
        ));
    }
}

fn investigate_target(path: &str) -> Result<Vec<&'static str>, String> {
    let mut issues = Vec::new();
    let target = Path::new(path);

    let metadata = match fs::metadata(target) {
        Ok(meta) => meta,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                issues.push("missing_target");
                return Ok(issues);
            }
            return Err(format!("stat {path}: {err}"));
        }
    };

    let mode = metadata.mode();
    let uid = metadata.uid();

    if uid != 0 {
        issues.push("non_root_owner");
    }
    if mode & 0o022 != 0 {
        issues.push("group_or_world_writable");
    }

    // If the path is a symlink, also check its target for suspicious locations.
    if let Ok(symlink_target) = fs::read_link(target) {
        if looks_temporary(&symlink_target) {
            issues.push("symlink_to_temporary");
        }
    }

    Ok(issues)
}

fn looks_temporary(path: &Path) -> bool {
    if let Some(s) = path.to_str() {
        s.starts_with("/tmp/") || s.starts_with("/var/tmp/") || s.starts_with("/dev/shm/")
    } else {
        false
    }
}
