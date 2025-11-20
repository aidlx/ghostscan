use crate::ScanOutcome;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub fn run() -> ScanOutcome {
    let mut errors = Vec::new();
    let pattern_raw = match fs::read_to_string("/proc/sys/kernel/core_pattern") {
        Ok(content) => content,
        Err(err) => {
            return Err(format!(
                "failed to read /proc/sys/kernel/core_pattern: {err}"
            ));
        }
    };

    let pattern = pattern_raw.trim();
    if !pattern.starts_with('|') {
        return Ok(None);
    }

    let pipe_limit = match fs::read_to_string("/proc/sys/kernel/core_pipe_limit") {
        Ok(content) => content.trim().to_string(),
        Err(err) => {
            errors.push(format!("core_pipe_limit: {err}"));
            String::new()
        }
    };

    let mut findings = Vec::new();
    if let Some(f) = analyze_pipeline(pattern, &pipe_limit, &mut errors) {
        findings.push(f);
    }

    if findings.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Err(errors.join(", "))
        }
    } else {
        if !errors.is_empty() {
            findings.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(findings.join("\n")))
    }
}

fn analyze_pipeline(pattern: &str, pipe_limit: &str, errors: &mut Vec<String>) -> Option<String> {
    let pipeline = pattern.trim_start_matches('|').trim();
    let target = pipeline.split_whitespace().next().unwrap_or("");

    let mut issues = Vec::new();

    if target.is_empty() {
        issues.push("missing_target");
    } else {
        if !target.starts_with('/') {
            issues.push("non_absolute");
        }
        if target.starts_with("/tmp/")
            || target.starts_with("/var/tmp/")
            || target.starts_with("/dev/shm/")
            || target.contains("(deleted)")
        {
            issues.push("suspicious_location");
        }

        match evaluate_target(target) {
            Ok(mut more) => issues.append(&mut more),
            Err(err) => errors.push(err),
        }
    }

    if let Ok(value) = pipe_limit.parse::<i64>() {
        if value == 0 {
            issues.push("unbounded_pipe_limit");
        } else if value < 0 {
            issues.push("negative_pipe_limit");
        }
    } else if !pipe_limit.is_empty() {
        errors.push(format!("failed to parse core_pipe_limit={pipe_limit}"));
    }

    if issues.is_empty() {
        None
    } else {
        Some(format!(
            "core_pattern pipeline={} issues={}",
            pipeline,
            issues.join("|")
        ))
    }
}

fn evaluate_target(target: &str) -> Result<Vec<&'static str>, String> {
    let mut issues = Vec::new();
    let path = Path::new(target);

    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.mode();
            let uid = meta.uid();
            if uid != 0 {
                issues.push("non_root_owner");
            }
            if mode & 0o022 != 0 {
                issues.push("group_or_world_writable");
            }
        }
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                issues.push("target_missing");
            } else {
                return Err(format!("stat {target}: {err}"));
            }
        }
    }

    Ok(issues)
}
