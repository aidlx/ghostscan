use crate::ScanOutcome;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let sources = vec![
        Source::System(PathBuf::from("/etc/crontab")),
        Source::SystemDir(PathBuf::from("/etc/cron.d")),
        Source::UserDir(PathBuf::from("/var/spool/cron")),
        Source::System(PathBuf::from("/etc/anacrontab")),
    ];

    for source in sources {
        match process_source(&source) {
            Ok(mut list) => findings.append(&mut list),
            Err(err) => errors.push(err),
        }
    }

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

enum Source {
    System(PathBuf),
    SystemDir(PathBuf),
    UserDir(PathBuf),
}

fn process_source(source: &Source) -> Result<Vec<String>, String> {
    match source {
        Source::System(path) => parse_file(path, None, true),
        Source::SystemDir(dir) => {
            let mut entries = Vec::new();
            let read = fs::read_dir(dir)
                .map_err(|err| format!("failed to read {}: {err}", dir.display()))?;
            for entry in read.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    entries.extend(parse_file(&path, Some(name), true)?);
                }
            }
            Ok(entries)
        }
        Source::UserDir(dir) => {
            let mut entries = Vec::new();
            let read = match fs::read_dir(dir) {
                Ok(read) => read,
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        return Ok(entries);
                    }
                    return Err(format!("failed to read {}: {err}", dir.display()));
                }
            };
            for entry in read.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let user = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    entries.extend(parse_file(&path, Some(user), false)?);
                }
            }
            Ok(entries)
        }
    }
}

fn parse_file(
    path: &Path,
    owner_override: Option<String>,
    has_user_field: bool,
) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    let mut findings = Vec::new();
    let owner = owner_override.unwrap_or_else(|| "system".to_string());

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 6 && has_user_field {
            continue;
        }
        if parts.len() < 5 {
            continue;
        }

        let (spec, command) = if has_user_field {
            let cmd_index = 6;
            if parts.len() < cmd_index + 1 {
                continue;
            }
            (parts[..cmd_index].join(" "), parts[cmd_index..].join(" "))
        } else {
            let cmd_index = 5;
            if parts.len() < cmd_index + 1 {
                continue;
            }
            (parts[..cmd_index].join(" "), parts[cmd_index..].join(" "))
        };

        let anomaly = evaluate_command(&command);
        if let Some(label) = anomaly {
            findings.push(format!(
                "owner={}, source={}, spec={}, cmd={}, anomaly={}",
                owner,
                path.display(),
                spec,
                command,
                label
            ))
        }
    }

    Ok(findings)
}

fn evaluate_command(command: &str) -> Option<&'static str> {
    let token = command.split_whitespace().next()?;
    if token.starts_with('/') {
        if !Path::new(token).exists() {
            return Some("target_missing");
        }
        if token.starts_with("/tmp/") || token.starts_with("/var/tmp/") {
            return Some("exec_in_tmp");
        }
    } else if token.contains("/tmp/") {
        return Some("exec_in_tmp");
    }

    None
}
