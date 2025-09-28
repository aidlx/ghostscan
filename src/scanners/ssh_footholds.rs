use crate::ScanOutcome;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub fn run() -> ScanOutcome {
    let passwd = match fs::read_to_string("/etc/passwd") {
        Ok(content) => content,
        Err(err) => return Err(format!("failed to read /etc/passwd: {err}")),
    };

    let mut findings = Vec::new();

    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 6 {
            continue;
        }
        let user = parts[0];
        let home = Path::new(parts[5]);
        if !home.exists() {
            continue;
        }
        let auth_path = home.join(".ssh").join("authorized_keys");
        if !auth_path.exists() {
            continue;
        }

        match analyze_file(user, &auth_path) {
            Ok(mut items) => findings.append(&mut items),
            Err(err) => findings.push(format!(
                "user={}, file={}, error={}",
                user,
                auth_path.display(),
                err
            )),
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn analyze_file(user: &str, path: &Path) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    let metadata =
        fs::metadata(path).map_err(|err| format!("failed to stat {}: {err}", path.display()))?;

    if metadata.mode() & 0o077 != 0 {
        findings.push(format!(
            "user={}, file={}, perms_insecure=true",
            user,
            path.display()
        ));
    }

    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut tokens = trimmed.split_whitespace();
        let first = tokens.next().unwrap_or("");

        let (options, key_tokens): (Option<&str>, Vec<&str>) = if first.starts_with("ssh-") {
            (None, std::iter::once(first).chain(tokens).collect())
        } else {
            (Some(first), tokens.collect())
        };

        if let Some(opts) = options {
            let comment = key_tokens.get(2).copied().unwrap_or("");
            for opt in opts.split(',') {
                let opt = opt.trim();
                if opt.is_empty() {
                    continue;
                }
                if opt.starts_with("command=")
                    || opt.starts_with("permitopen=")
                    || (opt.starts_with("from=") && opt.contains('*'))
                {
                    findings.push(format!(
                        "user={}, file={}, key_comment={}, option={}",
                        user,
                        path.display(),
                        comment,
                        opt
                    ));
                }
            }
        }
    }

    Ok(findings)
}
