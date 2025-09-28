use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let proc = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(err) => return Err(format!("failed to read /proc: {err}")),
    };

    for entry in proc.flatten() {
        let pid: i32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };
        if let Ok(Some(record)) = inspect_process(pid) {
            findings.push(record);
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn inspect_process(pid: i32) -> Result<Option<String>, String> {
    let environ_path = format!("/proc/{pid}/environ");
    let environ = fs::read(&environ_path).map_err(|err| format!("{environ_path}: {err}"))?;
    let mut ld_audit = None;
    for entry in environ.split(|b| *b == 0) {
        if entry.starts_with(b"LD_AUDIT=") {
            ld_audit = Some(String::from_utf8_lossy(&entry[9..]).into_owned());
            break;
        }
    }
    let Some(audit_value) = ld_audit else {
        return Ok(None);
    };

    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&stat_path).map_err(|err| format!("{stat_path}: {err}"))?;
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 7 {
        return Ok(None);
    }
    let tty_nr = fields[6].parse::<i64>().unwrap_or(0);
    if tty_nr != 0 {
        return Ok(None);
    }

    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    Ok(Some(format!(
        "pid={}, comm={}, LD_AUDIT={}",
        pid, comm, audit_value
    )))
}
