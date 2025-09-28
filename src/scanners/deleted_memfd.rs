use crate::ScanOutcome;
use std::{fs, io, path::Path};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    match fs::read_dir("/proc") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let pid_str = name.to_string_lossy();
                if let Ok(pid) = pid_str.parse::<i32>() {
                    match inspect_process(pid) {
                        Ok(Some(record)) => findings.push(record),
                        Ok(None) => {}
                        Err(err) => errors.push(format!("pid={pid}: {err}")),
                    }
                }
            }
        }
        Err(err) => return Err(format!("failed to read /proc: {err}")),
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

fn inspect_process(pid: i32) -> io::Result<Option<String>> {
    let proc_dir = Path::new("/proc").join(pid.to_string());

    let exe_path = fs::read_link(proc_dir.join("exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let indicator = if exe_path.contains("(deleted)") {
        Some(exe_path.clone())
    } else if exe_path.starts_with("memfd:") || exe_path.contains("memfd:") {
        Some(exe_path.clone())
    } else {
        None
    };

    let Some(exe) = indicator else {
        return Ok(None);
    };

    let comm = fs::read_to_string(proc_dir.join("comm"))?
        .trim()
        .to_string();
    let cwd = fs::read_link(proc_dir.join("cwd"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let cmdline = fs::read(proc_dir.join("cmdline"))
        .unwrap_or_default()
        .split(|b| *b == 0)
        .filter(|segment| !segment.is_empty())
        .map(|segment| String::from_utf8_lossy(segment).into_owned())
        .collect::<Vec<_>>()
        .join(" ");

    let cmdline = if cmdline.is_empty() {
        "".to_string()
    } else {
        cmdline
    };

    Ok(Some(format!(
        "pid={}, comm={}, exe={}, cwd={}, cmdline={}",
        pid, comm, exe, cwd, cmdline
    )))
}
