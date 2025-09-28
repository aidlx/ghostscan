use crate::ScanOutcome;
use std::{fs, io, path::Path};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    match fs::read_dir("/proc") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let pid_str = file_name.to_string_lossy();
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

fn inspect_process(pid: i32) -> Result<Option<String>, io::Error> {
    let comm_path = Path::new("/proc").join(pid.to_string()).join("comm");
    let comm = fs::read_to_string(&comm_path)?.trim().to_string();

    if !(comm.starts_with('[') && comm.ends_with(']')) {
        return Ok(None);
    }

    let status_path = Path::new("/proc").join(pid.to_string()).join("status");
    let status = fs::read_to_string(&status_path)?;
    let vm_size = parse_vm_size(&status).unwrap_or(0);

    let maps_path = Path::new("/proc").join(pid.to_string()).join("maps");
    let has_maps = fs::File::open(&maps_path)
        .and_then(|mut file| {
            use std::io::Read;
            let mut buf = [0u8; 1];
            match file.read(&mut buf) {
                Ok(0) => Ok(false),
                Ok(_) => Ok(true),
                Err(err) => Err(err),
            }
        })
        .unwrap_or(false);

    let has_user_mm = vm_size > 0 || has_maps;

    if has_user_mm {
        Ok(Some(format!(
            "pid={}, comm={}, kthread_name_like=true, has_user_mm=true",
            pid, comm
        )))
    } else {
        Ok(None)
    }
}

fn parse_vm_size(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmSize:") {
            let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            if let Ok(value) = digits.parse::<u64>() {
                return Some(value);
            }
        }
    }
    None
}
