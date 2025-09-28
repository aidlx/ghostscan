use crate::ScanOutcome;
use std::fs;

const MIN_SIZE: u64 = 65536;
const MAX_PROCESSES: usize = 256;

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(err) => return Err(format!("failed to read /proc: {err}")),
    };

    for entry in proc_dir.flatten().take(MAX_PROCESSES) {
        let pid: i32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };
        match inspect_process(pid) {
            Ok(mut list) => findings.append(&mut list),
            Err(_) => {}
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn inspect_process(pid: i32) -> Result<Vec<String>, String> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&stat_path).map_err(|err| format!("{stat_path}: {err}"))?;
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 7 {
        return Ok(Vec::new());
    }
    let tty_nr = fields[6].parse::<i64>().unwrap_or(0);
    if tty_nr != 0 {
        return Ok(Vec::new());
    }

    let maps_path = format!("/proc/{pid}/maps");
    let maps = fs::read_to_string(&maps_path).map_err(|err| format!("{maps_path}: {err}"))?;
    let mut jit_markers = false;
    if maps.contains("libjvm") || maps.contains("v8") || maps.contains("jit") {
        jit_markers = true;
    }

    if jit_markers {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let range = parts[0];
        let perms = parts[1];
        let path = parts[5];
        if !perms.contains('x') || perms.contains('s') {
            continue;
        }
        if !path.is_empty() && path != "[anon]" && path != "[heap]" && path != "[stack]" {
            continue;
        }
        if let Some(size) = mapping_size(range) {
            if size >= MIN_SIZE {
                findings.push(format!(
                    "pid={}, comm={}, anon_rx={} size={}B likely_non_jit=true",
                    pid,
                    command(pid),
                    range,
                    size
                ));
            }
        }
    }

    Ok(findings)
}

fn mapping_size(range: &str) -> Option<u64> {
    let mut parts = range.split('-');
    let start = u64::from_str_radix(parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(parts.next()?, 16).ok()?;
    Some(end.saturating_sub(start))
}

fn command(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}
