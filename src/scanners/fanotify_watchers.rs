use super::container_utils::collect_container_states;
use crate::ScanOutcome;
use std::{
    collections::{HashMap, HashSet},
    fs,
};

#[derive(Clone, Default)]
struct MountTable {
    map: HashMap<u64, String>,
}

pub fn run() -> ScanOutcome {
    let container_roots = collect_container_roots();
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let proc_entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(err) => return Err(format!("failed to read /proc: {err}")),
    };

    for entry in proc_entries.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };

        match scan_pid(pid, &container_roots) {
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

fn scan_pid(pid: u32, container_roots: &[String]) -> Result<Vec<String>, String> {
    let fdinfo_dir = format!("/proc/{pid}/fdinfo");
    let entries = match fs::read_dir(&fdinfo_dir) {
        Ok(entries) => entries,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(Vec::new());
            }
            return Err(format!("pid={pid} fdinfo: {err}"));
        }
    };

    let mut mount_table: Option<MountTable> = None;
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    let comm = read_trimmed(&format!("/proc/{pid}/comm")).unwrap_or_else(|| "?".to_string());
    let exe = read_exe(pid).unwrap_or_else(|| "unknown".to_string());
    let exe_issues = describe_exe(&exe);

    for entry in entries.flatten() {
        let fd_path = entry.path();
        let content = match fs::read_to_string(&fd_path) {
            Ok(c) => c,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    continue;
                }
                return Err(format!("pid={pid} fdinfo {}: {err}", fd_path.display()));
            }
        };

        if !content.contains("fanotify") {
            continue;
        }

        let mnt_ids = extract_mnt_ids(&content);
        if mnt_ids.is_empty() {
            continue;
        }

        if mount_table.is_none() {
            mount_table = Some(build_mount_table(pid)?);
        }

        for mnt_id in mnt_ids {
            if !seen.insert(mnt_id) {
                continue;
            }

            let mut issues = Vec::new();
            if !exe_issues.is_empty() {
                issues.extend(exe_issues.clone());
            }

            let mount_point = mount_table
                .as_ref()
                .and_then(|t| t.map.get(&mnt_id).cloned())
                .unwrap_or_else(|| "unknown".to_string());

            if mount_point == "/" {
                issues.push("watching_root".to_string());
            } else if mount_point == "/proc" {
                issues.push("watching_proc".to_string());
            } else if container_roots
                .iter()
                .any(|root| mount_point.starts_with(root))
            {
                issues.push("watching_container_root".to_string());
            }

            if mount_point == "unknown" {
                issues.push("mount_unresolved".to_string());
            }

            if issues.is_empty() {
                continue;
            }

            findings.push(format!(
                "pid={} comm={} exe={} mount={} issues={}",
                pid,
                comm.trim(),
                exe,
                mount_point,
                issues.join("|")
            ));
        }
    }

    Ok(findings)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_exe(pid: u32) -> Option<String> {
    let exe_link = format!("/proc/{pid}/exe");
    match fs::read_link(&exe_link) {
        Ok(link) => Some(link.display().to_string()),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                None
            } else {
                Some("unknown".to_string())
            }
        }
    }
}

fn describe_exe(exe: &str) -> Vec<String> {
    let mut issues = Vec::new();
    if exe.contains("(deleted)") {
        issues.push("exe_deleted".to_string());
    }
    if exe.starts_with("/tmp/") || exe.starts_with("/var/tmp/") || exe.starts_with("/dev/shm/") {
        issues.push("exe_temporary".to_string());
    }
    issues
}

fn extract_mnt_ids(content: &str) -> Vec<u64> {
    let mut ids = Vec::new();
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("fanotify mnt_id:") {
            if let Some(id) = rest.trim().parse::<u64>().ok() {
                ids.push(id);
            }
        }
    }
    ids
}

fn build_mount_table(pid: u32) -> Result<MountTable, String> {
    let path = format!("/proc/{pid}/mountinfo");
    let content = fs::read_to_string(&path)
        .map_err(|err| format!("pid={pid} mountinfo: failed to read {}: {err}", path))?;

    let mut map = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        if let Ok(id) = parts[0].parse::<u64>() {
            let mount_point = parts[4].to_string();
            map.insert(id, mount_point);
        }
    }

    Ok(MountTable { map })
}

fn collect_container_roots() -> Vec<String> {
    let mut roots = Vec::new();
    let inventory = collect_container_states(1024);
    for state in inventory.states {
        for mount in state.mounts {
            if mount.destination == "/" {
                if let Some(source) = mount.source {
                    roots.push(source);
                }
            }
        }
    }
    roots
}
