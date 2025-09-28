use crate::ScanOutcome;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub fn run() -> ScanOutcome {
    let mut inode_to_socket = BTreeMap::new();

    for path in [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                if let Some(inode) = line.split_whitespace().nth(9) {
                    inode_to_socket.insert(inode.to_string(), path.to_string());
                }
            }
        }
    }

    let mut inode_to_owners: BTreeMap<String, BTreeSet<i32>> = BTreeMap::new();

    if let Err(err) = collect_owners("/proc", &mut inode_to_owners) {
        return Err(format!("failed to enumerate fd owners: {err}"));
    }

    let mut findings = Vec::new();

    for (inode, source) in inode_to_socket {
        if inode == "0" {
            continue;
        }
        if !inode_to_owners.contains_key(&inode) {
            findings.push(format!(
                "proto_source={}, inode={}, owner_pids=∅",
                source, inode
            ));
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn collect_owners(dir: &str, map: &mut BTreeMap<String, BTreeSet<i32>>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|err| format!("failed to read {dir}: {err}"))? {
        let entry = entry.map_err(|err| format!("failed to iterate {dir}: {err}"))?;
        let file_type = entry
            .file_type()
            .map_err(|err| format!("failed to stat {}: {err}", entry.path().display()))?;
        if file_type.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(pid) = name.parse::<i32>() {
                collect_pid(pid, &entry.path(), map)?;
            }
        }
    }
    Ok(())
}

fn collect_pid(
    pid: i32,
    proc_path: &Path,
    map: &mut BTreeMap<String, BTreeSet<i32>>,
) -> Result<(), String> {
    let fd_path = proc_path.join("fd");
    let entries = match fs::read_dir(&fd_path) {
        Ok(entries) => entries,
        Err(err) => match err.raw_os_error() {
            Some(13) | Some(2) => return Ok(()),
            _ => return Err(format!("failed to read {}: {err}", fd_path.display())),
        },
    };

    for entry in entries.flatten() {
        if let Ok(target) = fs::read_link(entry.path()) {
            if let Some(inode) = target.to_string_lossy().strip_prefix("socket:[") {
                if let Some(inode) = inode.strip_suffix(']') {
                    map.entry(inode.to_string()).or_default().insert(pid);
                }
            }
        }
    }

    Ok(())
}
