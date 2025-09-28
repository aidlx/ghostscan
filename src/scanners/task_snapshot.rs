use serde_json::Value;
use std::{collections::HashMap, fs, process::Command};

#[derive(Debug, Default, Clone)]
pub struct BpfTaskSnapshot {
    pub tasks: HashMap<i32, BpfTaskRecord>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BpfTaskRecord {
    pub comm: Option<String>,
    pub sources: Vec<String>,
}

const MAP_NAME_HINTS: &[&str] = &["pid", "task", "proc"];
const MAP_TYPES: &[&str] = &["hash", "lru_hash", "percpu_hash", "lru_percpu_hash"];

pub fn collect_bpf_tasks(map_limit: usize, entry_limit: usize) -> Result<BpfTaskSnapshot, String> {
    if map_limit == 0 || entry_limit == 0 {
        return Err("map_limit and entry_limit must be non-zero".to_string());
    }

    let show = Command::new("bpftool")
        .args(["-j", "map", "show"])
        .output()
        .map_err(|err| format!("failed to execute bpftool map show: {err}"))?;

    if !show.status.success() {
        let stderr = String::from_utf8_lossy(&show.stderr);
        return Err(format!(
            "bpftool map show exited with {}: {}",
            show.status,
            stderr.trim()
        ));
    }

    let parsed: Value = serde_json::from_slice(&show.stdout)
        .map_err(|err| format!("failed to parse bpftool map show output: {err}"))?;
    let maps = parsed
        .as_array()
        .ok_or_else(|| "bpftool map show output was not an array".to_string())?;

    let mut snapshot = BpfTaskSnapshot::default();
    let mut processed = 0usize;

    for map in maps {
        if processed >= map_limit {
            break;
        }

        let Some(map_obj) = map.as_object() else {
            continue;
        };

        if let Some(error) = map_obj.get("error").and_then(Value::as_str) {
            return Err(format!("bpftool map show: {error}"));
        }

        let Some(map_id) = map_obj.get("id").and_then(Value::as_u64) else {
            continue;
        };

        let map_type = map_obj
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !MAP_TYPES.iter().any(|candidate| *candidate == map_type) {
            continue;
        }

        let key_size = map_obj.get("key_size").and_then(Value::as_u64).unwrap_or(0);
        if key_size != 4 && key_size != 8 {
            continue;
        }

        let name = map_obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_interesting_map(name, map_obj) {
            continue;
        }

        processed += 1;
        dump_map_entries(map_id, key_size as usize, entry_limit, name, &mut snapshot);
    }

    if snapshot.tasks.is_empty() && snapshot.errors.is_empty() {
        return Err("no candidate BPF PID maps discovered".to_string());
    }

    Ok(snapshot)
}

pub fn collect_proc_tasks() -> Result<HashMap<i32, String>, String> {
    let entries = fs::read_dir("/proc").map_err(|err| format!("failed to read /proc: {err}"))?;
    let mut tasks = HashMap::new();

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_err) => {
                // ignore transient inode races
                continue;
            }
        };

        let name = entry.file_name();
        let pid_str = match name.to_str() {
            Some(value) => value,
            None => continue,
        };

        let pid: i32 = match pid_str.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let comm_path = entry.path().join("comm");
        match fs::read_to_string(&comm_path) {
            Ok(comm) => {
                tasks.insert(pid, comm.trim().to_string());
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    continue;
                }
                // ignore short-lived tasks that exit between listing and read
            }
        }
    }

    if tasks.is_empty() {
        Err("no tasks enumerated via /proc".to_string())
    } else {
        Ok(tasks)
    }
}

fn is_interesting_map(name: &str, map_obj: &serde_json::Map<String, Value>) -> bool {
    let lowered = name.to_ascii_lowercase();
    if MAP_NAME_HINTS.iter().any(|hint| lowered.contains(hint)) {
        return true;
    }

    if let Some(btf_name) = map_obj
        .get("btf_key_type_name")
        .and_then(Value::as_str)
        .map(|v| v.to_ascii_lowercase())
    {
        if MAP_NAME_HINTS.iter().any(|hint| btf_name.contains(hint)) {
            return true;
        }
    }

    false
}

fn dump_map_entries(
    map_id: u64,
    key_size: usize,
    entry_limit: usize,
    map_name: &str,
    snapshot: &mut BpfTaskSnapshot,
) {
    let id_str = map_id.to_string();
    let dump = match Command::new("bpftool")
        .args(["-j", "map", "dump", "id", &id_str])
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            snapshot
                .errors
                .push(format!("failed to dump BPF map {}: {err}", map_name));
            return;
        }
    };

    if !dump.status.success() {
        let stderr = String::from_utf8_lossy(&dump.stderr);
        snapshot.errors.push(format!(
            "bpftool map dump id {} exited with {}: {}",
            map_id,
            dump.status,
            stderr.trim()
        ));
        return;
    }

    let parsed: Value = match serde_json::from_slice(&dump.stdout) {
        Ok(value) => value,
        Err(err) => {
            snapshot.errors.push(format!(
                "failed to parse dump for map {}: {}",
                map_name, err
            ));
            return;
        }
    };

    let entries = match parsed.as_array() {
        Some(entries) => entries,
        None => {
            snapshot
                .errors
                .push(format!("unexpected dump format for map {}", map_name));
            return;
        }
    };

    let label = format!("{}#{}", map_name, map_id);
    let mut processed = 0usize;

    for entry in entries {
        if processed >= entry_limit {
            snapshot.errors.push(format!(
                "map {} truncated at {} entries",
                map_name, entry_limit
            ));
            break;
        }
        processed += 1;

        let Some(pid) = extract_pid(entry, key_size) else {
            continue;
        };
        if pid <= 0 {
            continue;
        }

        let comm = extract_comm(entry);
        snapshot
            .tasks
            .entry(pid)
            .and_modify(|record| {
                if record.comm.is_none() && comm.is_some() {
                    record.comm = comm.clone();
                }
                if !record.sources.contains(&label) {
                    record.sources.push(label.clone());
                }
            })
            .or_insert_with(|| BpfTaskRecord {
                comm: comm.clone(),
                sources: vec![label.clone()],
            });
    }
}

fn extract_pid(entry: &Value, key_size: usize) -> Option<i32> {
    let key = entry.get("key")?;

    if let Some(obj) = key.as_object() {
        if let Some(pid) = obj.get("pid").and_then(Value::as_i64) {
            return Some(pid as i32);
        }
        if let Some(tgid) = obj.get("tgid").and_then(Value::as_i64) {
            return Some(tgid as i32);
        }
        if obj.len() == 1 {
            if let Some(value) = obj.values().next() {
                if let Some(pid) = value.as_i64() {
                    return Some(pid as i32);
                }
            }
        }
    }

    let bytes = to_bytes(key)?;
    if bytes.is_empty() {
        return None;
    }

    let mut buf = [0u8; 8];
    let take = bytes.len().min(key_size.min(buf.len()));
    buf[..take].copy_from_slice(&bytes[..take]);
    let pid = u64::from_le_bytes(buf) as u32;
    if pid == 0 { None } else { Some(pid as i32) }
}

fn extract_comm(entry: &Value) -> Option<String> {
    let value = entry.get("value")?;
    if let Some(obj) = value.as_object() {
        if let Some(comm) = obj.get("comm").and_then(Value::as_str) {
            return Some(comm.to_string());
        }
        if let Some(str_value) = obj.get("string").and_then(Value::as_str) {
            if !str_value.is_empty() {
                return Some(str_value.to_string());
            }
        }
        if let Some(value_str) = obj.get("value_str").and_then(Value::as_str) {
            if !value_str.is_empty() {
                return Some(value_str.to_string());
            }
        }
    }

    let bytes = to_bytes(value)?;
    ascii_from_bytes(&bytes)
}

fn to_bytes(value: &Value) -> Option<Vec<u8>> {
    if let Some(obj) = value.as_object() {
        if let Some(hex) = obj.get("hexdata").and_then(Value::as_str) {
            return parse_hex(hex);
        }
        if let Some(bytes) = obj.get("bytes") {
            if let Some(list) = bytes.as_array() {
                let mut result = Vec::with_capacity(list.len());
                for item in list {
                    if let Some(num) = item.as_u64() {
                        result.push((num & 0xFF) as u8);
                    } else if let Some(num) = item.as_i64() {
                        result.push((num & 0xFF) as u8);
                    } else if let Some(text) = item.as_str() {
                        if let Some(parsed) = parse_hex(text) {
                            result.extend(parsed);
                        }
                    }
                }
                return Some(result);
            }
            if let Some(text) = bytes.as_str() {
                return parse_hex(text);
            }
        }
        if let Some(num) = obj.get("value").and_then(Value::as_u64) {
            return Some(num.to_le_bytes().to_vec());
        }
        if obj.len() == 1 {
            if let Some(value) = obj.values().next() {
                return to_bytes(value);
            }
        }
    }

    if let Some(array) = value.as_array() {
        let mut result = Vec::with_capacity(array.len());
        for item in array {
            if let Some(num) = item.as_u64() {
                result.push((num & 0xFF) as u8);
            } else if let Some(num) = item.as_i64() {
                result.push((num & 0xFF) as u8);
            } else if let Some(text) = item.as_str() {
                if let Some(parsed) = parse_hex(text) {
                    result.extend(parsed);
                }
            }
        }
        return Some(result);
    }

    if let Some(text) = value.as_str() {
        return parse_hex(text);
    }

    if let Some(num) = value.as_u64() {
        return Some(num.to_le_bytes().to_vec());
    }
    if let Some(num) = value.as_i64() {
        return Some((num as u64).to_le_bytes().to_vec());
    }

    None
}

fn parse_hex(input: &str) -> Option<Vec<u8>> {
    let mut hex = input.trim().to_string();
    if hex.starts_with("0x") || hex.starts_with("0X") {
        hex = hex[2..].to_string();
    }
    hex.retain(|c| !c.is_whitespace() && c != ':' && c != ',');
    if hex.is_empty() {
        return None;
    }
    if hex.len() % 2 != 0 {
        hex.insert(0, '0');
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = chunk[0];
        let lo = chunk[1];
        let byte = match (from_hex(hi), from_hex(lo)) {
            (Some(h), Some(l)) => (h << 4) | l,
            _ => return None,
        };
        bytes.push(byte);
    }
    Some(bytes)
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn ascii_from_bytes(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    if !bytes[..end].iter().all(|b| b.is_ascii()) {
        return None;
    }
    String::from_utf8(bytes[..end].to_vec()).ok()
}
