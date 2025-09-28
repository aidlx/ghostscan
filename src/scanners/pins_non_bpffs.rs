use crate::ScanOutcome;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub fn run() -> ScanOutcome {
    if Command::new("bpftool")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Err("bpftool not available to inspect pinned objects".to_string());
    }

    let mounts = match parse_mountinfo() {
        Ok(mut list) => {
            list.sort_by_key(|entry| std::cmp::Reverse(entry.mount_point.components().count()));
            list
        }
        Err(err) => return Err(format!("failed to parse /proc/self/mountinfo: {err}")),
    };

    let mut pins = Vec::new();
    let mut errors = Vec::new();

    match collect_pins(["-j", "prog", "show"], "prog") {
        Ok(mut list) => pins.append(&mut list),
        Err(err) => errors.push(format!("prog: {err}")),
    }

    match collect_pins(["-j", "map", "show"], "map") {
        Ok(mut list) => pins.append(&mut list),
        Err(err) => errors.push(format!("map: {err}")),
    }

    match collect_pins(["-j", "link", "show"], "link") {
        Ok(mut list) => pins.append(&mut list),
        Err(err) => errors.push(format!("link: {err}")),
    }

    let mut findings = Vec::new();

    for pin in pins {
        let path = Path::new(&pin.path);
        let mount_type = mount_type_for(path, &mounts).unwrap_or("unknown");
        if mount_type != "bpf" {
            findings.push(format!(
                "pinned_path={}, obj_type={}, id={}, mount_fstype={}",
                pin.path, pin.obj_type, pin.id, mount_type
            ));
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

struct PinRecord {
    obj_type: &'static str,
    id: String,
    path: String,
}

fn collect_pins<const N: usize>(
    args: [&str; N],
    obj_type: &'static str,
) -> Result<Vec<PinRecord>, String> {
    let output = Command::new("bpftool")
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute bpftool {obj_type} show: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "bpftool {obj_type} show exited with {}",
            output.status
        ));
    }

    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse bpftool {obj_type} output: {err}"))?;

    let mut records = Vec::new();

    if let Some(array) = value.as_array() {
        for entry in array {
            let id = entry
                .get("id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            for path in extract_pin_paths(entry) {
                records.push(PinRecord {
                    obj_type,
                    id: id.clone(),
                    path,
                });
            }
        }
    }

    Ok(records)
}

fn extract_pin_paths(value: &Value) -> BTreeSet<String> {
    let mut set = BTreeSet::new();

    if let Some(pinned) = value.get("pinned") {
        collect_paths(pinned, &mut set);
    }

    if let Some(pins) = value.get("pins") {
        collect_paths(pins, &mut set);
    }

    set
}

fn collect_paths(value: &Value, set: &mut BTreeSet<String>) {
    match value {
        Value::String(s) => {
            if !s.is_empty() {
                set.insert(s.to_string());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_paths(item, set);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_paths(item, set);
            }
        }
        _ => {}
    }
}

struct MountEntry {
    mount_point: PathBuf,
    fstype: String,
}

fn parse_mountinfo() -> std::io::Result<Vec<MountEntry>> {
    let content = fs::read_to_string("/proc/self/mountinfo")?;
    let mut mounts = Vec::new();

    for line in content.lines() {
        if let Some((pre, post)) = line.split_once(" - ") {
            let mut post_fields = post.split_whitespace();
            let fstype = post_fields.next().unwrap_or("").to_string();

            let fields: Vec<&str> = pre.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let mount_point = decode_mount_field(fields[4]);
            mounts.push(MountEntry {
                mount_point: PathBuf::from(mount_point),
                fstype,
            });
        }
    }

    Ok(mounts)
}

fn decode_mount_field(field: &str) -> String {
    let mut result = String::new();
    let mut chars = field.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let (Some(a), Some(b), Some(c)) = (chars.next(), chars.next(), chars.next()) {
                let code = [a, b, c];
                let decoded = match &code {
                    ['0', '4', '0'] => ' ',
                    ['0', '1', '1'] => '\t',
                    ['0', '1', '2'] => '\n',
                    ['0', '1', '3'] => '\r',
                    ['0', '1', '4'] => 0x0c as char,
                    ['0', '1', '5'] => 0x0b as char,
                    ['0', '1', '6'] => 0x0e as char,
                    ['0', '1', '7'] => 0x0f as char,
                    ['0', '1', '0'] => 0x08 as char,
                    ['1', '3', '4'] => '\\',
                    _ => {
                        result.push('\\');
                        result.push(a);
                        result.push(b);
                        result.push(c);
                        continue;
                    }
                };
                result.push(decoded);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn mount_type_for<'a>(path: &Path, mounts: &'a [MountEntry]) -> Option<&'a str> {
    for entry in mounts {
        if path.starts_with(&entry.mount_point) {
            return Some(entry.fstype.as_str());
        }
    }
    None
}
