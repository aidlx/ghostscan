use crate::ScanOutcome;
use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::{Command, Stdio},
};

pub fn run() -> ScanOutcome {
    if Command::new("ss")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Err("ss not available to query listeners".to_string());
    }

    let mut netlink = BTreeMap::new();
    let mut proc = BTreeMap::new();
    let mut errors = Vec::new();

    for (flags, proto) in [(["-l", "-t"], "tcp"), (["-l", "-u"], "udp")] {
        match collect_ss(&flags, proto) {
            Ok(map) => netlink.extend(map),
            Err(err) => errors.push(err),
        }

        match collect_proc(proto) {
            Ok(map) => proc.extend(map),
            Err(err) => errors.push(err),
        }
    }

    let mut findings = Vec::new();

    for (key, entry) in &netlink {
        if !proc.contains_key(key) {
            findings.push(format!(
                "proto={}, laddr={}, raddr={}, from=netlink_only, inode={}, owner_pids={}",
                key.proto,
                key.local,
                key.remote,
                entry.inode.as_deref().unwrap_or("unknown"),
                if entry.pids.is_empty() {
                    "∅".to_string()
                } else {
                    entry
                        .pids
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("|")
                }
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

fn collect_ss(flags: &[&str], proto: &str) -> Result<BTreeMap<SocketKey, NetlinkEntry>, String> {
    let mut args = vec!["-H", "-n", "-a", "-p"];
    args.extend_from_slice(flags);
    let output = Command::new("ss")
        .args(&args)
        .output()
        .map_err(|err| format!("failed to execute ss {}: {err}", flags.join("")))?;

    if !output.status.success() {
        return Err(format!(
            "ss {} exited with {}",
            flags.join(""),
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = BTreeMap::new();

    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 5 {
            continue;
        }
        let local = match normalize_endpoint(tokens[3]) {
            Some(value) => value,
            None => continue,
        };
        let remote = match normalize_endpoint(tokens[4]) {
            Some(value) => value,
            None => continue,
        };

        let key = SocketKey {
            proto: proto.to_string(),
            local,
            remote,
        };

        let inode = extract_inode(line);
        let pids = extract_pids(line);
        map.insert(key, NetlinkEntry { inode, pids });
    }

    Ok(map)
}

fn extract_inode(line: &str) -> Option<String> {
    line.split_whitespace()
        .find_map(|segment| segment.strip_prefix("ino:"))
        .map(|inode| inode.to_string())
}

fn extract_pids(line: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut remaining = line;
    while let Some(idx) = remaining.find("pid=") {
        let tail = &remaining[idx + 4..];
        let pid_str: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = pid_str.parse::<u32>() {
            pids.push(pid);
        }
        remaining = &tail[pid_str.len()..];
    }
    pids
}

fn normalize_endpoint(raw: &str) -> Option<String> {
    if raw == "*" {
        return Some("0.0.0.0:0".to_string());
    }

    if raw.starts_with('[') {
        let end = raw.rfind(']')?;
        let addr = &raw[1..end];
        let port = raw.get(end + 2..).unwrap_or("0");
        let port = port.parse::<u16>().unwrap_or(0);
        let ip = addr.parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED);
        return Some(format!("[{}]:{}", ip, port));
    }

    if let Some(idx) = raw.rfind(':') {
        let addr = &raw[..idx];
        let port = raw[idx + 1..].parse::<u16>().unwrap_or(0);
        let ip = addr
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        return Some(format_endpoint(ip, port));
    }

    None
}

fn collect_proc(proto: &str) -> Result<BTreeMap<SocketKey, ()>, String> {
    let mut map = BTreeMap::new();
    let files = [
        format!("/proc/net/{proto}"),
        format!("/proc/net/{}6", proto),
    ];

    for path in files {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let ipv6 = path.ends_with('6');
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let state = fields[3];
            if proto == "tcp" && state != "0A" {
                continue;
            }

            let local = match parse_proc_endpoint(fields[1], ipv6) {
                Some(value) => value,
                None => continue,
            };
            let remote = match parse_proc_endpoint(fields[2], ipv6) {
                Some(value) => value,
                None => continue,
            };

            map.insert(
                SocketKey {
                    proto: proto.to_string(),
                    local,
                    remote,
                },
                (),
            );
        }
    }

    Ok(map)
}

fn parse_proc_endpoint(raw: &str, ipv6: bool) -> Option<String> {
    let mut parts = raw.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if ipv6 {
        let ip = parse_ipv6(addr_hex)?;
        Some(format_endpoint(IpAddr::V6(ip), port))
    } else {
        let ip = parse_ipv4(addr_hex)?;
        Some(format_endpoint(IpAddr::V4(ip), port))
    }
}

fn parse_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let value = std::str::from_utf8(chunk).ok()?;
        bytes[i] = u8::from_str_radix(value, 16).ok()?;
    }
    bytes.reverse();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let value = std::str::from_utf8(chunk).ok()?;
        bytes[i] = u8::from_str_radix(value, 16).ok()?;
    }
    for chunk in bytes.chunks_mut(4) {
        chunk.reverse();
    }
    Some(Ipv6Addr::from(bytes))
}

fn format_endpoint(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(v4) => format!("{}:{}", v4, port),
        IpAddr::V6(v6) => format!("[{}]:{}", v6, port),
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
struct SocketKey {
    proto: String,
    local: String,
    remote: String,
}

struct NetlinkEntry {
    inode: Option<String>,
    pids: Vec<u32>,
}
