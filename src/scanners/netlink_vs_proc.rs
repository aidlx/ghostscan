use crate::ScanOutcome;
use std::{
    collections::{BTreeMap, BTreeSet},
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
        return Err("ss not available to query sockets".to_string());
    }

    let mut netlink_map = BTreeMap::new();
    let mut proc_map = BTreeMap::new();
    let mut errors = Vec::new();

    for (flag, proto) in [("-t", "tcp"), ("-u", "udp")] {
        match collect_ss(flag, proto) {
            Ok(map) => netlink_map.extend(map),
            Err(err) => errors.push(err),
        }
        match collect_proc(proto) {
            Ok(map) => proc_map.extend(map),
            Err(err) => errors.push(err),
        }
    }

    let mut findings = Vec::new();

    for (key, entry) in &netlink_map {
        if !proc_map.contains_key(key) {
            let inode = entry.inode.clone().unwrap_or_else(|| "unknown".to_string());
            let owners = if entry.pids.is_empty() {
                "∅".to_string()
            } else {
                entry
                    .pids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("|")
            };
            findings.push(format!(
                "from=netlink_only, proto={}, laddr={}, raddr={}, inode={}, owner_pids={}",
                key.proto, key.local, key.remote, inode, owners
            ));
        }
    }

    for (key, entry) in &proc_map {
        if !netlink_map.contains_key(key) {
            findings.push(format!(
                "from=proc_only, proto={}, laddr={}, raddr={}, inode={}, owner_pids=unknown",
                key.proto, key.local, key.remote, entry.inode
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

fn collect_ss(flag: &str, proto: &str) -> Result<BTreeMap<SocketKey, NetlinkEntry>, String> {
    let output = Command::new("ss")
        .args(["-H", "-a", "-n", "-p", "-i", flag])
        .output()
        .map_err(|err| format!("failed to execute ss {}: {err}", flag))?;

    if !output.status.success() {
        return Err(format!("ss {} exited with {}", flag, output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = BTreeMap::new();

    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 5 {
            continue;
        }
        let local = match normalize_ss_endpoint(tokens[3]) {
            Some(value) => value,
            None => continue,
        };
        let remote = match normalize_ss_endpoint(tokens[4]) {
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
    for segment in line.split_whitespace() {
        if let Some(rest) = segment.strip_prefix("ino:") {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    if let Some(pos) = line.find("ino:") {
        let tail = &line[pos + 4..];
        let inode: String = tail.chars().take_while(|c| !c.is_whitespace()).collect();
        if !inode.is_empty() {
            return Some(inode);
        }
    }
    None
}

fn extract_pids(line: &str) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let mut remaining = line;
    while let Some(idx) = remaining.find("pid=") {
        let tail = &remaining[idx + 4..];
        let pid_str: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = pid_str.parse::<u32>() {
            set.insert(pid);
        }
        remaining = &tail[pid_str.len()..];
    }
    set
}

fn normalize_ss_endpoint(raw: &str) -> Option<String> {
    if raw == "*" {
        return Some("0.0.0.0:0".to_string());
    }

    let (addr_part, port_part) = if raw.starts_with('[') {
        let end = raw.rfind(']')?;
        let addr = &raw[1..end];
        let port = raw.get(end + 2..)?;
        (addr, port)
    } else if let Some(idx) = raw.rfind(':') {
        let addr = &raw[..idx];
        let port = &raw[idx + 1..];
        (addr, port)
    } else {
        return None;
    };

    let addr = match addr_part {
        "*" => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "::" => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        other => other
            .parse::<IpAddr>()
            .unwrap_or_else(|_| IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    };

    let port = if port_part == "*" {
        0
    } else {
        port_part.parse::<u16>().unwrap_or(0)
    };

    Some(format_endpoint(addr, port))
}

fn collect_proc(proto: &str) -> Result<BTreeMap<SocketKey, ProcEntry>, String> {
    let mut map = BTreeMap::new();
    let files = [
        format!("/proc/net/{proto}"),
        format!("/proc/net/{}6", proto),
    ];

    for path in files {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };

        let is_ipv6 = path.ends_with('6');
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            let local = match parse_proc_endpoint(parts[1], is_ipv6) {
                Some(value) => value,
                None => continue,
            };
            let remote = match parse_proc_endpoint(parts[2], is_ipv6) {
                Some(value) => value,
                None => continue,
            };
            let inode = parts[9].to_string();

            let key = SocketKey {
                proto: proto.to_string(),
                local,
                remote,
            };
            map.insert(key, ProcEntry { inode });
        }
    }

    Ok(map)
}

fn parse_proc_endpoint(endpoint: &str, ipv6: bool) -> Option<String> {
    let mut parts = endpoint.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if ipv6 {
        let addr = parse_ipv6(addr_hex)?;
        Some(format_endpoint(IpAddr::V6(addr), port))
    } else {
        let addr = parse_ipv4(addr_hex)?;
        Some(format_endpoint(IpAddr::V4(addr), port))
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
    pids: BTreeSet<u32>,
}

struct ProcEntry {
    inode: String,
}
