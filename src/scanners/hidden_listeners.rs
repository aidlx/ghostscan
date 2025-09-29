use crate::ScanOutcome;
use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::{Command, Stdio},
};

const BPF_LISTENER_ENTRY_LIMIT: usize = 65536;

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone)]
struct SocketKey {
    proto: String,
    local: String,
    remote: String,
}

struct NetlinkEntry {
    inode: Option<String>,
    pids: Vec<u32>,
}

#[derive(Default)]
struct BpfListenerRecord {
    sources: Vec<String>,
    state: Option<u32>,
}

#[derive(Default)]
struct BpfListenerSnapshot {
    entries: BTreeMap<SocketKey, BpfListenerRecord>,
    errors: Vec<String>,
}

impl BpfListenerRecord {
    fn new(source: &str, state: Option<u32>) -> Self {
        Self {
            sources: vec![source.to_string()],
            state,
        }
    }

    fn merge(&mut self, source: &str, state: Option<u32>) {
        if let Some(value) = state {
            if self.state.is_none() {
                self.state = Some(value);
            }
        }
        if !self.sources.iter().any(|existing| existing == source) {
            self.sources.push(source.to_string());
        }
    }
}

#[cfg(target_os = "linux")]
mod bpf_support {
    use super::{BpfListenerRecord, BpfListenerSnapshot, SocketKey, current_netns_inum};
    use libbpf_rs::{AsRawLibbpf, Iter, Link, MapFlags, ObjectBuilder};
    use std::io::Read;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr::{self, NonNull};

    const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hidden_listeners.bpf.o"));
    const MAP_NAME: &str = "ghostscan_listener_sockets";
    const TCP_PROG: &str = "ghostscan_iter_tcp";
    const UDP_PROG: &str = "ghostscan_iter_udp";
    const TCP_SOURCE: &str = "ghostscan_bpf_tcp_iter";
    const UDP_SOURCE: &str = "ghostscan_bpf_udp_iter";
    const FAMILY_INET: u8 = 2;
    const FAMILY_INET6: u8 = 10;
    const PROTO_TCP: u8 = 6;
    const PROTO_UDP: u8 = 17;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct BpfListenerKey {
        proto: u8,
        family: u8,
        port: u16,
        addr: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct BpfListenerValue {
        state: u32,
        netns_inum: u32,
    }

    pub(super) fn collect_listeners(entry_limit: usize) -> Result<BpfListenerSnapshot, String> {
        let mut snapshot = BpfListenerSnapshot::default();
        if entry_limit == 0 {
            return Err("entry_limit must be non-zero".to_string());
        }

        if let Err(err) = bump_memlock_limit() {
            snapshot.errors.push(err);
        }

        let netns = match current_netns_inum() {
            Ok(value) => value,
            Err(err) => {
                snapshot.errors.push(err);
                return Ok(snapshot);
            }
        };

        let mut builder = ObjectBuilder::default();
        builder.relaxed_maps(true);

        let mut obj = match builder
            .open_memory(BPF_OBJECT)
            .map_err(|err| format!("failed to open embedded hidden listener BPF: {err}"))?
            .load()
            .map_err(|err| format!("failed to load embedded hidden listener BPF: {err}"))
        {
            Ok(obj) => obj,
            Err(err) => {
                snapshot.errors.push(err);
                return Ok(snapshot);
            }
        };

        if let Err(err) = run_iter(&mut obj, TCP_PROG) {
            snapshot.errors.push(err);
        }
        if let Err(err) = run_iter(&mut obj, UDP_PROG) {
            snapshot.errors.push(err);
        }

        let map = match obj.map(MAP_NAME) {
            Some(map) => map,
            None => {
                snapshot
                    .errors
                    .push("embedded listener map missing".to_string());
                return Ok(snapshot);
            }
        };

        let key_size = mem::size_of::<BpfListenerKey>();
        let value_size = mem::size_of::<BpfListenerValue>();
        let mut processed = 0usize;

        for key_bytes in map.keys() {
            if processed >= entry_limit {
                snapshot
                    .errors
                    .push(format!("listener map truncated at {} entries", entry_limit));
                break;
            }

            if key_bytes.len() < key_size {
                continue;
            }

            processed += 1;

            let key = unsafe { ptr::read_unaligned(key_bytes.as_ptr() as *const BpfListenerKey) };

            let value = match map.lookup(&key_bytes, MapFlags::ANY) {
                Ok(Some(bytes)) if bytes.len() >= value_size => unsafe {
                    ptr::read_unaligned(bytes.as_ptr() as *const BpfListenerValue)
                },
                Ok(Some(_)) => {
                    snapshot.errors.push(format!(
                        "listener value truncated for proto {} port {}",
                        key.proto, key.port
                    ));
                    continue;
                }
                Ok(None) => {
                    snapshot.errors.push(format!(
                        "listener value missing for proto {} port {}",
                        key.proto, key.port
                    ));
                    continue;
                }
                Err(err) => {
                    snapshot
                        .errors
                        .push(format!("listener map lookup failed: {err}"));
                    continue;
                }
            };

            if value.netns_inum != netns {
                continue;
            }

            let (proto_name, source) = match key.proto {
                PROTO_TCP => ("tcp", TCP_SOURCE),
                PROTO_UDP => ("udp", UDP_SOURCE),
                _ => continue,
            };

            let (local_ip, remote_ip) = match key.family {
                FAMILY_INET => {
                    let mut raw = [0u8; 4];
                    raw.copy_from_slice(&key.addr[..4]);
                    (
                        IpAddr::V4(Ipv4Addr::from(raw)),
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    )
                }
                FAMILY_INET6 => {
                    let mut raw = [0u8; 16];
                    raw.copy_from_slice(&key.addr);
                    (
                        IpAddr::V6(Ipv6Addr::from(raw)),
                        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    )
                }
                _ => continue,
            };

            let local = super::format_endpoint(local_ip, key.port);
            let remote = super::format_endpoint(remote_ip, 0);

            let socket_key = SocketKey {
                proto: proto_name.to_string(),
                local,
                remote,
            };

            let record = snapshot
                .entries
                .entry(socket_key)
                .or_insert_with(|| BpfListenerRecord::new(source, Some(value.state)));
            record.merge(source, Some(value.state));
        }

        Ok(snapshot)
    }

    fn run_iter(obj: &mut libbpf_rs::Object, prog_name: &str) -> Result<(), String> {
        let mut prog = obj
            .prog_mut(prog_name)
            .ok_or_else(|| format!("embedded listener program '{}' missing", prog_name))?;
        let link = attach_iter(&mut prog)
            .map_err(|err| format!("failed to attach {}: {err}", prog_name))?;
        let mut iter = Iter::new(&link)
            .map_err(|err| format!("failed to create iterator for {}: {err}", prog_name))?;
        let mut drain = [0u8; 4096];
        while iter
            .read(&mut drain)
            .map_err(|err| format!("failed to drain iterator for {}: {err}", prog_name))?
            > 0
        {}
        drop(iter);
        drop(link);
        Ok(())
    }

    fn attach_iter(prog: &mut libbpf_rs::Program) -> Result<Link, libbpf_rs::Error> {
        unsafe {
            let prog_ptr = prog.as_libbpf_object();
            let mut link_info = libbpf_sys::bpf_iter_link_info::default();
            let attach_opts = libbpf_sys::bpf_iter_attach_opts {
                link_info: &mut link_info as *mut libbpf_sys::bpf_iter_link_info,
                link_info_len: mem::size_of::<libbpf_sys::bpf_iter_link_info>() as _,
                sz: mem::size_of::<libbpf_sys::bpf_iter_attach_opts>() as _,
                ..Default::default()
            };

            let raw = libbpf_sys::bpf_program__attach_iter(
                prog_ptr.as_ptr(),
                &attach_opts as *const libbpf_sys::bpf_iter_attach_opts,
            );
            if raw.is_null() {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EPERM);
                return Err(libbpf_rs::Error::from_raw_os_error(errno));
            }

            let err = libbpf_sys::libbpf_get_error(raw.cast());
            if err != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-err as i32));
            }

            let ptr = NonNull::new(raw)
                .ok_or_else(|| libbpf_rs::Error::from_raw_os_error(libc::EINVAL))?;
            Ok(Link::from_ptr(ptr))
        }
    }

    fn bump_memlock_limit() -> Result<(), String> {
        let rlimit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            Err(format!("failed to raise memlock rlimit: {err}"))
        } else {
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod bpf_support {
    use super::BpfListenerSnapshot;

    pub(super) fn collect_listeners(_entry_limit: usize) -> Result<BpfListenerSnapshot, String> {
        let mut snapshot = BpfListenerSnapshot::default();
        snapshot
            .errors
            .push("BPF listener collection not supported on this platform".to_string());
        Ok(snapshot)
    }
}

fn collect_bpf_listeners(entry_limit: usize) -> Result<BpfListenerSnapshot, String> {
    bpf_support::collect_listeners(entry_limit)
}

fn current_netns_inum() -> Result<u32, String> {
    let link = fs::read_link("/proc/self/ns/net")
        .map_err(|err| format!("failed to read /proc/self/ns/net: {err}"))?;
    let target = link.to_string_lossy();
    let start = target
        .find('[')
        .ok_or_else(|| format!("unexpected netns symlink target: {target}"))?;
    let end = target[start + 1..]
        .find(']')
        .map(|idx| start + 1 + idx)
        .ok_or_else(|| format!("unexpected netns symlink target: {target}"))?;
    let slice = &target[start + 1..end];
    let value = slice
        .parse::<u64>()
        .map_err(|err| format!("failed to parse netns inum from '{}': {err}", target))?;
    if value > u32::MAX as u64 {
        return Err(format!("netns inum {} exceeds u32 range", value));
    }
    Ok(value as u32)
}

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

    let mut errors = Vec::new();

    let bpf_snapshot = match collect_bpf_listeners(BPF_LISTENER_ENTRY_LIMIT) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            errors.push(err);
            BpfListenerSnapshot::default()
        }
    };

    errors.extend(bpf_snapshot.errors.iter().cloned());

    let mut netlink = BTreeMap::new();
    let mut proc = BTreeMap::new();

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
        if proc.contains_key(key) {
            continue;
        }

        let bpf_record = bpf_snapshot.entries.get(key);

        let mut segments = vec![
            format!("proto={}", key.proto),
            format!("laddr={}", key.local),
            format!("raddr={}", key.remote),
        ];

        let mut seen_by = vec!["netlink".to_string()];
        if let Some(record) = bpf_record {
            seen_by.push("bpf".to_string());
            segments.push(format!("bpf_sources={}", record.sources.join("|")));
            if let Some(state) = record.state {
                segments.push(format!("bpf_state={state}"));
            }
        }
        segments.push(format!("seen_by={}", seen_by.join("|")));

        let mut missing = vec!["proc".to_string()];
        if bpf_record.is_none() {
            missing.push("bpf".to_string());
        }
        segments.push(format!("missing={}", missing.join("|")));
        segments.push(format!(
            "inode={}",
            entry.inode.as_deref().unwrap_or("unknown")
        ));
        segments.push(format!("owner_pids={}", format_owner_pids(&entry.pids)));

        findings.push(segments.join(", "));
    }

    for (key, record) in &bpf_snapshot.entries {
        if netlink.contains_key(key) {
            continue;
        }

        let proc_seen = proc.contains_key(key);

        let mut segments = vec![
            format!("proto={}", key.proto),
            format!("laddr={}", key.local),
            format!("raddr={}", key.remote),
        ];

        let mut seen_by = vec!["bpf".to_string()];
        if proc_seen {
            seen_by.push("proc".to_string());
        }
        segments.push(format!("seen_by={}", seen_by.join("|")));

        let mut missing = vec!["netlink".to_string()];
        if !proc_seen {
            missing.push("proc".to_string());
        }
        segments.push(format!("missing={}", missing.join("|")));

        segments.push(format!("bpf_sources={}", record.sources.join("|")));
        if let Some(state) = record.state {
            segments.push(format!("bpf_state={state}"));
        }

        findings.push(segments.join(", "));
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

fn format_owner_pids(pids: &[u32]) -> String {
    if pids.is_empty() {
        "∅".to_string()
    } else {
        pids.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("|")
    }
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
