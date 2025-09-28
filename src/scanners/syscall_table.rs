use crate::ScanOutcome;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::PathBuf,
};

pub fn run() -> ScanOutcome {
    let mut addresses: Vec<Resolution> = Vec::new();
    let mut violations: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    match resolve_from_kallsyms() {
        Ok(Some(resolution)) => {
            if resolution.address == 0 {
                errors.push(format!(
                    "{} returned zero address (likely kptr_restrict)",
                    resolution.source
                ));
            } else {
                addresses.push(resolution);
            }
        }
        Ok(None) => {
            violations.push("source=/proc/kallsyms issue=missing_sys_call_table".to_string())
        }
        Err(err) => errors.push(format!("/proc/kallsyms: {err}")),
    }

    for candidate in resolve_from_system_map() {
        match candidate {
            Ok(resolution) => {
                if resolution.address == 0 {
                    errors.push(format!("{} returned zero address", resolution.source));
                } else {
                    addresses.push(resolution);
                }
            }
            Err(SourceError::Io { source, error }) => {
                errors.push(format!("{}: {}", source, error));
            }
            Err(SourceError::MissingSymbol { source }) => {
                violations.push(format!("source={} issue=missing_sys_call_table", source));
            }
        }
    }

    if !addresses.is_empty() {
        if let Some((mismatch_sources, values)) = detect_address_mismatch(&addresses) {
            violations.push(format!(
                "inconsistent_addresses sources={} addresses={}",
                mismatch_sources.join("|"),
                values
                    .iter()
                    .map(|addr| format!("0x{addr:016x}"))
                    .collect::<Vec<_>>()
                    .join("|")
            ));
        }
    }

    if violations.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Err(errors.join(", "))
        }
    } else {
        let mut message_parts = Vec::new();
        message_parts.push(violations.join("\n"));
        if !errors.is_empty() {
            message_parts.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(message_parts.join("\n")))
    }
}

#[derive(Clone)]
struct Resolution {
    source: String,
    address: u64,
}

enum SourceError {
    Io { source: String, error: io::Error },
    MissingSymbol { source: String },
}

fn resolve_from_kallsyms() -> io::Result<Option<Resolution>> {
    let file = File::open("/proc/kallsyms")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split_whitespace();
        let address_str = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        let _symbol_type = parts.next();
        let symbol = match parts.next() {
            Some(value) => value,
            None => continue,
        };

        if symbol == "sys_call_table" {
            let address = parse_hex(address_str).unwrap_or(0);
            return Ok(Some(Resolution {
                source: "/proc/kallsyms".to_string(),
                address,
            }));
        }
    }

    Ok(None)
}

fn resolve_from_system_map() -> Vec<Result<Resolution, SourceError>> {
    let mut results = Vec::new();
    let kernel = match fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(value) => value.trim().to_string(),
        Err(err) => {
            return vec![Err(SourceError::Io {
                source: "/proc/sys/kernel/osrelease".to_string(),
                error: err,
            })];
        }
    };
    let candidates = [
        format!("/usr/lib/modules/{kernel}/System.map"),
        format!("/usr/lib/modules/{kernel}/build/System.map"),
        format!("/lib/modules/{kernel}/System.map"),
        format!("/lib/modules/{kernel}/build/System.map"),
        format!("/boot/System.map-{kernel}"),
        "/boot/System.map".to_string(),
    ];

    for candidate in candidates {
        let path = PathBuf::from(&candidate);
        match File::open(&path) {
            Ok(file) => match find_symbol_in_system_map(file, "sys_call_table") {
                Ok(Some(address)) => results.push(Ok(Resolution {
                    source: format!("System.map({})", path.display()),
                    address,
                })),
                Ok(None) => results.push(Err(SourceError::MissingSymbol {
                    source: format!("System.map({})", path.display()),
                })),
                Err(err) => results.push(Err(SourceError::Io {
                    source: format!("System.map({})", path.display()),
                    error: err,
                })),
            },
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    results.push(Err(SourceError::Io {
                        source: format!("System.map({})", path.display()),
                        error: err,
                    }));
                }
            }
        }
    }

    results
}

fn find_symbol_in_system_map(file: File, target: &str) -> io::Result<Option<u64>> {
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split_whitespace();
        let address_str = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        let _symbol_type = parts.next();
        let symbol = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        if symbol == target {
            let address = parse_hex(address_str).unwrap_or(0);
            return Ok(Some(address));
        }
    }
    Ok(None)
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value, 16).ok()
}

fn detect_address_mismatch(resolutions: &[Resolution]) -> Option<(Vec<String>, Vec<u64>)> {
    let mut unique_addresses: Vec<(String, u64)> = Vec::new();

    for resolution in resolutions {
        if unique_addresses
            .iter()
            .any(|(_, addr)| *addr == resolution.address)
        {
            continue;
        }
        unique_addresses.push((resolution.source.clone(), resolution.address));
    }

    if unique_addresses.len() > 1 {
        let (sources, values): (Vec<_>, Vec<_>) = unique_addresses.into_iter().unzip();
        Some((sources, values))
    } else {
        None
    }
}
