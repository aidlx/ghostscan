use super::container_utils::collect_container_states;
use crate::ScanOutcome;

const ALLOWED_PREFIXES: &[&str] = &[
    "/var/lib/containers",
    "/var/lib/docker",
    "/var/lib/oci",
    "/run/containers",
];

pub fn run() -> ScanOutcome {
    let states = match collect_container_states(1024) {
        Ok(states) => states,
        Err(err) => return Err(err),
    };

    let mut findings = Vec::new();

    for state in states {
        for mount in &state.mounts {
            for option in &mount.options {
                if let Some(rest) = option.strip_prefix("lowerdir=") {
                    for dir in rest.split(':') {
                        if !is_allowed(dir) {
                            findings.push(format!(
                                "container_id={}, mount_point={}, lowerdir={}, anomaly=outside_storage_root",
                                state.id,
                                mount.destination,
                                dir
                            ));
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn is_allowed(path: &str) -> bool {
    ALLOWED_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}
