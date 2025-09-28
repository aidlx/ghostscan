use super::container_utils::collect_container_states;
use crate::ScanOutcome;

const ALLOWED_PREFIXES: &[&str] = &[
    "/var/lib/containers",
    "/var/lib/docker",
    "/var/lib/oci",
    "/run/containers",
];

pub fn run() -> ScanOutcome {
    let inventory = collect_container_states(1024);
    let mut findings = Vec::new();
    let errors = inventory.errors;

    for state in inventory.states {
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

fn is_allowed(path: &str) -> bool {
    ALLOWED_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}
