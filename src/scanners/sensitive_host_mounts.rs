use super::container_utils::collect_container_states;
use crate::ScanOutcome;

const SENSITIVE_SOURCES: &[&str] = &[
    "/proc/kcore",
    "/sys/kernel/debug",
    "/dev/mem",
    "/proc/sysrq-trigger",
];

pub fn run() -> ScanOutcome {
    let inventory = collect_container_states(1024);
    let mut findings = Vec::new();
    let errors = inventory.errors;

    for state in inventory.states {
        for mount in &state.mounts {
            if let Some(source) = &mount.source {
                for sensitive in SENSITIVE_SOURCES {
                    if source.starts_with(sensitive) {
                        findings.push(format!(
                            "container_id={}, mount_point={}, source={}, exposes={}",
                            state.id, mount.destination, source, sensitive
                        ));
                        break;
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
