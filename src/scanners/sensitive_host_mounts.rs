use super::container_utils::collect_container_states;
use crate::ScanOutcome;

const SENSITIVE_SOURCES: &[&str] = &[
    "/proc/kcore",
    "/sys/kernel/debug",
    "/dev/mem",
    "/proc/sysrq-trigger",
];

pub fn run() -> ScanOutcome {
    let states = match collect_container_states(1024) {
        Ok(states) => states,
        Err(err) => return Err(err),
    };

    let mut findings = Vec::new();

    for state in states {
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
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}
