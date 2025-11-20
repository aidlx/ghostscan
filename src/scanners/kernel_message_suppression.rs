use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let restrict = fs::read_to_string("/proc/sys/kernel/dmesg_restrict")
        .map_err(|err| format!("failed to read dmesg_restrict: {err}"))?
        .trim()
        .to_string();
    let printk = fs::read_to_string("/proc/sys/kernel/printk")
        .map_err(|err| format!("failed to read printk levels: {err}"))?
        .trim()
        .to_string();

    let mut findings = Vec::new();
    if restrict != "1" {
        findings.push("dmesg_restrict!=1".to_string());
    }

    let levels: Vec<&str> = printk.split_whitespace().collect();
    if let Some(console) = levels.get(0) {
        if let Ok(level) = console.parse::<i32>() {
            // Lower console loglevels drop more messages, so flag suppressed consoles.
            if level < 7 {
                findings.push("printk_console_level_silenced=true".to_string());
            }
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        Ok(Some(findings.join(", ")))
    }
}
