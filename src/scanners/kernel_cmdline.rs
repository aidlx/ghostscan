use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let content = fs::read_to_string("/proc/cmdline")
        .map_err(|err| format!("failed to read /proc/cmdline: {err}"))?;

    let mut findings = Vec::new();

    let cmdline = content.trim();
    if cmdline.contains("audit=0") {
        findings.push("flag=audit=0".to_string());
    }
    if cmdline.contains("lockdown=none") {
        findings.push("flag=lockdown=none".to_string());
    }
    if cmdline.contains("ima_appraise_tcb=0") {
        findings.push("flag=ima_appraise_tcb=0".to_string());
    }
    if let Some(lsm_idx) = cmdline.find("lsm=") {
        let tail = &cmdline[lsm_idx..];
        let value: String = tail
            .chars()
            .skip_while(|c| *c != '=')
            .skip(1)
            .take_while(|c| !c.is_whitespace())
            .collect();
        if !value.is_empty() {
            findings.push(format!("flag=lsm={}", value));
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        Ok(Some(findings.join(", ")))
    }
}
