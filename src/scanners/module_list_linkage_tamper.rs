use crate::ScanOutcome;
use std::{collections::BTreeSet, fs, io};

pub fn run() -> ScanOutcome {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let sys_modules = match read_sys_modules() {
        Ok(set) => set,
        Err(err) => {
            return Err(format!("failed to read /sys/module: {err}"));
        }
    };

    let proc_modules = match read_proc_modules() {
        Ok(list) => list,
        Err(err) => {
            errors.push(format!("/proc/modules: {err}"));
            Vec::new()
        }
    };

    for module in &proc_modules {
        if !sys_modules.contains(module) {
            findings.push(format!(
                "module_name={}, this_ptr=unknown, prev_ptr=unknown, next_ptr=unknown, anomaly=null_gap",
                module
            ));
        }
    }

    for module in &sys_modules {
        let holders_path = format!("/sys/module/{}/holders", module);
        match fs::read_dir(&holders_path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let holder = entry.file_name().to_string_lossy().to_string();
                    if holder == *module {
                        findings.push(format!(
                            "module_name={}, this_ptr=unknown, prev_ptr=unknown, next_ptr=unknown, anomaly=self_loop",
                            module
                        ));
                        break;
                    }
                }
            }
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    errors.push(format!("{}: {}", holders_path, err));
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

fn read_sys_modules() -> io::Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    for entry in fs::read_dir("/sys/module")? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            set.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(set)
}

fn read_proc_modules() -> io::Result<Vec<String>> {
    let content = fs::read_to_string("/proc/modules")?;
    let mut modules = Vec::new();
    for line in content.lines() {
        if let Some(name) = line.split_whitespace().next() {
            modules.push(name.to_string());
        }
    }
    Ok(modules)
}
