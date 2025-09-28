use crate::ScanOutcome;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{self, BufRead, BufReader},
};

pub fn run() -> ScanOutcome {
    const SOURCES: [(&str, fn() -> io::Result<HashSet<String>>); 3] = [
        ("proc_modules", collect_proc_modules),
        ("sysfs", collect_sysfs_modules),
        ("kallsyms", collect_kallsyms_modules),
    ];

    let mut collections: Vec<(&str, HashSet<String>)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (name, collector) in SOURCES {
        match collector() {
            Ok(set) => collections.push((name, set)),
            Err(err) => errors.push(format!("{name}: {err}")),
        }
    }

    if collections.is_empty() {
        return Err(format!(
            "failed to collect module lists: {}",
            errors.join("; ")
        ));
    }

    let mut presence: HashMap<String, HashSet<&str>> = HashMap::new();
    for (source, modules) in &collections {
        for module in modules {
            presence.entry(module.clone()).or_default().insert(*source);
        }
    }

    let sources: Vec<&str> = collections.iter().map(|(name, _)| *name).collect();
    let mut findings: Vec<String> = Vec::new();

    for (module, seen_in) in presence {
        if seen_in.len() < sources.len() {
            if seen_in.len() == 1 && seen_in.contains("sysfs") {
                continue;
            }

            let mut missing: Vec<&str> = sources
                .iter()
                .copied()
                .filter(|name| !seen_in.contains(name))
                .collect();
            missing.sort();

            findings.push(format!("{module} missing_in={}", missing.join(",")));
        }
    }

    findings.sort();

    let mut message_parts = Vec::new();
    if !findings.is_empty() {
        message_parts.push(findings.join("\n"));
    }

    if !errors.is_empty() {
        message_parts.push(format!("collection_errors={}", errors.join(", ")));
    }

    if message_parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(message_parts.join("\n")))
    }
}

fn collect_proc_modules() -> io::Result<HashSet<String>> {
    let content = fs::read_to_string("/proc/modules")?;
    let mut modules = HashSet::new();

    for line in content.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if !name.is_empty() {
                modules.insert(name.to_string());
            }
        }
    }

    Ok(modules)
}

fn collect_sysfs_modules() -> io::Result<HashSet<String>> {
    let mut modules = HashSet::new();
    for entry in fs::read_dir("/sys/module")? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            if !name.is_empty() {
                modules.insert(name);
            }
        }
    }
    Ok(modules)
}

fn collect_kallsyms_modules() -> io::Result<HashSet<String>> {
    let file = File::open("/proc/kallsyms")?;
    let reader = BufReader::new(file);
    let mut modules = HashSet::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(module) = extract_module_name(&line) {
            modules.insert(module);
        }
    }

    Ok(modules)
}

fn extract_module_name(line: &str) -> Option<String> {
    let start = line.rfind('[')?;
    let end = line.rfind(']')?;
    if end + 1 != line.len() || end < start {
        return None;
    }
    let module = &line[start + 1..end];
    if module.is_empty() {
        None
    } else {
        Some(module.to_string())
    }
}
