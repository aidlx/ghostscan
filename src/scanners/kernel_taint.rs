use crate::ScanOutcome;
use std::{
    collections::{HashMap, HashSet},
    fs, io,
};

pub fn run() -> ScanOutcome {
    let raw_taint = fs::read_to_string("/proc/sys/kernel/tainted")
        .map_err(|err| format!("failed to read /proc/sys/kernel/tainted: {err}"))?;

    let taint_value = raw_taint
        .trim()
        .parse::<u64>()
        .map_err(|err| format!("failed to parse tainted value '{raw_taint}': {err}"))?;

    if taint_value == 0 {
        return Ok(None);
    }

    let module_taints = collect_module_taint_letters()
        .map_err(|err| format!("failed to collect module taints: {err}"))?;

    let mut active_flags = Vec::new();
    let mut missing_module_flags = Vec::new();

    for flag in TAINT_FLAGS {
        if (taint_value & (1u64 << flag.bit)) != 0 {
            active_flags.push(flag);
            if flag.module_related && !module_taints.contains_key(&flag.letter) {
                missing_module_flags.push(flag);
            }
        }
    }

    if missing_module_flags.is_empty() {
        return Ok(None);
    }

    let active_letters: String = active_flags.iter().map(|flag| flag.letter).collect();
    let missing_descriptions: Vec<String> = missing_module_flags
        .iter()
        .map(|flag| format!("{} ({})", flag.letter, flag.description))
        .collect();

    let mut message = format!(
        "tainted={} active_flags={}",
        taint_value,
        if active_letters.is_empty() {
            "none"
        } else {
            active_letters.as_str()
        }
    );

    message.push_str(" missing_module_flags=");
    message.push_str(&missing_descriptions.join(", "));

    if !module_taints.is_empty() {
        let mut visible: Vec<String> = module_taints
            .iter()
            .map(|(letter, modules)| {
                let mut modules = modules.clone();
                modules.sort();
                format!("{} -> {}", letter, modules.join("|"))
            })
            .collect();
        visible.sort();
        message.push_str(" visible=");
        message.push_str(&visible.join("; "));
    }

    Ok(Some(message))
}

fn collect_module_taint_letters() -> io::Result<HashMap<char, Vec<String>>> {
    let mut map: HashMap<char, HashSet<String>> = HashMap::new();

    for entry in fs::read_dir("/sys/module")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let taint_path = entry.path().join("taint");
        if let Ok(content) = fs::read_to_string(&taint_path) {
            for ch in content.trim().chars() {
                if ch.is_ascii_alphabetic() {
                    map.entry(ch).or_default().insert(name.clone());
                }
            }
        }
    }

    let modules = fs::read_to_string("/proc/modules")?;
    for line in modules.lines() {
        let module_name = line.split_whitespace().next().unwrap_or_default();
        if module_name.is_empty() {
            continue;
        }

        if let Some(start) = line.find('(') {
            if let Some(end_offset) = line[start + 1..].find(')') {
                let letters = &line[start + 1..start + 1 + end_offset];
                for ch in letters.chars() {
                    if ch.is_ascii_alphabetic() {
                        map.entry(ch).or_default().insert(module_name.to_string());
                    }
                }
            }
        }
    }

    let mut result: HashMap<char, Vec<String>> = HashMap::new();
    for (letter, modules) in map {
        let mut names: Vec<String> = modules.into_iter().collect();
        names.sort();
        result.insert(letter, names);
    }

    Ok(result)
}

#[derive(Clone, Copy)]
struct TaintFlag {
    bit: u32,
    letter: char,
    description: &'static str,
    module_related: bool,
}

const TAINT_FLAGS: &[TaintFlag] = &[
    TaintFlag {
        bit: 0,
        letter: 'P',
        description: "proprietary module was loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 1,
        letter: 'F',
        description: "module was force-loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 2,
        letter: 'S',
        description: "SMP with unsupported hardware",
        module_related: false,
    },
    TaintFlag {
        bit: 3,
        letter: 'R',
        description: "module was forcibly removed",
        module_related: true,
    },
    TaintFlag {
        bit: 4,
        letter: 'M',
        description: "machine check occurred",
        module_related: false,
    },
    TaintFlag {
        bit: 5,
        letter: 'B',
        description: "kernel detected bad page",
        module_related: false,
    },
    TaintFlag {
        bit: 6,
        letter: 'U',
        description: "user forced taint",
        module_related: false,
    },
    TaintFlag {
        bit: 7,
        letter: 'D',
        description: "kernel oops or BUG",
        module_related: false,
    },
    TaintFlag {
        bit: 8,
        letter: 'A',
        description: "ACPI table override",
        module_related: false,
    },
    TaintFlag {
        bit: 9,
        letter: 'W',
        description: "kernel issued warning",
        module_related: false,
    },
    TaintFlag {
        bit: 10,
        letter: 'C',
        description: "staging driver loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 11,
        letter: 'I',
        description: "firmware workaround in effect",
        module_related: false,
    },
    TaintFlag {
        bit: 12,
        letter: 'O',
        description: "out-of-tree module loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 13,
        letter: 'E',
        description: "unsigned module loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 14,
        letter: 'L',
        description: "soft lockup or similar condition",
        module_related: false,
    },
    TaintFlag {
        bit: 15,
        letter: 'K',
        description: "livepatch applied",
        module_related: false,
    },
    TaintFlag {
        bit: 16,
        letter: 'X',
        description: "auxiliary taint flag",
        module_related: false,
    },
    TaintFlag {
        bit: 17,
        letter: 'T',
        description: "test kernel or test taint",
        module_related: false,
    },
];
