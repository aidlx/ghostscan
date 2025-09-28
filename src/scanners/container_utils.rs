use serde::Deserialize;
use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct ContainerState {
    pub id: String,
    pub pid: Option<u32>,
    pub mounts: Vec<ContainerMount>,
}

#[derive(Debug, Clone)]
pub struct ContainerMount {
    pub destination: String,
    pub source: Option<String>,
    pub options: Vec<String>,
}

#[derive(Deserialize)]
struct RawState {
    id: Option<String>,
    pid: Option<u32>,
    mounts: Option<Vec<RawMount>>,
}

#[derive(Deserialize)]
struct RawMount {
    destination: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    options: Vec<String>,
}

const ROOTS: &[&str] = &[
    "/run",
    "/var/run",
    "/var/lib/containers/storage/overlay-containers",
    "/var/lib/docker/containers",
];

pub fn collect_container_states(limit: usize) -> Result<Vec<ContainerState>, String> {
    let mut files = Vec::new();
    for root in ROOTS {
        let path = Path::new(root);
        if path.exists() {
            find_state_files(path, limit, &mut files)?;
        }
    }

    files.sort();
    files.dedup();

    let mut states = Vec::new();
    for file in files {
        match fs::read_to_string(&file) {
            Ok(content) => match serde_json::from_str::<RawState>(&content) {
                Ok(raw) => {
                    let id = raw.id.unwrap_or_else(|| file.display().to_string());
                    let mounts = raw
                        .mounts
                        .unwrap_or_default()
                        .into_iter()
                        .map(|m| ContainerMount {
                            destination: m.destination,
                            source: m.source,
                            options: m.options,
                        })
                        .collect();
                    states.push(ContainerState {
                        id,
                        pid: raw.pid,
                        mounts,
                    });
                }
                Err(err) => {
                    return Err(format!("failed to parse {}: {err}", file.display()));
                }
            },
            Err(err) => return Err(format!("failed to read {}: {err}", file.display())),
        }
    }

    Ok(states)
}

fn find_state_files(root: &Path, limit: usize, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut queue = VecDeque::new();
    queue.push_back(root.to_path_buf());
    let mut visited = 0usize;

    while let Some(dir) = queue.pop_front() {
        if visited >= limit {
            break;
        }
        visited += 1;

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                // ignore permission errors
                if let Some(13) | Some(30) = err.raw_os_error() {
                    continue;
                }
                return Err(format!("failed to read {}: {err}", dir.display()));
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with('.') {
                        continue;
                    }
                }
                queue.push_back(path);
            } else if path.file_name().and_then(|n| n.to_str()) == Some("state.json") {
                files.push(path);
            }
        }
    }

    Ok(())
}
