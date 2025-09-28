use crate::ScanOutcome;
use std::{collections::HashMap, fs, io, path::Path};

pub fn run() -> ScanOutcome {
    let tasks = match collect_tasks() {
        Ok(map) => map,
        Err(err) => return Err(err),
    };

    let mut findings = Vec::new();

    for task in tasks.values() {
        if let Some(tracer_pid) = task.tracer_pid {
            if tracer_pid == 0 {
                continue;
            }

            if let Some(tracer) = tasks.get(&tracer_pid) {
                let cross_uid = tracer.uid != task.uid;
                let daemon_tracing = tracer.ppid == 1;

                if !cross_uid && !daemon_tracing {
                    continue;
                }

                let mut flags = Vec::new();
                if cross_uid {
                    flags.push("cross_uid=true");
                }
                if daemon_tracing {
                    flags.push("daemon_tracing=true");
                }

                findings.push(format!(
                    "{} -> {}, tracer_comm={}, traced_comm={}, {}",
                    tracer_pid,
                    task.pid,
                    tracer.comm,
                    task.comm,
                    flags.join("|")
                ));
            } else {
                findings.push(format!(
                    "{} -> {}, tracer_comm=unknown, traced_comm={}, info=missing_tracer",
                    tracer_pid, task.pid, task.comm
                ));
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

struct TaskInfo {
    pid: i32,
    comm: String,
    uid: u32,
    tracer_pid: Option<i32>,
    ppid: i32,
}

fn collect_tasks() -> Result<HashMap<i32, TaskInfo>, String> {
    let mut map = HashMap::new();
    let proc_dir = fs::read_dir("/proc").map_err(|err| format!("failed to read /proc: {err}"))?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: i32 = match pid_str.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        match read_task(pid) {
            Ok(info) => {
                map.insert(pid, info);
            }
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    return Err(format!("pid={pid}: {err}"));
                }
            }
        }
    }

    Ok(map)
}

fn read_task(pid: i32) -> io::Result<TaskInfo> {
    let base = Path::new("/proc").join(pid.to_string());
    let comm = fs::read_to_string(base.join("comm"))?.trim().to_string();
    let status = fs::read_to_string(base.join("status"))?;

    let mut tracer_pid = None;
    let mut uid = 0;

    for line in status.lines() {
        if let Some(value) = line.strip_prefix("TracerPid:") {
            tracer_pid = value.trim().parse::<i32>().ok();
        }
        if let Some(value) = line.strip_prefix("Uid:") {
            if let Some(uid_str) = value.split_whitespace().next() {
                uid = uid_str.parse::<u32>().unwrap_or(0);
            }
        }
    }

    let stat = fs::read_to_string(base.join("stat"))?;
    let ppid = parse_ppid(&stat).unwrap_or(0);

    Ok(TaskInfo {
        pid,
        comm,
        uid,
        tracer_pid,
        ppid,
    })
}

fn parse_ppid(stat: &str) -> Option<i32> {
    let right_paren = stat.rfind(')')?;
    let rest = &stat[right_paren + 2..];
    let mut fields = rest.split_whitespace();
    fields.next()?; // state
    fields.next()?.parse::<i32>().ok()
}
