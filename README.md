# ghostscan

ghostscan is the grab-it-run-it-read-it toolkit for responders who need a fast gut check on a Linux host. Drop the binary on a box, run it once, and ghostscan walks the kernel, procfs, bpffs, systemd, cron, sockets, and more to surface the things an attacker would rather you never notice.

## Why operators reach for ghostscan

- High signal, low noise: every scanner hunts for a specific stealth technique and explains the evidence in plain English.
- Safe to run in the middle of an incident: ghostscan is read-only and avoids bash gymnastics that might tip off an adversary.
- Honest about blind spots: if a capability or helper binary is missing you get the reason on screen, not a silent miss.
- Simple mental model: each module returns `Ok(Some finding)` when it sees trouble, `Ok(None)` when things look clean, or `Err(reason)` if it cannot perform the check.

## Getting started

1. Install a modern Rust toolchain (Rust 1.82+ or the latest stable release).
2. Build a release binary with `cargo build --release`.
3. Copy `target/release/ghostscan` to the machine you want to inspect.
4. Run it with root or with the capabilities needed to read privileged interfaces: `sudo ./ghostscan`.

Helpful companion binaries dramatically expand coverage: `bpftool` for the BPF suite, `nft` for Netfilter analysis, `ss` for socket comparisons, `journalctl` for log gap checks, and `auditctl` (or audit netlink access) for auditing state.

## Reading the output

```
[Hidden LKM (proc/sysfs vs kallsyms clusters)]
OK

[Ownerless BPF objects]
bpftool not available to inspect BPF objects

[Hidden listeners (netlink-only)]
tcp 0.0.0.0:2222 owner_pids=[] from=netlink_only inode=123456
```

- Green `OK` means the check ran and found nothing interesting.
- Red lines (when ANSI colors are available) highlight findings or execution issues you should investigate.
- The process exit code is always zero; treat the text log as the source of truth.

## Scanner highlights

ghostscan ships with dozens of focused checks. A few crowd favorites:

- Kernel integrity: detects hidden LKMs, suspicious kprobes, syscall table tampering, ftrace redirection, kernel thread masquerade, and muted printk settings.
- BPF sleuthing: surfaces orphaned programs and maps, hidden sockmap verdicts, sensitive kfunc usage, LSM hooks, XDP and TC anomalies, and pins that live outside bpffs.
- Network footholds: inspects nftables for cloak attempts, compares netlink and proc socket views, and calls out backdoors listening from deleted binaries or odd locations.
- Persistence and hijacks: reviews cron, systemd, scripts.d, SSH keys, LD_PRELOAD, LD_AUDIT, library search paths, and processes still running from deleted or memfd executables.
- Containers and isolation: checks for host PID namespace reuse, sensitive host mounts, suspicious overlay lowerdirs, hidden bind mounts, and mismatched task lists between BPF and proc.
- Policy and logging: examines sudoers, PAM/NSS modules, kernel cmdline flags, audit state, and journal continuity so you can see whether defenders have been blinded.

Every scanner lives in `src/scanners/` as a tiny module with a single `run()` function, making it easy to read, modify, or drop into your own tooling.

## Developing and extending

- Format before you commit with `cargo fmt` and sanity check with `cargo check`.
- New scanners follow the same pattern: create `src/scanners/your_module.rs`, implement `pub fn run() -> ScanOutcome`, and register it in `SCANNERS` inside `src/main.rs`.
- Keep changes tight and reviewable; ghostscan values clarity over cleverness.

## Operational notes

- Most scanners need root because they rely on privileged kernel interfaces; without them you will see explicit errors per module.
- ghostscan never writes to disk, flips sysctls, or opens network sockets. It is safe to run mid-incident so long as reading sensitive files is acceptable in your environment.
- Findings are heuristics. Treat the output as leads to validate, not instant verdicts.

## License

MIT license
