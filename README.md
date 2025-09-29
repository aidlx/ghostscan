# ghostscan

Fast one-shot sweep for Linux incident response. Drop the binary on a host, run it once, and collect actionable leads from the kernel, procfs, bpffs, systemd, cron, sockets, and more.

## Quick start

1. Install a current Rust toolchain.
2. Build with `cargo build --release`.
3. Copy `target/release/ghostscan` to the target host.
4. Run as root (or with equivalent capabilities): `sudo ./ghostscan`.
5. Optional helpers (`bpftool`, `nft`, `ss`, `journalctl`, `auditctl`) expand coverage; when missing, the output explains what was skipped.

## Reading results

- Each scanner prints a bracketed name followed by either findings, `OK`, or an error string.
- The process always exits with code `0`; treat the log itself as the verdict.
- Findings are heuristics designed for triage; validate before acting.

## Available scanners

- **Hidden LKM**: compares procfs/sysfs clusters against `kallsyms` to surface hidden modules.
- **Kernel taint**: highlights taint flags that lack a visible explanation.
- **Ftrace redirection**: spots risky `ftrace` hooks on critical kernel paths.
- **Unknown kprobes**: looks for kprobes attached to sensitive symbols that ghostscan cannot explain.
- **Syscall table integrity**: verifies syscall table pointers for tampering.
- **Netfilter hook drift**: finds orphaned or invalid netfilter hook jumps.
- **Module linkage tamper**: checks module list pointers for manipulation.
- **Ownerless BPF objects**: reports BPF maps/programs without a backing task.
- **BPF kprobe attachments**: flags kprobes pointed at high-value kernel routines.
- **BPF LSM**: notes when BPF LSM programs are active.
- **Detached XDP/TC programs**: detects XDP or TC programs that no longer have an interface.
- **Sockmap/Sockhash verdicts**: surfaces sockmap/sockhash programs lacking owners.
- **Sensitive kfunc usage**: tracks invocations of dangerous `kfunc` targets.
- **Non-bpffs pins**: finds BPF pins created outside bpffs mounts.
- **Netlink vs proc**: compares netlink inventories with `/proc/net` to expose hidden sockets.
- **Task list mismatch**: contrasts BPF snapshots with `/proc` task lists to expose hidden PIDs.
- **Hidden PIDs**: uses BPF-only views to reveal task IDs invisible to `/proc`.
- **Kernel thread masquerade**: detects kernel threads spoofing user process metadata.
- **Suspicious ptrace edges**: reports unusual ptrace parent/child relationships.
- **Deleted or memfd binaries**: lists processes executing from deleted files or memfd mounts.
- **Hidden listeners**: identifies listeners seen via netlink vs `/proc` vs BPF.
- **Ownerless sockets**: reports sockets without an owning task.
- **Netfilter cloaking**: spots tampering patterns that hide netfilter rules.
- **Local port backdoors**: highlights sockets bound to deleted or temporary paths.
- **`ld.so.preload` tamper**: inspects `ld.so.preload` for unexpected entries.
- **Cron ghosts**: checks cron/anacron/at directories for orphaned or cloaked jobs.
- **Systemd ghosts**: finds unit files pointing to deleted or temporary executables.
- **SSH footholds**: surfaces dangerous `authorized_keys` options and forced commands.
- **OverlayFS whiteouts**: reports suspicious opaque or whiteout entries in OverlayFS.
- **Hidden bind mounts**: lists bind or immutable mounts likely used for concealment.
- **PAM/NSS modules**: flags PAM or NSS modules loaded from non-system paths.
- **Live `LD_PRELOAD`**: notes processes still using deleted or writable preload libraries.
- **Library search hijack**: checks SUID/privileged binaries for unsafe search paths.
- **`LD_AUDIT` daemons**: finds daemons configured with `LD_AUDIT` despite lacking TTYs.
- **Large RX regions**: surfaces non-JIT daemons with large anonymous RX memory.
- **Kernel text RO**: verifies that kernel text sections remain read-only.
- **`/etc/scripts.d` provenance**: warns on executable scripts from tmp or non-root owners.
- **Sudoers**: examines sudoers entries for insecure privilege escalation paths.
- **Kernel cmdline**: alerts on boot parameters that disable audit, lockdown, or IMA.
- **Sensitive host mounts**: identifies sensitive host paths exposed inside containers.
- **Host PID namespace**: reports containers sharing the host PID namespace.
- **Overlay lowerdir**: catches OverlayFS lowerdirs that escape the storage root.
- **Audit disabled**: detects when auditd is off or dropping records.
- **Journal gaps**: looks for missing spans in the current boot's journal.
- **Kernel message suppression**: notices unusual suppression of kernel logs.

## Development pointers

- Format and lint locally with `cargo fmt && cargo check`.
- New scanners live in `src/scanners/` and expose `pub fn run() -> ScanOutcome` before being registered in `SCANNERS` inside `src/main.rs`.

## Operational notes

- Most modules require elevated privileges to read privileged interfaces, and they report missing access instead of silently failing.

## License

MIT
