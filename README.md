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
- Findings are heuristics designed for triage—validate before acting.

## Development pointers

- Format and lint locally with `cargo fmt && cargo check`.
- New scanners live in `src/scanners/` and expose `pub fn run() -> ScanOutcome` before being registered in `SCANNERS` inside `src/main.rs`.

## Operational notes

- Most modules require elevated privileges to read privileged interfaces, and they report missing access instead of silently failing.

## License

MIT
