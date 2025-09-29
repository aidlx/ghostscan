use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        println!(
            "cargo:warning=Skipping BPF object build for non-Linux target {}",
            target_os
        );
        return Ok(());
    }

    println!("cargo:rerun-if-changed=bpf/task_snapshot.bpf.c");
    println!("cargo:rerun-if-env-changed=BPF_VMLINUX");
    println!("cargo:rerun-if-env-changed=BPF_VMLINUX_H");
    println!("cargo:rerun-if-env-changed=BPF_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=BPFTOOL");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::create_dir_all(&out_dir)?;

    let vmlinux = prepare_vmlinux_header(&out_dir)?;
    compile_bpf(&out_dir, &vmlinux)?;

    Ok(())
}

fn prepare_vmlinux_header(out_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let header_path = out_dir.join("vmlinux.h");

    if let Ok(prebuilt) = env::var("BPF_VMLINUX_H") {
        fs::copy(prebuilt, &header_path)?;
        return Ok(header_path);
    }

    let bpftool = env::var("BPFTOOL").unwrap_or_else(|_| "bpftool".to_string());
    let vmlinux_btf =
        env::var("BPF_VMLINUX").unwrap_or_else(|_| "/sys/kernel/btf/vmlinux".to_string());

    let output = Command::new(&bpftool)
        .args(["btf", "dump", "file", &vmlinux_btf, "format", "c"])
        .output()
        .map_err(|err| format!("failed to execute '{bpftool}': {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "{bpftool} failed to dump BTF from {}: {}",
            vmlinux_btf,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }

    fs::write(&header_path, output.stdout)?;
    Ok(header_path)
}

fn compile_bpf(out_dir: &Path, vmlinux_header: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let clang = env::var("BPF_CLANG")
        .or_else(|_| env::var("CLANG"))
        .unwrap_or_else(|_| "clang".to_string());

    let arch = env::var("BPF_TARGET_ARCH").unwrap_or_else(|_| map_target_arch());
    if arch.is_empty() {
        return Err("unable to determine BPF target arch".into());
    }

    let src = Path::new("bpf").join("task_snapshot.bpf.c");
    let obj = out_dir.join("task_snapshot.bpf.o");

    let output = Command::new(&clang)
        .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
        .arg(format!("-D__TARGET_ARCH_{}", arch))
        .arg("-I")
        .arg(out_dir)
        .arg("-I")
        .arg("bpf")
        .arg("-c")
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .output()
        .map_err(|err| format!("failed to execute '{clang}': {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "{clang} failed to compile {}: {}",
            src.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }

    // Ensure the header exists to keep the compiler happy even if clang's include cache changes.
    if !vmlinux_header.exists() {
        return Err(format!("missing generated header {}", vmlinux_header.display()).into());
    }
    Ok(obj)
}

fn map_target_arch() -> String {
    match env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_else(|_| "x86_64".to_string())
        .as_str()
    {
        "x86_64" | "x86" => "x86".to_string(),
        "aarch64" => "arm64".to_string(),
        "arm" => "arm".to_string(),
        "powerpc" | "powerpc64" | "powerpc64le" => "powerpc".to_string(),
        "riscv64" => "riscv".to_string(),
        other => {
            println!(
                "cargo:warning=Unknown target arch '{}' for BPF build, defaulting to x86",
                other
            );
            "x86".to_string()
        }
    }
}
