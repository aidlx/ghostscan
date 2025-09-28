use crate::ScanOutcome;
use std::{fs, path::Path};

pub fn run() -> ScanOutcome {
    let path = Path::new("/sys/kernel/rodata_enabled");
    if path.exists() {
        let value = fs::read_to_string(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let trimmed = value.trim();
        if trimmed == "0" || trimmed.eq_ignore_ascii_case("n") {
            return Ok(Some("region=kernel_text, perms_detected!=RO".to_string()));
        }
        return Ok(None);
    }

    let config_path = Path::new("/proc/config.gz");
    if config_path.exists() {
        if let Ok(config) = read_gzip(config_path) {
            if config.contains("CONFIG_STRICT_KERNEL_RWX=y") {
                return Ok(None);
            }
            if config.contains("CONFIG_STRICT_KERNEL_RWX=n") {
                return Ok(Some(
                    "region=kernel_text, perms_detected!=RO (CONFIG_STRICT_KERNEL_RWX=n)"
                        .to_string(),
                ));
            }
        }
    }

    Ok(None)
}

fn read_gzip(path: &Path) -> Result<String, String> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let file = fs::File::open(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let mut decoder = GzDecoder::new(file);
    let mut content = String::new();
    decoder
        .read_to_string(&mut content)
        .map_err(|err| format!("failed to decompress {}: {err}", path.display()))?;
    Ok(content)
}
