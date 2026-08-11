//! `CycloneDX` SBOM generation (port of scripts/generate-sbom.sh).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CYCLONEDX_VERSION: &str = "0.5.9";

fn run_cmd(cmd: &mut Command) -> Result<(), String> {
    let status = cmd.status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("command failed with {status}"));
    }
    Ok(())
}

fn current_head() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output().map_or_else(|_| "unknown".to_string(), |o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn utc_timestamp() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output().map_or_else(|_| "unknown".to_string(), |o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Find the most recently modified `*.cdx.json` in `root`.
fn newest_cdx(root: &Path) -> Result<PathBuf, String> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries = fs::read_dir(root).map_err(|e| format!("read_dir {}: {e}", root.display()))?;
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".cdx.json") {
            continue;
        }
        let mtime = fs::metadata(&p).and_then(|m| m.modified()).ok();
        let newer = match (&best, mtime) {
            (None, _) => true,
            (Some((best_t, _)), Some(t)) => t > *best_t,
            _ => false,
        };
        if newer {
            best = Some((mtime.unwrap_or(std::time::UNIX_EPOCH), p));
        }
    }
    best.map(|(_, p)| p)
        .ok_or_else(|| "no .cdx.json file produced by cargo cyclonedx".to_string())
}

pub fn run() -> Result<String, String> {
    let root = std::env::current_dir().map_err(|e| e.to_string())?;

    // 1. Ensure cargo-cyclonedx at pinned version.
    let have_version = Command::new("cargo")
        .args(["cyclonedx", "--version"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(CYCLONEDX_VERSION));
    if !have_version {
        run_cmd(
            Command::new("cargo")
                .args([
                    "install",
                    "--locked",
                    "cargo-cyclonedx",
                    "--version",
                    CYCLONEDX_VERSION,
                ])
                .stdin(std::process::Stdio::inherit()),
        )?;
    }

    // 2. Generate SBOM.
    run_cmd(Command::new("cargo").args(["cyclonedx", "--format", "json"]))?;
    let tmp = newest_cdx(&root)?;
    let sbom_file = root.join("sbom.cdx.json");
    fs::rename(&tmp, &sbom_file).map_err(|e| format!("rename SBOM: {e}"))?;

    // 3. JSON validation + component count.
    let text = fs::read_to_string(&sbom_file).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("SBOM is not valid JSON: {e}"))?;
    let component_count = v
        .get("components")
        .and_then(|c| c.as_array())
        .map_or(0, std::vec::Vec::len);
    let size = text.len();

    // 4. Report markdown.
    let doc = root.join("target/audit/SBOM.md");
    if let Some(parent) = doc.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let report = format!(
        "# SBOM (Software Bill of Materials)\n\n\
         **Oluşturulma:** {ts}\n\
         **Araç:** cargo-cyclonedx (https://github.com/CycloneDX/cyclonedx-rust-cargo)\n\
         **Format:** CycloneDX 1.5 (JSON)\n\
         **Repo:** lubosruler/budlum @ `{head}`\n\n\
         ## Özet\n\n\
         - **SBOM dosyası:** `sbom.cdx.json` (boyut: {size} byte)\n\
         - **Bileşen sayısı:** {count}\n\n\
         ## Kullanım\n\n\
         Harici audit firması `sbom.cdx.json` dosyasını doğrudan kullanabilir.\n\
         Format: CycloneDX 1.5 JSON, tüm transitive bağımlılıkları içerir.\n\n\
         ## Yenileme\n\n\
         ```\n\
         cargo run --release --manifest-path xtask/tools/Cargo.toml -- sbom\n\
         ```\n",
        ts = utc_timestamp(),
        head = current_head(),
        size = size,
        count = component_count
    );
    fs::write(&doc, report).map_err(|e| e.to_string())?;

    Ok(format!(
        "SBOM: {} ({} byte, {} bilesen); rapor: {}",
        sbom_file.display(),
        size,
        component_count,
        doc.display()
    ))
}
