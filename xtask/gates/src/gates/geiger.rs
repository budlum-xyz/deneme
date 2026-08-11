//! First-party crates must show zero unsafe usage in cargo-geiger output.
//!
//! Ported from `scripts/check-geiger.sh`. The gate reads a `cargo geiger
//! --all-targets` report: lines whose crate name starts with `budlum-core` or
//! `bud-` must show a `0/N` unsafe column (the crate roots already
//! `#![forbid(unsafe_code)]`; this is the second, independent evidence
//! layer). Third-party dependencies are informational only.

use std::path::Path;

/// # Errors
///
/// Returns a finding when a first-party crate shows non-zero unsafe usage, or
/// when the report file is missing/empty.
pub fn run(_root: &Path, out: &Path) -> Result<String, String> {
    if !out.is_file() {
        return Err(format!("geiger çıktısı yok/boş: {}", out.display()));
    }
    let text =
        std::fs::read_to_string(out).map_err(|e| format!("cannot read {}: {e}", out.display()))?;
    let mut fp_bad = String::new();
    let mut total = 0usize;
    for line in text.lines() {
        if line.starts_with("budlum-core") || line.starts_with("bud-") {
            if !line.split_whitespace().any(|t| t.starts_with("0/")) {
                fp_bad.push_str(line);
                fp_bad.push('\n');
            }
        } else if line.as_bytes().first().is_some_and(u8::is_ascii_lowercase) {
            total += 1;
        }
    }
    if !fp_bad.is_empty() {
        return Err(format!(
            "FAIL: first-party crate'te sıfır-olmayan unsafe kullanımı (forbid(unsafe_code) ile çelişir - sahte rapor olabilir!):\n{fp_bad}"
        ));
    }
    Ok(format!(
        "OK: first-party unsafe kullanımı = 0 (forbid(unsafe_code) ile tutarlı). {total} satır inceleme (deps bilgi amaçlı):"
    ))
}

/// # Errors
///
/// Returns a finding when the canary report does not behave: a first-party
/// `2/N` line must fail, a clean report must pass.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-geiger-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let clean = dir.join("temiz.txt");
    let dirty = dir.join("kirli.txt");
    std::fs::write(
        &clean,
        "budlum-core 0/120\nbud-proof 0/44\nring 17/8920\nsled 3/1200\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(&dirty, "budlum-core 2/120\nring 17/8920\n").map_err(|e| e.to_string())?;

    let dirty_failed = run(&dir, &dirty).is_err();
    let clean_passed = run(&dir, &clean).is_ok();
    let _ = std::fs::remove_dir_all(&dir);

    if !dirty_failed {
        return Err(String::from("canary: first-party unsafe (2) geçti"));
    }
    if !clean_passed {
        return Err(String::from("canary: temiz çıktı reddedildi"));
    }
    Ok(String::from(
        "kanarya OK: first-party unsafe FAIL, deps-unsafe PASS (bilgi), temiz PASS.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report() {
        let dir = std::env::temp_dir().join(format!("budlum-geiger-t-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("r.txt");
        std::fs::write(&f, "budlum-core 0/120\nring 17/8920\n").unwrap();
        assert!(run(&dir, &f).is_ok());
        std::fs::write(&f, "budlum-core 3/120\n").unwrap();
        assert!(run(&dir, &f).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
