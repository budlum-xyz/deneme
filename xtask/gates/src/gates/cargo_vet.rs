//! cargo-vet unvetted-dependency count ratchet.
//!
//! Ported from `scripts/check-cargo-vet.sh`. Runs `cargo vet check`, reads the
//! `<N> unvetted dependencies` count from its output, and fails when the
//! count exceeds `.github/cargo-vet-baseline.txt`. The count may fall (the
//! baseline is tightened in a deliberate PR), never rise.

use std::path::Path;

fn baseline(root: &Path) -> Result<u64, String> {
    let f = root.join(".github/cargo-vet-baseline.txt");
    let text = std::fs::read_to_string(&f)
        .map_err(|e| format!("baseline okunamadı ({}): {e}", f.display()))?;
    text.lines()
        .find(|l| l.chars().all(|c| c.is_ascii_digit()) && !l.is_empty())
        .ok_or_else(|| format!("baseline okunamadı ({})", f.display()))?
        .parse::<u64>()
        .map_err(|e| format!("baseline sayı değil: {e}"))
}

fn count_from_output(out: &str) -> u64 {
    out.lines()
        .find_map(|l| {
            let t = l.trim_start();
            // The count is the leading run of digits.
            let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                return None;
            }
            let rest = &t[digits.len()..];
            if rest.starts_with(" unvetted dependencies") {
                digits.parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// Run `cargo vet check` in the repo root and return its stdout/stderr.
fn run_vet(root: &Path) -> String {
    let out = std::process::Command::new("cargo")
        .args(["vet", "check"])
        .current_dir(root)
        .output();
    match out {
        Ok(o) => {
            String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
        }
        Err(e) => format!("cargo vet çalışmadı: {e}"),
    }
}

/// # Errors
///
/// Returns a finding when the unvetted count exceeds the baseline.
pub fn run(root: &Path) -> Result<String, String> {
    let base = baseline(root)?;
    let n = count_from_output(&run_vet(root));
    let msg = format!("cargo-vet denetimsiz bağımlılık: {n} | baseline: {base}");
    if n > base {
        return Err(format!(
            "{msg}\nFAIL: denetimsiz bağımlılık sayısı baseline'ı aştı (+{}).\n      Yeni bir bağımlılık eklendiyse: ya güvenilir bir import kaynağı\n      onu kapsamalı, ya `cargo vet certify` ile gerekçeli denetim\n      kaydı girilmeli. Baseline'ı YÜKSELTMEK bir çözüm değildir.",
            n - base
        ));
    }
    if n < base {
        return Ok(format!(
            "{msg}\nİYİLEŞME: baseline {base} -> {n} düşürülebilir.\n          .github/cargo-vet-baseline.txt dosyasını {n} yapın (ratchet sıkılır).\n\nOK: denetimsiz bağımlılık baseline altında/eşit (ratchet sağlam)."
        ));
    }
    Ok(format!(
        "{msg}\nOK: denetimsiz bağımlılık baseline altında/eşit (ratchet sağlam)."
    ))
}

/// # Errors
///
/// Returns a finding when the output parser misreads a known shape.
pub fn self_test() -> Result<String, String> {
    let got = count_from_output(
        "Vetting Failed!\n\n123 unvetted dependencies:\n  aead:0.5.2 missing [\"safe-to-deploy\"]",
    );
    if got != 123 {
        return Err(format!(
            "canary: sayaç 123 yerine '{got}' okudu (parse bozuk)"
        ));
    }
    let clean = count_from_output("Vetting Succeeded!");
    if clean != 0 {
        return Err(format!("canary: temiz çıktı 0 yerine '{clean}' okudu"));
    }
    Ok(String::from("Kanarya OK: sayaç 123/0 doğru okudu."))
}
