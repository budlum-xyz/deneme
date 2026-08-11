//! Dependency audit (port of scripts/audit-deps.sh).

use std::fs;
use std::process::Command;

fn cargo_audit_exists() -> bool {
    Command::new("cargo-audit")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
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

/// Run `cargo audit` against one lockfile, returning (`exit_code`, `raw_output`).
fn audit_lockfile(lockfile: &str, deny_warnings: bool) -> Result<(i32, String), String> {
    let mut cmd = Command::new("cargo");
    cmd.arg("audit").arg("--file").arg(lockfile);
    if deny_warnings {
        cmd.arg("--deny").arg("warnings");
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    Ok((out.status.code().unwrap_or(1), raw))
}

fn extract_advisories(outs: &[&str]) -> Vec<String> {
    let mut set: Vec<String> = Vec::new();
    for o in outs {
        for tok in o.split_whitespace() {
            if tok.len() == 15
                && tok.starts_with("RUSTSEC-")
                && tok[8..12].chars().all(|c| c.is_ascii_digit())
                && !set.contains(&tok.to_string()) {
                    set.push(tok.to_string());
                }
        }
    }
    set.sort();
    set
}

pub fn run() -> Result<String, String> {
    let root = std::env::current_dir().map_err(|e| e.to_string())?;

    if !cargo_audit_exists() {
        let st = Command::new("cargo")
            .args(["install", "--locked", "cargo-audit"])
            .stdin(std::process::Stdio::inherit())
            .status()
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err("cargo-audit install failed".to_string());
        }
    }

    let root_lock = root.join("Cargo.lock");
    let budzero_lock = root.join("budzero/Cargo.lock");

    // JSON runs give exit codes.
    let (root_exit, _) = if root_lock.exists() {
        audit_lockfile("Cargo.lock", false)?
    } else {
        (0, String::new())
    };
    let (bz_exit, _) = if budzero_lock.exists() {
        audit_lockfile("budzero/Cargo.lock", false)?
    } else {
        (0, String::new())
    };

    let audit_exit = if root_exit != 0 {
        root_exit
    } else {
        bz_exit
    };

    // Raw outputs for the log.
    let (_, root_raw) = if root_lock.exists() {
        audit_lockfile("Cargo.lock", true)?
    } else {
        (0, String::new())
    };
    let (_, bz_raw) = if budzero_lock.exists() {
        audit_lockfile("budzero/Cargo.lock", true)?
    } else {
        (0, String::new())
    };

    println!("──────── cargo audit - root Cargo.lock ────────");
    println!("{root_raw}");
    println!("──────── cargo audit - budzero/Cargo.lock ────────");
    println!("{bz_raw}");
    println!("──────────────────────────────────────────────────");

    let advisories = extract_advisories(&[&root_raw, &bz_raw]);
    if advisories.is_empty() {
        println!("[audit-deps] Hicbir danisma bulunmadi.");
    } else {
        println!("[audit-deps] Bu agacta gorulen danismalar:");
        for a in &advisories {
            println!("  - {a}");
        }
    }

    // Report.
    let report = root.join("target/audit/DEPENDENCY_AUDIT.md");
    if let Some(parent) = report.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let verdict = if audit_exit == 0 {
        "- Bilinen güvenlik açığı **YOK** (root + budzero lockfile)."
    } else {
        &format!("- cargo-audit exit code: {audit_exit} (genelde unmaintained warning).")
    };
    let doc = format!(
        "# Dependency Audit Raporu\n\n\
         **Oluşturulma:** {ts}\n\
         **Araç:** cargo-audit (https://github.com/rustsec/rustsec)\n\
         **Repo:** lubosruler/budlum @ `{head}`\n\n\
         ## Özet\n\n\
         {verdict}\n\
         - Root lockfile exit code: {root_exit}\n\
         - BudZero lockfile exit code: {bz_exit}\n\n\
         ## Kabul kriteri\n\n\
         CI'da `dependency-audit` job'ı bu aracı çalıştırır. Bilinen güvenlik\n\
         açığı tespit edilirse job fail eder. Unmaintained warning'leri warning\n\
         olarak raporlanır (fail etmez). Root ve BudZero lockfile'ları birlikte\n\
         denetlenir.\n",
        ts = utc_timestamp(),
        head = current_head(),
        verdict = verdict,
        root_exit = root_exit,
        bz_exit = bz_exit
    );
    fs::write(&report, doc).map_err(|e| e.to_string())?;

    println!("[audit-deps] Rapor: {}", report.display());
    println!("[audit-deps] Bitti.");

    if audit_exit != 0 {
        Err(format!("cargo-audit exit code {audit_exit}"))
    } else {
        Ok("dependency audit OK".to_string())
    }
}
