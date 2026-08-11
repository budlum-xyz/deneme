//! Pre-push local checks (port of scripts/pre-push-check.sh).

use std::process::Command;

fn check(cmd: &mut Command, label: &str) -> Result<(), String> {
    let status = cmd.status().map_err(|e| format!("{label}: {e}"))?;
    if !status.success() {
        return Err(format!("{label}: {status}"));
    }
    Ok(())
}

pub fn run() -> Result<String, String> {
    println!("Running Budlum Pre-push Checks...");
    println!("Checking code formatting...");
    check(Command::new("cargo").args(["fmt", "--all", "--", "--check"]), "cargo fmt")?;
    println!("Running Clippy (Strict mode)...");
    check(
        Command::new("cargo")
            .args(["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]),
        "cargo clippy",
    )?;
    Ok("All checks passed! Safe to push.".to_string())
}
