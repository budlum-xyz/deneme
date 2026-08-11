//! Coverage report (port of scripts/coverage-report.sh).

use std::process::Command;

pub fn run() -> String {
    println!("=== Budlum Coverage Report ===");
    let has_llvm = Command::new("cargo-llvm-cov")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !has_llvm {
        println!("cargo-llvm-cov not installed. Install: cargo install cargo-llvm-cov");
        println!();
        let base = std::fs::read_to_string(".github/coverage-baseline.txt").unwrap_or_default();
        println!("Coverage baseline:");
        if base.trim().is_empty() {
            println!("(baseline not found)");
        } else {
            print!("{base}");
        }
        return "coverage report (llvm-cov unavailable)".to_string();
    }
    println!("--- Per-file coverage (top 20 by lines) ---");
    let _ = Command::new("cargo")
        .args(["llvm-cov", "nextest", "--lib", "--text"])
        .stdin(std::process::Stdio::null())
        .status();
    println!();
    println!("--- Summary ---");
    let _ = Command::new("cargo")
        .args(["llvm-cov", "nextest", "--lib", "--summary-only"])
        .stdin(std::process::Stdio::null())
        .status();
    println!();
    println!("--- Module breakdown ---");
    for module in ["consensus", "cross_domain", "crypto", "execution", "chain", "network", "storage", "ai"] {
        println!("  src/{module}/: (see llvm-cov output)");
    }
    "coverage report OK".to_string()
}
