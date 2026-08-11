//! Clippy-extra ratchet report (port of scripts/clippy-extra-report.py).

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub fn run_from_path(path: &Path, max_per_lint: usize) -> String {
    let mut per_lint: BTreeMap<String, usize> = BTreeMap::new();
    let mut hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            // A missing file is the gate's problem to report, not this tool's.
            println!("clippy-extra-report: cannot read {}: {e}", path.display());
            return String::new();
        }
    };
    for line in text.lines() {
        let record: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if record.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }
        let Some(message) = record.get("message") else { continue };
        let code = message.get("code").and_then(|c| c.get("code")).and_then(|c| c.as_str()).unwrap_or("");
        if message.get("level").and_then(|l| l.as_str()) != Some("warning") || !code.starts_with("clippy::") {
            continue;
        }
        *per_lint.entry(code.to_string()).or_insert(0) += 1;
        if let Some(spans) = message.get("spans").and_then(|s| s.as_array()) {
            if let Some(first) = spans.first() {
                let f = first.get("file_name").and_then(|x| x.as_str()).unwrap_or("?");
                let l = first.get("line_start").and_then(serde_json::Value::as_u64).unwrap_or(0);
                hits.entry(code.to_string()).or_default().push(format!("{f}:{l}"));
            }
        }
    }
    let total: usize = per_lint.values().sum();
    println!("--- clippy-extra: {total} warnings across {} lints ---", per_lint.len());
    let mut sorted: Vec<_> = per_lint.into_iter().collect();
    sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (code, count) in sorted.into_iter().take(30) {
        println!("{count:6}  {code}");
        if let Some(hs) = hits.get(&code) {
            for h in hs.iter().take(max_per_lint) {
                println!("            {h}");
            }
        }
    }
    String::new()
}
