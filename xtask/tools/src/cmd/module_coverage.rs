#![allow(clippy::cast_precision_loss)]

//! Module-level coverage analysis (port of `scripts/check_module_coverage.py`).

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MODULE_PREFIXES: &[(&str, &str)] = &[
    ("budlum:consensus", "src/consensus/"),
    ("budlum:crypto", "src/crypto/"),
    ("budlum:rpc", "src/rpc/"),
    ("budlum:chain", "src/chain/"),
    ("budlum:core", "src/core/"),
    ("budlum:domain", "src/domain/"),
    ("budlum:network", "src/network/"),
    ("budlum:storage", "src/storage/"),
    ("budlum:tokenomics", "src/tokenomics/"),
    ("budlum:node_di", "src/node_di/"),
    ("budlum:cli", "src/cli/"),
    ("budlum:docs", "src/docs/"),
    ("budzero:vm", "budzero/src/"),
    ("budzero:proof", "budzero/bud-proof/src/"),
    ("budzero:isa", "budzero/bud-isa/src/"),
    ("budzero:node", "budzero/bud-node/src/"),
    ("budzero:compiler", "budzero/bud-compiler/src/"),
];

fn normalize(path: &str) -> String {
    let p = path.replace('\\', "/");
    for anchor in ["/budlum/", "/budzero/"] {
        if p.contains(anchor) {
            if anchor == "/budzero/" {
                let idx = p.find("budzero/").unwrap_or(0);
                return p[idx..].to_string();
            }
            return p.split(anchor).nth(1).unwrap_or(&p).to_string();
        }
    }
    p
}

fn module_of(path: &str) -> String {
    for (name, prefix) in MODULE_PREFIXES {
        if path.starts_with(prefix) {
            return (*name).to_string();
        }
    }
    "__other__".to_string()
}

struct Row {
    module: String,
    covered: u64,
    total: u64,
}

fn analyze(cov: &Value) -> Vec<Row> {
    let mut acc: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    if let Some(data) = cov.get("data").and_then(|d| d.as_array()) {
        for d in data {
            if let Some(files) = d.get("files").and_then(|f| f.as_array()) {
                for f in files {
                    let fname = f.get("filename").and_then(|s| s.as_str()).unwrap_or("");
                    let norm = normalize(fname);
                    let lines = f.get("summary").and_then(|s| s.get("lines"));
                    let total = lines.and_then(|l| l.get("count")).and_then(serde_json::Value::as_u64).unwrap_or(0);
                    let covered = lines.and_then(|l| l.get("covered")).and_then(serde_json::Value::as_u64).unwrap_or(0);
                    if total == 0 {
                        continue;
                    }
                    let mod_name = module_of(&norm);
                    let e = acc.entry(mod_name).or_insert((0, 0));
                    e.0 += covered;
                    e.1 += total;
                }
            }
        }
    }
    acc.into_iter()
        .map(|(module, (c, t))| Row {
            module,
            covered: c,
            total: t,
        })
        .collect()
}

fn print_table(rows: &[Row]) {
    println!("{:<22}{:>10}{:>10}{:>9}", "modul", "kaplanan", "toplam", "%");
    for r in rows {
        let pct = if r.total == 0 { 100.0 } else { 100.0 * r.covered as f64 / r.total as f64 };
        println!("{:<22}{:>10}{:>10}{:>8.2}", r.module, r.covered, r.total, pct);
    }
}

fn gate(rows: &[Row], baselines: &BTreeMap<String, f64>) -> Result<String, String> {
    let mut fails = Vec::new();
    for (name, floor) in baselines {
        let hit = rows.iter().find(|r| &r.module == name);
        match hit {
            None => {
                println!("FAIL: taban istenen modul raporda yok: {name}");
                fails.push(name.clone());
            }
            Some(r) => {
                let pct = if r.total == 0 { 100.0 } else { 100.0 * r.covered as f64 / r.total as f64 };
                if pct + 1e-9 < *floor {
                    println!("FAIL: {name} coverage {pct:.2}% < taban {floor:.2}% (ratchet)");
                    fails.push(name.clone());
                }
            }
        }
    }
    if fails.is_empty() {
        println!("OK: tum modul tabanlari tuttu (ratchet yonu: dusus yok).");
        Ok("OK".to_string())
    } else {
        Err(format!("{} modul tabani ihlal edildi", fails.len()))
    }
}

fn baselines_path() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_default()
        .join(".github/module-coverage-baselines.json")
}

/// Load baseline floors from `.github/module-coverage-baselines.json` (if any).
fn load_baselines() -> Option<BTreeMap<String, f64>> {
    let p = baselines_path();
    let text = fs::read_to_string(p).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let obj = v.get("module_line_floors")?.as_object()?;
    let mut map = BTreeMap::new();
    for (k, val) in obj {
        if let Some(f) = val.as_f64() {
            map.insert(k.clone(), f);
        }
    }
    Some(map)
}

pub fn check_from_path(cov_path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(cov_path).map_err(|e| e.to_string())?;
    let cov: Value = serde_json::from_str(&text).map_err(|e| format!("cov json: {e}"))?;
    let rows = analyze(&cov);
    print_table(&rows);
    let Some(baselines) = load_baselines() else {
        return Ok("SKIP: baselines yok - rapor modu (vacuous-gate YOK).".to_string());
    };
    if baselines.is_empty() {
        return Ok("SKIP: baselines bos - rapor modu.".to_string());
    }
    gate(&rows, &baselines)
}

pub fn self_test() -> Result<String, String> {
    let fake = serde_json::json!({
        "data": [{
            "files": [
                {"filename": "/x/budlum/src/consensus/pow.rs",
                 "summary": {"lines": {"count": 100, "covered": 50}}},
                {"filename": "/x/budlum/src/crypto/hash.rs",
                 "summary": {"lines": {"count": 100, "covered": 90}}},
                {"filename": "/x/budlum/budzero/src/lib.rs",
                 "summary": {"lines": {"count": 10, "covered": 8}}},
            ]
        }]
    });
    let rows = analyze(&fake);
    let mp: BTreeMap<&str, f64> = rows.iter().map(|r| {
        let pct = if r.total == 0 { 100.0 } else { 100.0 * r.covered as f64 / r.total as f64 };
        (r.module.as_str(), pct)
    }).collect();
    let get = |k: &str| mp.get(k).copied().unwrap_or(0.0);
    if (get("budlum:consensus") - 50.0).abs() > 1e-6 { return Err("consensus coverage yanlis".into()); }
    if (get("budlum:crypto") - 90.0).abs() > 1e-6 { return Err("crypto coverage yanlis".into()); }
    if (get("budzero:vm") - 80.0).abs() > 1e-6 { return Err("budzero:vm coverage yanlis".into()); }

    let mut under = BTreeMap::new();
    under.insert("budlum:consensus".to_string(), 49.0);
    gate(&rows, &under)?;
    let mut over = BTreeMap::new();
    over.insert("budlum:consensus".to_string(), 51.0);
    if gate(&rows, &over).is_ok() {
        return Err("VACUOUS GATE: 51 taban gecti!".into());
    }
    Ok("kanarya OK: olcum dogru; taban alti FAIL, ustu PASS.".to_string())
}
