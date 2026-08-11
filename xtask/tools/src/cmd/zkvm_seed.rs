//! Regenerate synthetic `BudZero` ZKVM seed corpus (port of `generate_zkvm_seed_corpus.sh`).

use std::fs;
use std::path::PathBuf;

/// (filename, bytes)
fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("01_simple_add.bud", vec![0x01, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00]),
        (
            "02_branch_loop.bud",
            vec![0x0a, 0x01, 0x02, 0x03, 0x05, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
        ("03_verify_merkle_0x1E.bud", vec![0x1e, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00]),
        ("04_poseidon_hash.bud", vec![0x1d, 0x01, 0x02, 0x03, 0x0a, 0x00, 0x00, 0x00]),
        ("05_memory_ops.bud", vec![0x10, 0x01, 0x02, 0x00, 0x11, 0x01, 0x02, 0x00]),
    ]
}

pub fn run(args: &[std::ffi::OsString]) -> Result<String, String> {
    let root = std::env::current_dir().map_err(|e| e.to_string())?;
    let out_dir = match args.first() {
        Some(p) => root.join(PathBuf::from(p)),
        None => root.join("fuzz/corpus/zkvm"),
    };
    fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
    println!(
        "Generating synthetic binary seed corpus files for BudZero ZKVM fuzzing in: {}",
        out_dir.display()
    );
    for (name, bytes) in seeds() {
        let p = out_dir.join(name);
        fs::write(&p, &bytes).map_err(|e| format!("write {}: {e}", p.display()))?;
        println!("  [+] {} ({} bytes)", p.display(), bytes.len());
    }
    let count = fs::read_dir(&out_dir)
        .map_or(0, |it| it.flatten().filter(|e| e.path().extension() == Some(std::ffi::OsStr::new("bud"))).count());
    Ok(format!("Synthetic ZKVM seed corpus generation complete. Total seeds: {count}"))
}
