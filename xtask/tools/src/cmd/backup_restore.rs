//! Backup/restore drill (port of `ops/backup_restore_drill.sh`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn newest_backup(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for e in fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        let name = p.file_name()?.to_string_lossy().into_owned();
        if !name.starts_with("budlum-") || !name.ends_with(".budbak") {
            continue;
        }
        let mtime = fs::metadata(&p).and_then(|m| m.modified()).ok();
        let newer = match (&best, mtime) {
            (None, _) => true,
            (Some((bt, _)), Some(t)) => t > *bt,
            _ => false,
        };
        if newer {
            best = Some((mtime.unwrap_or(std::time::UNIX_EPOCH), p));
        }
    }
    best.map(|(_, p)| p)
}

pub fn run() -> Result<String, String> {
    let root = std::env::current_dir().map_err(|e| e.to_string())?;
    let bin = root.join("target/release/budlum-core");
    if !bin.is_file() {
        return Err(format!("budlum binary not executable: {}", bin.display()));
    }
    let source_db = std::env::var("SOURCE_DB").map_err(|_| "Set SOURCE_DB to the stopped node database directory".to_string())?;
    let backup_dir = std::env::var("BACKUP_DIR").map_err(|_| "Set BACKUP_DIR to the backup destination".to_string())?;
    fs::create_dir_all(&backup_dir).map_err(|e| e.to_string())?;

    let st = Command::new(&bin)
        .args(["--db-path", &source_db, "--backup-dir", &backup_dir, "--backup-retention-count", "168", "--backup-now"])
        .status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err(format!("backup failed with {st}"));
    }

    let backup = newest_backup(Path::new(&backup_dir))
        .ok_or_else(|| "No backup produced".to_string())?;

    let tmp = std::env::temp_dir().join(format!("budlum-restore-drill-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let restore_db = tmp.join("restored.db");

    let st = Command::new(&bin).args(["--db-path", restore_db.to_str().unwrap(), "--restore-backup", backup.to_str().unwrap()])
        .status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err("restore failed".to_string());
    }
    let out = Command::new(&bin).args(["--db-path", restore_db.to_str().unwrap(), "--check-db"])
        .output().map_err(|e| e.to_string())?;
    let output = String::from_utf8_lossy(&out.stdout).into_owned();
    print!("{output}");
    if !output.contains("Integrity Audit PASSED") {
        return Err("integrity audit did not pass".to_string());
    }
    let _ = fs::remove_dir_all(&tmp);
    Ok(format!("Restore drill passed: {} -> {}", backup.display(), restore_db.display()))
}
