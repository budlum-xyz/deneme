//! Node boot smoke test (port of `scripts/smoke_rpc.sh`).

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

fn find_bin(root: &Path) -> Result<std::path::PathBuf, String> {
    let debug = root.join("target/debug/budlum-core");
    if debug.is_file() {
        return Ok(debug);
    }
    let release = root.join("target/release/budlum-core");
    if release.is_file() {
        return Ok(release);
    }
    let st = Command::new("cargo")
        .args(["build", "-q", "--bin", "budlum-core"])
        .status()
        .map_err(|e| e.to_string())?;
    if !st.success() {
        return Err("cargo build failed".to_string());
    }
    Ok(debug)
}

fn rpc_chain_id(port: u16) -> Option<String> {
    let body = r#"{"jsonrpc":"2.0","method":"bud_chainId","params":[],"id":1}"#.to_string();
    let out = Command::new("curl")
        .args([
            "-sf",
            "--max-time",
            "2",
            "-H",
            "Content-Type: application/json",
            "--data",
            &body,
            &format!("http://127.0.0.1:{port}"),
        ])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

fn wait_ready(port: u16, child: &mut Child) -> Result<String, String> {
    for i in 0..60 {
        if let Some(resp) = rpc_chain_id(port) {
            if resp.contains("\"result\"") {
                return Ok(resp);
            }
            let _ = i;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("node exited early with {status}"));
        }
    }
    Err("timeout waiting for RPC".to_string())
}

pub fn run(args: &[std::ffi::OsString]) -> Result<String, String> {
    let root = std::env::current_dir().map_err(|e| e.to_string())?;
    let network = std::env::var("SMOKE_NETWORK").unwrap_or_else(|_| "devnet".to_string());
    let rpc_port: u16 = std::env::var("SMOKE_RPC_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(18546);
    let db_path = std::env::var("SMOKE_DB_PATH").unwrap_or_else(|_| "/tmp/budlum-smoke-db".to_string());
    let _ = args;

    let bin = find_bin(&root)?;
    let _ = fs::remove_dir_all(&db_path);
    fs::create_dir_all(format!("{db_path}/secrets")).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(&bin);
    cmd.args([
        "--network", &network,
        "--port", "0",
        "--rpc-public-listener", "127.0.0.1:18545",
        "--rpc-operator-listener", &format!("127.0.0.1:{rpc_port}"),
        "--db-path", &format!("{db_path}/chain"),
        "--snapshot-dir", &format!("{db_path}/snapshots"),
        "--p2p-identity-file", &format!("{db_path}/secrets/node-id.key"),
    ]);
    cmd.env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()));
    cmd.env("BUDLUM_RPC_AUTH_REQUIRED", std::env::var("BUDLUM_RPC_AUTH_REQUIRED").unwrap_or_else(|_| "0".to_string()));
    let log = fs::File::create(format!("{db_path}/node.log")).map_err(|e| e.to_string())?;
    cmd.stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?));
    cmd.stderr(Stdio::from(log));
    let mut child = cmd.spawn().map_err(|e| format!("spawn node: {e}"))?;

    let resp = match wait_ready(rpc_port, &mut child) {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill();
            return Err(format!("{e} (see {db_path}/node.log)"));
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    println!("[smoke] RPC response: {resp}");
    Ok(format!("[smoke] OK - bud_chainId responded on {network}"))
}
