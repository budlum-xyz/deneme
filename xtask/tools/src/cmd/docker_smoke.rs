//! Docker mainnet smoke (port of scripts/docker-smoke-mainnet.sh).

use std::process::Command;

fn rpc(port: u16, method: &str, params: &str) -> Option<String> {
    let body = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{params},"id":1}}"#);
    let out = Command::new("curl")
        .args(["-sf", "--max-time", "5", "-H", "Content-Type: application/json", "--data", &body, &format!("http://localhost:{port}")])
        .output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

fn chain_id_from(resp: &str) -> Option<String> {
    // result may be a number, hex string, or null
    let trimmed = resp.trim();
    if let Some(s) = trimmed.strip_prefix("\"result\":") {
        let v: serde_json::Value = serde_json::from_str(s).ok()?;
        v.as_str().map(std::string::ToString::to_string).or_else(|| v.as_number().map(std::string::ToString::to_string))
    } else {
        None
    }
}

pub fn run() -> Result<String, String> {
    let rpc_port = std::env::var("SMOKE_RPC_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8545);
    let image = "budlum-mainnet-smoke";
    let container = "budlum-smoke-run";

    let _ = Command::new("docker").args(["rm", "-f", container]).status();
    let build = Command::new("docker").args(["build", "-t", image, "."]).status().map_err(|e| e.to_string())?;
    if !build.success() {
        return Err("docker build failed".to_string());
    }

    let mut ok = false;
    // Try mainnet, then devnet fallback.
    for attempt in 0..2 {
        let _ = Command::new("docker").args(["rm", "-f", container]).status();
        let mut cmd = Command::new("docker");
        cmd.args(["run", "-d", "--name", container, "-p", &format!("127.0.0.1:{rpc_port}:{rpc_port}"), image]);
        if attempt == 0 {
            cmd.args(["--network", "mainnet", "--port", &rpc_port.to_string()]);
        } else {
            cmd.args(["-e", "BUDLUM_RPC_AUTH_REQUIRED=0", "-e", "BUDLUM_RPC_ALLOWED_IPS="]);
        }
        let run = cmd.status().map_err(|e| e.to_string())?;
        if !run.success() {
            continue;
        }
        for _ in 0..60 {
            if let Some(resp) = rpc(rpc_port, "bud_chainId", "[]") {
                if let Some(cid) = chain_id_from(&resp) {
                    println!("[docker-smoke] Connected! Chain ID: {cid}");
                    if cid != "1337" && cid != "null" {
                        println!("[docker-smoke] OK: Responded with Chain ID {cid}");
                    } else {
                        println!("[docker-smoke] WARNING: Default Chain ID (1337) detected.");
                    }
                    ok = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        if ok {
            break;
        }
    }
    if !ok {
        return Err("docker-smoke: timeout waiting for RPC".to_string());
    }

    // Genesis hash.
    if let Some(resp) = rpc(rpc_port, "bud_getBlockByNumber", "[0]") {
        let hash: Option<String> = resp
            .find("\"hash\":")
            .and_then(|idx| {
                let rest = &resp[idx..];
                let v: serde_json::Value = serde_json::from_str(&rest[7..]).ok()?;
                v.as_str().map(std::string::ToString::to_string)
            });
        match hash {
            Some(h) if !h.is_empty() && h != "null" => println!("[docker-smoke] Genesis Hash: {h}"),
            _ => return Err("[docker-smoke] ERROR: Could not retrieve Genesis Hash".to_string()),
        }
    } else {
        return Err("[docker-smoke] ERROR: Could not retrieve Genesis Hash".to_string());
    }
    let _ = Command::new("docker").args(["rm", "-f", container]).status();
    Ok("[docker-smoke] SUCCESS: Budlum Mainnet container is operational.".to_string())
}
