//! 4-node devnet multinode smoke (port of scripts/devnet-multinode-smoke.sh).

use std::process::Command;

fn rpc(port: u16, method: &str) -> Option<serde_json::Value> {
    let body = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":[],"id":1}}"#);
    let out = Command::new("curl")
        .args(["-sf", "--max-time", "5", "-H", "Content-Type: application/json", "--data", &body, &format!("http://127.0.0.1:{port}")])
        .output().ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

fn hex_to_u64(v: &serde_json::Value) -> u64 {
    v.as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

pub fn run() -> Result<String, String> {
    let rpc_port = 8545u16;
    // [0/5] compose up
    println!("== [0/5] compose up (4 node + prometheus) ==");
    let st = Command::new("docker")
        .args(["compose", "-f", "docker-compose.yml", "-f", "docker-compose.ci.yml", "-p", "budlum-multinode-smoke", "up", "-d", "--build"])
        .status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err("compose up failed".to_string());
    }

    // [1/5] netListening
    println!("== [1/5] bud_netListening ==");
    for _ in 0..120 {
        if let Some(v) = rpc(rpc_port, "bud_netListening") {
            if v.get("result").is_some_and(|r| r.is_boolean() && r.as_bool() == Some(true)) {
                println!("PASS [1/5]: netListening true");
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // [2/5] peer mesh >= 3
    println!("== [2/5] peer mesh (bud_netPeerCount >= 3) ==");
    let mut ok = false;
    let mut peers = 0u64;
    for _ in 0..60 {
        if let Some(v) = rpc(rpc_port, "bud_netPeerCount") {
            peers = v.get("result").map_or(0, hex_to_u64);
            if peers >= 3 {
                ok = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    if !ok {
        return Err(format!("4-node P2P mesh kanıtı oluşmadı (peerCount={peers}, beklenen >= 3)"));
    }
    println!("PASS [2/5]: peer mesh ({peers} peer)");

    // [3/5] blockNumber increasing
    println!("== [3/5] konsensus liveness (bud_blockNumber artıyor) ==");
    let h1 = rpc(rpc_port, "bud_blockNumber").and_then(|v| v.get("result").cloned()).map_or(0, |r| hex_to_u64(&r));
    let mut inc = false;
    let mut h2 = h1;
    for _ in 0..4 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        if let Some(v) = rpc(rpc_port, "bud_blockNumber") {
            h2 = v.get("result").map_or(h2, hex_to_u64);
            if h2 > h1 {
                inc = true;
                break;
            }
        }
    }
    if !inc {
        return Err(format!("yükselti ilerlemiyor ({h1} -> {h2})"));
    }
    println!("PASS [3/5]: liveness ({h1} -> {h2})");

    // [4/5] /metrics
    println!("== [4/5] /metrics endpoint ==");
    let metrics = Command::new("curl").args(["-sf", "--max-time", "5", "http://127.0.0.1:9090/metrics"]).output().map_err(|e| e.to_string())?;
    if !metrics.status.success() {
        return Err("/metrics erişilemez (HTTP != 2xx)".to_string());
    }
    if metrics.stdout.is_empty() {
        return Err("/metrics boş gövde".to_string());
    }
    println!("PASS [4/5]: /metrics 2xx ({} satır)", String::from_utf8_lossy(&metrics.stdout).lines().count());

    // [5/5] operator RPC isolation
    println!("== [5/5] operator RPC izolasyonu (8546 hosttan kapalı olmalı) ==");
    let probe = Command::new("curl").args(["-s", "--max-time", "2", "http://127.0.0.1:8546"]).output().map_err(|e| e.to_string())?;
    if probe.status.success() {
        return Err("operator RPC 127.0.0.1:8546 hosttan erişilebilir - SIZMA".to_string());
    }
    println!("PASS [5/5]: operator RPC hosttan erişilemez");

    let _ = Command::new("docker").args(["compose", "-f", "docker-compose.yml", "-f", "docker-compose.ci.yml", "-p", "budlum-multinode-smoke", "down"]).status();
    Ok("DEVNET-MULTINODE-SMOKE: 5/5 PASS".to_string())
}
