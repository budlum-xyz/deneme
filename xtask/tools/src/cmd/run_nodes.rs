//! Local multi-node runner setup (port of `run_nodes.sh`).

use std::fs;

pub fn run() -> Result<String, String> {
    let _ = fs::remove_dir_all("./data/node1.db");
    let _ = fs::remove_dir_all("./data/node2.db");
    let _ = fs::remove_file("./data/validators.json");
    fs::create_dir_all("./data").map_err(|e| e.to_string())?;
    let validators = r#"{
  "validators": [
    "12D3KooWNode1ValidatorAddress12345"
  ]
}"#;
    fs::write("./data/validators.json", validators).map_err(|e| e.to_string())?;
    let msg = "\
=============================================
To run the validator node (Node 1):
cargo run -- --port 4001 --db-path ./data/node1.db --consensus poa --validators-file ./data/validators.json

To run the observer node (Node 2) syncing to Node 1:
cargo run -- --port 4002 --db-path ./data/node2.db --consensus poa --validators-file ./data/validators.json --dial /ip4/127.0.0.1/tcp/4001
=============================================";
    println!("{msg}");
    Ok("validators.json written".to_string())
}
