//! Genesis JSON schema gate (port of `scripts/check_genesis_schema.py`).

use serde_json::Value;
use std::fs;

const REQUIRED_TOP: &[&str] = &[
    "chain_id",
    "allocations",
    "validators",
    "block_reward",
    "base_fee",
    "gas_schedule",
    "timestamp",
    "bud_tokenomics",
];

const GAS_KEYS: &[&str] = &[
    "base_fee",
    "gas_per_byte",
    "gas_per_signature",
    "transfer_gas",
    "stake_gas",
    "vote_gas",
    "contract_call_gas",
];

const TOKENOMICS_KEYS: &[&str] = &[
    "community",
    "liquidity",
    "ecosystem",
    "team",
    "burn_reserve",
    "epochs_per_year",
    "annual_burn_ratio_fixed",
    "team_cliff_epochs",
    "team_vesting_epochs",
    "tx_fee_burn_ratio_fixed",
    "block_reward",
    "validator_annual_yield_ratio_fixed",
    "slot_duration_secs",
    "epoch_length_slots",
];

/// bool is not a valid int for genesis fields.
fn is_int(v: &Value) -> bool {
    v.is_i64() || v.is_u64()
}

/// An integer that is zero or positive (bool excluded).
fn is_nonneg_int(v: &Value) -> bool {
    if let Some(i) = v.as_i64() {
        return i >= 0;
    }
    v.as_u64().is_some()
}

fn validate(g: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    let Some(obj) = g.as_object() else {
        return vec!["kok obje JSON object olmali".to_string()];
    };
    for k in REQUIRED_TOP {
        if !obj.contains_key(*k) {
            errs.push(format!("eksik zorunlu alan: {k}"));
        }
    }
    if !errs.is_empty() {
        return errs; // alanlar yoksa derin kontrol anlamsiz
    }
    for k in ["chain_id", "block_reward", "base_fee", "timestamp"] {
        if !is_int(&obj[k]) {
            errs.push(format!("{k}: tam sayi (int) olmali, bool/str degil"));
        }
    }
    if !obj["allocations"].is_array() {
        errs.push("allocations: liste olmali".to_string());
    }
    if !obj["validators"].is_array() {
        errs.push("validators: liste olmali".to_string());
    }
    if obj["gas_schedule"].is_object() {
        let gs = obj["gas_schedule"].as_object().unwrap();
        for k in GAS_KEYS {
            match gs.get(*k) {
                Some(v) if is_nonneg_int(v) => {}
                _ => errs.push(format!("gas_schedule.{k}: int >= 0 olmali")),
            }
        }
    } else {
        errs.push("gas_schedule: obje olmali".to_string());
    }
    if obj["bud_tokenomics"].is_object() {
        let tk = obj["bud_tokenomics"].as_object().unwrap();
        for k in TOKENOMICS_KEYS {
            match tk.get(*k) {
                Some(v) if is_nonneg_int(v) => {}
                _ => errs.push(format!("bud_tokenomics.{k}: int >= 0 olmali")),
            }
        }
    } else {
        errs.push("bud_tokenomics: obje olmali".to_string());
    }
    if is_int(&obj["chain_id"]) && obj["chain_id"].as_i64().unwrap_or(0) < 1 {
        errs.push("chain_id >= 1 olmali (mainnet=1)".to_string());
    }
    errs
}

fn load_genesis() -> Result<Value, String> {
    let root = std::env::current_dir().map_err(|e| e.to_string())?;
    let p = root.join("config/mainnet-genesis.json");
    let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("genesis parse: {e}"))
}

pub fn run() -> Result<String, String> {
    let genesis = load_genesis()?;
    let errs = validate(&genesis);
    if !errs.is_empty() {
        for e in &errs {
            println!("FAIL: {e}");
        }
        return Err(format!("{} kural ihlali", errs.len()));
    }
    Ok("OK: config/mainnet-genesis.json sema kapisini gecti.".to_string())
}

/// Canary: current genesis must pass; five injected defects must fail.
pub fn self_test() -> Result<String, String> {
    type Mutation = Box<dyn Fn(&mut Value)>;
    let good = load_genesis()?;
    if !validate(&good).is_empty() {
        return Err("BOZUK KAPI: mevcut genesis reddedildi!".to_string());
    }
    let variants: Vec<(&str, Mutation)> = vec![
        ("chain_id=0", Box::new(|g| {
            g.as_object_mut().unwrap().insert("chain_id".into(), Value::from(0));
        })),
        ("eksik alan", Box::new(|g| {
            g.as_object_mut().unwrap().remove("gas_schedule");
        })),
        ("str block_reward", Box::new(|g| {
            g.as_object_mut().unwrap().insert("block_reward".into(), Value::from("50"));
        })),
        ("bool chain_id", Box::new(|g| {
            g.as_object_mut().unwrap().insert("chain_id".into(), Value::Bool(true));
        })),
        ("negatif gas", Box::new(|g| {
            if let Some(v) = g.pointer_mut("/gas_schedule/transfer_gas") {
                *v = Value::from(-5);
            }
        })),
    ];
    for (name, mutation) in variants {
        let mut bad = good.clone();
        mutation(&mut bad);
        if validate(&bad).is_empty() {
            return Err(format!("VACUOUS GATE: '{name}' varyanti reddedilmedi!"));
        }
    }
    Ok("kanarya OK: 5 bozuk varyantin tamami reddedildi, mevcut genesis PASS.".to_string())
}
