//! Repository tooling previously implemented as shell/python scripts.
//!
//! The workspace moved every security-relevant *gate* into Rust (`xtask/gates`).
//! The remaining operational scripts (SBOM generation, dependency audit,
//! coverage reporting, genesis-schema checks) are the same class of thing:
//! if they are written in shell they are not type-checked, are re-implemented
//! differently on every machine, and drift. This binary is their Rust home.
//!
//! `unsafe` is forbidden; the crate has a single small dependency set.

use std::path::Path;
use std::process::ExitCode;

mod cmd {
    pub mod audit_deps;
    pub mod backup_restore;
    pub mod clippy_extra;
    pub mod coverage;
    pub mod devnet_multinode;
    pub mod docker_smoke;
    pub mod genesis_schema;
    pub mod module_coverage;
    pub mod pre_push;
    pub mod run_nodes;
    pub mod sbom;
    pub mod smoke;
    pub mod zkvm_seed;
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("budlum-tools: expected a subcommand (see --help)");
        return ExitCode::FAILURE;
    }
    let name = args.remove(0).to_string_lossy().into_owned();
    let result = match name.as_str() {
        "--help" | "-h" => {
            println!("budlum-tools <cmd>");
            println!("  sbom             generate CycloneDX SBOM");
            println!("  audit-deps       run cargo audit");
            println!("  coverage         coverage report");
            println!("  genesis-schema   check genesis schema");
            println!("  pre-push         fmt + clippy pre-push check");
            println!("  zkvm-seed [dir]  (re)generate ZKVM seed corpus");
            println!("  module-coverage  module-level coverage (needs <path>)");
            println!("  clippy-extra     clippy ratchet report (needs <path>)");
            println!("  smoke            node boot smoke test");
            println!("  docker-smoke     docker mainnet smoke");
            println!("  devnet-multinode 4-node devnet smoke");
            println!("  backup-restore   backup/restore drill");
            println!("  run-nodes        local multi-node runner setup");
            println!("  --help           this help");
            return ExitCode::SUCCESS;
        }
        "sbom" => cmd::sbom::run(),
        "audit-deps" => cmd::audit_deps::run(),
        "coverage" => Ok(cmd::coverage::run()),
        "genesis-schema" => cmd::genesis_schema::run(),
        "genesis-schema-self-test" => cmd::genesis_schema::self_test(),
        "module-coverage-self-test" => cmd::module_coverage::self_test(),
        "pre-push" => cmd::pre_push::run(),
        "zkvm-seed" => cmd::zkvm_seed::run(&args),
        "smoke" => cmd::smoke::run(&args),
        "docker-smoke" => cmd::docker_smoke::run(),
        "devnet-multinode" => cmd::devnet_multinode::run(),
        "backup-restore" => cmd::backup_restore::run(),
        "run-nodes" => cmd::run_nodes::run(),
        "module-coverage" => {
            if args.is_empty() {
                Err("module-coverage requires a llvm-cov json path".to_string())
            } else {
                cmd::module_coverage::check_from_path(Path::new(&args[0]))
            }
        }
        "clippy-extra" => {
            if args.is_empty() {
                Err("clippy-extra requires a clippy json path".to_string())
            } else {
                Ok(cmd::clippy_extra::run_from_path(Path::new(&args[0]), 40))
            }
        }
        other => {
            eprintln!("budlum-tools: unknown subcommand `{other}`");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(msg) => {
            if !msg.is_empty() {
                println!("{msg}");
            }
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("budlum-tools: {msg}");
            ExitCode::FAILURE
        }
    }
}
