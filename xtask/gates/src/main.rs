//! Repository gates, in Rust.
//!
//! # Why this crate exists
//!
//! The gates were shell. Eighteen thousand lines of it across seventy-four
//! `scripts/check-*.sh`, each one deciding whether a commit is allowed onto
//! `main`. That places them inside the trust boundary, and shell is a poor
//! language to put there:
//!
//!   * A misspelt variable is an empty string, not an error, so a check can
//!     silently examine nothing and report OK. `set -u` catches the unset
//!     case and not the misspelt-but-assigned one.
//!   * `grep -q` answers "does this text appear", which is the wrong question
//!     often enough that it let a wrongly scaled rate and a stale factor
//!     through two separate gates on this branch alone. Both were found by
//!     recomputing outside the gate, not by the gate.
//!   * There is no type between a path, a count and a label, so a gate that
//!     compares the wrong two things compiles and runs.
//!   * The canaries were themselves shell, so a broken canary and a working
//!     one look the same from the outside.
//!
//! Rust removes the first and third by construction, and makes the second a
//! matter of writing the arithmetic out rather than grepping for its answer.
//!
//! # Shape
//!
//! One binary, one gate per module, each exposing `run` and `self_test`.
//! Both return `Result<String, String>`: the `Ok` side is what a passing gate
//! prints, the `Err` side is the finding. Nothing calls `process::exit` from
//! inside a gate, so a gate can be called from a test.
//!
//! # Migration
//!
//! The shell gates are being replaced one at a time, not in a single sweep. A
//! gate moves when its Rust version reproduces every canary the shell version
//! had, which is checked by `--self-test`. Until a gate has moved, its shell
//! script stays wired and authoritative; a half-ported gate that runs in
//! neither language would be worse than the shell it replaced.

use std::path::{Path, PathBuf};

mod gates {
    pub mod bns_names_are_safe_in_an_address_bar;
    pub mod capability_modules_are_wired;
    pub mod coding_audit_samples_the_relationship;
    pub mod content_encryption_is_declared_and_bound;
    pub mod economy_invariants;
    pub mod every_fuzz_target_is_run;
    pub mod fork_choice_gate;
    pub mod gov_slash_evidence_is_validator_only;
    pub mod governance_invariants;
    pub mod hash_inputs_are_length_prefixed;
    pub mod mermaid;
    pub mod named_tests;
    pub mod network_hardening_gate;
    pub mod no_new_shell_gates;
    pub mod node_classification_gate;
    pub mod poa_compliance_gate;
    pub mod security_scans_can_fail;
    pub mod self_derived_ids_cover_every_field;
    pub mod storage_provider_gate;
    pub mod suppressions_are_justified;
    pub mod tee_trust_boundary_is_structural;
    pub mod the_image_builds_what_the_manifest_declares;
    pub mod wire_fields_are_signed;
    pub mod workflows_produce_jobs;
    pub mod zero_address_sender_is_verified;
}

/// One gate, as the runner sees it.
type Run = fn(&Path) -> Result<String, String>;
/// A gate's log run: inspect the repo root plus a cargo test log path.
type RunLog = fn(&Path, &Path) -> Result<String, String>;
/// A gate's argumented run: the repo root plus whatever the caller passed.
type RunArgs = fn(&Path, &[&str]) -> Result<String, String>;

/// One gate, as the runner sees it.
struct Gate {
    /// Name used on the command line and in CI job names.
    name: &'static str,
    /// The shell script this replaced, so the two can be compared during the
    /// migration and the old one deleted with evidence rather than hope.
    replaces: Option<&'static str>,
    run: Run,
    /// Gates that read a cargo test log take the log path as a second
    /// argument; `run` stays a placeholder that explains the requirement.
    run_log: Option<RunLog>,
    /// Gates that take extra positional arguments (a log path, two roots,
    /// a flag) receive them here; `run` stays a placeholder that explains
    /// the requirement.
    run_args: Option<RunArgs>,
    self_test: fn() -> Result<String, String>,
}

const GATES: &[Gate] = &[
    Gate {
        name: "capability-wiring",
        replaces: Some("check-capability-modules-are-wired.sh"),
        run: gates::capability_modules_are_wired::run,
        run_log: None,
        run_args: None,
        self_test: gates::capability_modules_are_wired::self_test,
    },
    Gate {
        name: "coding-audit-samples-the-relationship",
        replaces: Some("check-coding-audit-samples-the-relationship.sh"),
        run: gates::coding_audit_samples_the_relationship::run,
        run_log: None,
        run_args: None,
        self_test: gates::coding_audit_samples_the_relationship::self_test,
    },
    Gate {
        name: "content-encryption-bound",
        replaces: Some("check-content-encryption-is-declared-and-bound.sh"),
        run: gates::content_encryption_is_declared_and_bound::run,
        run_log: None,
        run_args: None,
        self_test: gates::content_encryption_is_declared_and_bound::self_test,
    },
    Gate {
        name: "mermaid",
        replaces: None,
        run: gates::mermaid::run,
        run_log: None,
        run_args: None,
        self_test: gates::mermaid::self_test,
    },
    Gate {
        name: "bns-names",
        replaces: None,
        run: gates::bns_names_are_safe_in_an_address_bar::run,
        run_log: None,
        run_args: None,
        self_test: gates::bns_names_are_safe_in_an_address_bar::self_test,
    },
    Gate {
        name: "security-scans-can-fail",
        replaces: None,
        run: gates::security_scans_can_fail::run,
        run_log: None,
        run_args: None,
        self_test: gates::security_scans_can_fail::self_test,
    },
    Gate {
        name: "self-derived-ids-cover-every-field",
        replaces: Some("check-self-derived-ids-cover-every-field.sh"),
        run: gates::self_derived_ids_cover_every_field::run,
        run_log: None,
        run_args: None,
        self_test: gates::self_derived_ids_cover_every_field::self_test,
    },
    Gate {
        name: "suppressions-are-justified",
        replaces: None,
        run: gates::suppressions_are_justified::run,
        run_log: None,
        run_args: None,
        self_test: gates::suppressions_are_justified::self_test,
    },
    Gate {
        name: "workflows-produce-jobs",
        replaces: None,
        run: gates::workflows_produce_jobs::run,
        run_log: None,
        run_args: None,
        self_test: gates::workflows_produce_jobs::self_test,
    },
    Gate {
        name: "hash-inputs-length-prefixed",
        replaces: Some("check-hash-inputs-are-length-prefixed.sh"),
        run: gates::hash_inputs_are_length_prefixed::run,
        run_log: None,
        run_args: None,
        self_test: gates::hash_inputs_are_length_prefixed::self_test,
    },
    Gate {
        name: "wire-fields-are-signed",
        replaces: Some("check-wire-fields-are-signed.sh"),
        run: gates::wire_fields_are_signed::run,
        run_log: None,
        run_args: None,
        self_test: gates::wire_fields_are_signed::self_test,
    },
    Gate {
        name: "image-builds-the-manifest",
        replaces: None,
        run: gates::the_image_builds_what_the_manifest_declares::run,
        run_log: None,
        run_args: None,
        self_test: gates::the_image_builds_what_the_manifest_declares::self_test,
    },
    Gate {
        name: "every-fuzz-target-is-run",
        replaces: None,
        run: gates::every_fuzz_target_is_run::run,
        run_log: None,
        run_args: None,
        self_test: gates::every_fuzz_target_is_run::self_test,
    },
    Gate {
        name: "no-new-shell-gates",
        replaces: None,
        run: gates::no_new_shell_gates::run,
        run_log: None,
        run_args: None,
        self_test: gates::no_new_shell_gates::self_test,
    },
    Gate {
        name: "storage-provider",
        replaces: Some("check-storage-provider-gate.sh"),
        run: |_| {
            Err(String::from(
                "storage-provider reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::storage_provider_gate::run),
        run_args: None,
        self_test: gates::storage_provider_gate::self_test,
    },
    Gate {
        name: "fork-choice",
        replaces: Some("check-fork-choice-gate.sh"),
        run: |_| {
            Err(String::from(
                "fork-choice reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::fork_choice_gate::run),
        run_args: None,
        self_test: gates::fork_choice_gate::self_test,
    },
    Gate {
        name: "governance-invariants",
        replaces: Some("check-governance-invariants.sh"),
        run: |_| {
            Err(String::from(
                "governance-invariants reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::governance_invariants::run),
        run_args: None,
        self_test: gates::governance_invariants::self_test,
    },
    Gate {
        name: "poa-compliance",
        replaces: Some("check-poa-compliance-gate.sh"),
        run: |_| {
            Err(String::from(
                "poa-compliance reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::poa_compliance_gate::run),
        run_args: None,
        self_test: gates::poa_compliance_gate::self_test,
    },
    Gate {
        name: "economy-invariants",
        replaces: Some("check-economy-invariants.sh"),
        run: |_| {
            Err(String::from(
                "economy-invariants reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::economy_invariants::run),
        run_args: None,
        self_test: gates::economy_invariants::self_test,
    },
    Gate {
        name: "network-hardening",
        replaces: Some("check-network-hardening-gate.sh"),
        run: |_| {
            Err(String::from(
                "network-hardening reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::network_hardening_gate::run),
        run_args: None,
        self_test: gates::network_hardening_gate::self_test,
    },
    Gate {
        name: "node-classification",
        replaces: Some("check-node-classification-gate.sh"),
        run: |_| {
            Err(String::from(
                "node-classification reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::node_classification_gate::run),
        run_args: None,
        self_test: gates::node_classification_gate::self_test,
    },
    Gate {
        name: "zero-address-sender-verified",
        replaces: None,
        run: gates::zero_address_sender_is_verified::run,
        run_log: None,
        run_args: None,
        self_test: gates::zero_address_sender_is_verified::self_test,
    },
    Gate {
        name: "tee-trust-boundary-structural",
        replaces: None,
        run: gates::tee_trust_boundary_is_structural::run,
        run_log: None,
        run_args: None,
        self_test: gates::tee_trust_boundary_is_structural::self_test,
    },
    Gate {
        name: "gov-slash-evidence-validator-only",
        replaces: None,
        run: gates::gov_slash_evidence_is_validator_only::run,
        run_log: None,
        run_args: None,
        self_test: gates::gov_slash_evidence_is_validator_only::self_test,
    },
];

fn usage() -> String {
    let mut s = String::from(
        "usage:\n  \
         budlum-gates <gate>              run one gate\n  \
         budlum-gates <gate> --self-test  run one gate's canaries\n  \
         budlum-gates --all               run every gate\n  \
         budlum-gates --all --self-test   run every canary\n  \
         budlum-gates --list              name every gate\n\n\
         gates:\n",
    );
    for g in GATES {
        s.push_str("  ");
        s.push_str(g.name);
        if let Some(r) = g.replaces {
            s.push_str("  (replaces ");
            s.push_str(r);
            s.push(')');
        }
        s.push('\n');
    }
    s
}

/// Where the repository root is.
///
/// `BUDLUM_ROOT` wins so a canary can point the gate at a staged copy. The
/// fallback walks up from the binary's own directory rather than trusting the
/// current directory, because CI does not always run from the root.
fn repo_root() -> PathBuf {
    if let Ok(r) = std::env::var("BUDLUM_ROOT") {
        return PathBuf::from(r);
    }
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if dir.join("ARCHITECTURE.md").is_file() && dir.join("Cargo.toml").is_file() {
            return dir;
        }
        if !dir.pop() {
            return PathBuf::from(".");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let self_test = refs.contains(&"--self-test");
    let root = repo_root();

    let selected: Vec<&Gate> = match refs.first() {
        None => {
            eprint!("{}", usage());
            std::process::exit(2);
        }
        Some(&"--list") => {
            for g in GATES {
                println!("{}", g.name);
            }
            return;
        }
        // `--all` and a bare `--self-test` both mean every gate; the flag was
        // already read above, so the two arms are one. Gates that take a log
        // path or positional roots are left out: they cannot run without
        // their argument, and their CI steps call them directly.
        Some(&"--all" | &"--self-test") => GATES
            .iter()
            .filter(|g| g.run_log.is_none() && g.run_args.is_none())
            .collect(),
        Some(name) => {
            if let Some(g) = GATES.iter().find(|g| g.name == *name) {
                vec![g]
            } else {
                eprintln!("FAIL: no gate named `{name}`.\n");
                eprint!("{}", usage());
                std::process::exit(2);
            }
        }
    };

    let mut failed = 0usize;
    for g in selected {
        let outcome = if self_test {
            (g.self_test)()
        } else if let Some(run_args) = g.run_args {
            (run_args)(&root, &refs[1..])
        } else if let (Some(run_log), Some(log)) = (g.run_log, refs.get(1)) {
            run_log(&root, Path::new(log))
        } else {
            (g.run)(&root)
        };
        match outcome {
            Ok(msg) => println!("{msg}"),
            Err(msg) => {
                eprintln!("FAIL [{}]: {msg}", g.name);
                failed += 1;
            }
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
}
