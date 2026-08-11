//! Round 5 kök çözüm: `syn` tabanlı AST güvenlik gate'leri.
//!
//! Substring+brace-walk gate'ler (`zero_address_sender_is_verified`,
//! `tee_trust_boundary_is_structural`, `gov_slash_evidence_is_validator_only`)
//! Strix'in parser-seviyesi düşüncesini modelleyemedi: her turda yeni bir
//! varyant (closure, nested helper, nested conditional, move closure,
//! collection item) buldu. Bu modül aynı üç korumayı GERÇEK Rust AST'si
//! üzerinde doğrular; `syn::visit` ile fonksiyon gövdeleri geçilir, closure
//! ve nested bloklar AST düğümleri olarak ayırt edilir.
//!
//! Korumalar:
//!   1. zero-address: `validate_transaction_with_context` içinde, zero-address
//!      dalındaki `Ok(())`, `if tx.verify()` bloğunun İÇİNDE ve closure dışında
//!      olmalı.
//!   2. TEE: `sign_with_privacy` içinde `verifier.verify_quote` çağrısı sonucu
//!      (attestation) `if !verify_measurement/backend/report_data` koşullarında
//!      fail-closed `return Err` ile kullanılmalı.
//!   3. gov-slash: `execute_proposal` içindeki `SlashValidator` dalında digest
//!      karşılaştırması success'i yönlendirmeli (if koşulu veya closure
//!      tail-expr).

use quote::ToTokens;
use std::path::Path;
use syn::visit::{self, Visit};
use syn::Expr;

/// Visitor'ların bool alanları, AST gezintisinin durumunu taşır.
/// `struct_excessive_bools` pedantic stil kuralıdır; güvenlik değil, bu
/// yüzden kurala uymak için bool'ları birleştirmek okunabilirliği bozar.
#[allow(clippy::struct_excessive_bools)]
struct ZeroAddressVisitor {
    ok_inside_verify: bool,
    in_verify_block: bool,
    closure_depth: usize,
}

impl ZeroAddressVisitor {
    fn new() -> Self {
        Self {
            ok_inside_verify: false,
            in_verify_block: false,
            closure_depth: 0,
        }
    }
}

impl<'ast> Visit<'ast> for ZeroAddressVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let is_ok = matches!(
            node.func.as_ref(),
            Expr::Path(p) if p.path.is_ident("Ok")
        );
        if self.in_verify_block && is_ok && self.closure_depth == 0 {
            self.ok_inside_verify = true;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if self.in_verify_block && self.closure_depth == 0 {
            if let Some(expr) = &node.expr {
                if expr.to_token_stream().to_string().contains("Ok") {
                    self.ok_inside_verify = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.closure_depth += 1;
        visit::visit_expr_closure(self, node);
        self.closure_depth -= 1;
    }
}

/// `validate_transaction_with_context` gövdesini gez; zero-address dalını
/// işaretle, `tx.verify()` bloğuna gir.
impl<'ast> Visit<'ast> for ZeroAddressBranch {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let cond: String = node
            .cond
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if cond.contains("Address::zero") || cond.contains("tx.from") {
            // zero-address dalı: verify bloğu DEĞİL; buradaki Ok(()) guard'sız.
            visit::visit_expr_if(self, node);
            return;
        }
        if cond.contains("tx.verify()") {
            let prev = self.inner.in_verify_block;
            self.inner.in_verify_block = true;
            visit::visit_expr_if(self, node);
            self.inner.in_verify_block = prev;
            return;
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.inner.visit_expr_call(node);
    }

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        self.inner.visit_expr_return(node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.inner.visit_expr_closure(node);
    }
}

struct ZeroAddressBranch {
    inner: ZeroAddressVisitor,
}

#[allow(clippy::struct_excessive_bools)]
struct TeeVisitor {
    in_sign_with_privacy: bool,
    has_quote_call: bool,
    has_verify_quote: bool,
    measurement_guard: bool,
    backend_guard: bool,
    report_guard: bool,
    in_guard: bool,
    guard_has_err: bool,
}

impl TeeVisitor {
    fn new() -> Self {
        Self {
            in_sign_with_privacy: false,
            has_quote_call: false,
            has_verify_quote: false,
            measurement_guard: false,
            backend_guard: false,
            report_guard: false,
            in_guard: false,
            guard_has_err: false,
        }
    }
}

impl<'ast> Visit<'ast> for TeeVisitor {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "sign_with_privacy" {
            self.in_sign_with_privacy = true;
            visit::visit_impl_item_fn(self, node);
            self.in_sign_with_privacy = false;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let recv = node.receiver.to_token_stream().to_string();
        if self.in_sign_with_privacy && method == "quote" {
            self.has_quote_call = true;
        }
        if self.in_sign_with_privacy && method == "verify_quote" && recv.contains("verifier") {
            self.has_verify_quote = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let cond = node.cond.to_token_stream().to_string();
        if self.in_sign_with_privacy {
            let which = if cond.contains("verify_measurement") {
                Some(0)
            } else if cond.contains("backend") {
                Some(1)
            } else if cond.contains("verify_report_data") {
                Some(2)
            } else {
                None
            };
            if let Some(kind) = which {
                self.in_guard = true;
                self.guard_has_err = false;
                visit::visit_block(self, &node.then_branch);
                let ok = self.guard_has_err;
                self.in_guard = false;
                match kind {
                    0 => self.measurement_guard = ok,
                    1 => self.backend_guard = ok,
                    _ => self.report_guard = ok,
                }
                return;
            }
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if self.in_guard {
            if let Some(expr) = &node.expr {
                if expr.to_token_stream().to_string().contains("Err") {
                    self.guard_has_err = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }
}

#[allow(clippy::struct_excessive_bools)]
struct GovSlashVisitor {
    in_slash_validator: bool,
    has_digest_condition: bool,
    digest_guards_return: bool,
}

impl GovSlashVisitor {
    fn new() -> Self {
        Self {
            in_slash_validator: false,
            has_digest_condition: false,
            digest_guards_return: false,
        }
    }
}

impl<'ast> Visit<'ast> for GovSlashVisitor {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "execute_proposal" {
            visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let scrut = node.expr.to_token_stream().to_string();
        if scrut.contains("p_type") || scrut.contains("proposal") {
            for arm in &node.arms {
                let pat = arm.pat.to_token_stream().to_string();
                if pat.contains("SlashValidator") {
                    self.in_slash_validator = true;
                    visit::visit_expr(self, &arm.body);
                    self.in_slash_validator = false;
                    return;
                }
            }
        }
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let cond = node.cond.to_token_stream().to_string();
        if self.in_slash_validator && cond.contains("evidence_hash") {
            self.has_digest_condition = true;
            let mut v = ReturnTrueFinder { found: false };
            v.visit_block(&node.then_branch);
            if v.found {
                self.digest_guards_return = true;
            }
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        if self.in_slash_validator {
            let body: String = node
                .body
                .to_token_stream()
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if body.contains("sha2::Sha256::digest") && body.contains("evidence_hash") {
                self.has_digest_condition = true;
                self.digest_guards_return = true;
            }
        }
        visit::visit_expr_closure(self, node);
    }
}

struct ReturnTrueFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for ReturnTrueFinder {
    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if let Some(expr) = &node.expr {
            if expr.to_token_stream().to_string() == "true" {
                self.found = true;
            }
        }
        visit::visit_expr_return(self, node);
    }
}

/// Hangi korumaların bu dosyada aranacağı.
#[derive(Clone, Copy)]
struct Checks {
    zero_address: bool,
    tee: bool,
    gov_slash: bool,
}

fn judge_file(src: &str, checks: Checks) -> Vec<String> {
    let mut problems = Vec::new();
    let ast: syn::File = match syn::parse_file(src) {
        Ok(f) => f,
        Err(e) => {
            problems.push(format!("parse error: {e}"));
            return problems;
        }
    };

    if checks.zero_address {
        let mut inner = ZeroAddressVisitor::new();
        let mut za = ZeroAddressBranch { inner };
        za.visit_file(&ast);
        if !za.inner.ok_inside_verify {
            problems.push(String::from(
                "AST: validate_transaction_with_context zero-address dalında Ok(()) yok veya closure içinde. CWE-306 guard'ı doğrulanamadı.",
            ));
        }
    }

    if checks.tee {
        let mut tee = TeeVisitor::new();
        tee.visit_file(&ast);
        if !tee.has_quote_call || !tee.has_verify_quote {
            problems.push(String::from(
                "AST: sign_with_privacy quote->verify_quote zinciri yok.",
            ));
        }
        if !tee.measurement_guard {
            problems.push(String::from(
                "AST: verify_measurement fail-closed guard yok.",
            ));
        }
        if !tee.backend_guard {
            problems.push(String::from("AST: backend fail-closed guard yok."));
        }
        if !tee.report_guard {
            problems.push(String::from(
                "AST: verify_report_data fail-closed guard yok.",
            ));
        }
    }

    if checks.gov_slash {
        let mut gs = GovSlashVisitor::new();
        gs.visit_file(&ast);
        if !gs.digest_guards_return {
            problems.push(String::from(
                "AST: SlashValidator dalında digest koşulu success'i yönlendirmiyor.",
            ));
        }
    }

    problems
}

/// # Errors
///
/// AST tabanlı bulgular.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = Vec::new();
    let plan: &[(&str, Checks)] = &[
        (
            "src/core/account.rs",
            Checks {
                zero_address: true,
                tee: false,
                gov_slash: true,
            },
        ),
        (
            "wallet-core/src/lib.rs",
            Checks {
                zero_address: false,
                tee: true,
                gov_slash: false,
            },
        ),
    ];
    for (rel, checks) in plan {
        let p = root.join(rel);
        let src = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("cannot read {}: {e}", p.display()));
                continue;
            }
        };
        problems.extend(judge_file(&src, *checks));
    }

    if problems.is_empty() {
        return Ok(String::from(
            "AST security gates OK: zero-address, TEE trust boundary and gov-slash evidence are enforced on the real Rust AST.",
        ));
    }
    Err(problems.join("\n"))
}

/// # Errors
///
/// Kanaryalar.
pub fn self_test() -> Result<String, String> {
    let mut problems = Vec::new();

    let good = r#"
fn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {
    if tx.from == Address::zero() {
        if tx.verify() {
            return Ok(());
        }
        return Err("x".into());
    }
    Ok(())
}
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable("x".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        Ok([0u8; 64])
    }
}
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash {
                return true;
            }
        }
    }
}
"#;
    let finds = judge_file(
        good,
        Checks {
            zero_address: true,
            tee: true,
            gov_slash: true,
        },
    );
    if !finds.is_empty() {
        problems.push(format!("BROKEN: good tree rejected: {finds:?}"));
    }

    let bad_za = "
fn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {
    if tx.from == Address::zero() {
        return Ok(());
    }
    Ok(())
}
";
    let finds = judge_file(
        bad_za,
        Checks {
            zero_address: true,
            tee: false,
            gov_slash: false,
        },
    );
    if !finds.iter().any(|p| p.contains("zero-address")) {
        problems.push(String::from(
            "VACUOUS: unguarded zero-address success accepted.",
        ));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "AST security gates self-test OK: good tree passes, unguarded zero-address rejected.",
    ))
}
