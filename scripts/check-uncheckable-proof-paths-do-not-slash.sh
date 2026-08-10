#!/usr/bin/env bash
# ============================================================================
# check-uncheckable-proof-paths-do-not-slash.sh
#
# A verifier that cannot state what an honest proof looks like must not be
# wired to a penalty.
#
# Why this gate exists.
#
# `storage_challenge_expected_program_and_inputs` builds the public inputs a
# storage challenge proof is checked against. Three of them named values the
# AIR does not produce for the program it names:
#
#   * `initial_state_root` was given the storage root. Since the initial-image
#     commitment landed, that field is the fold of the memory and register
#     words a program reads before anything writes them. The program here
#     reads 65 words from the path buffer and two seeded registers; a storage
#     root is none of those.
#   * `event_digest` was given a keccak context digest. The AIR builds that
#     field by summing the `rs1` of every `Log` row, and the program has no
#     `Log`, so the only value it accepts is zero.
#   * `gas_used` was 0. `VerifyMerkle` costs 10.
#
# So `DefaultAdapter::verify` rejected every proof, including a correct one.
# That would be merely dead code, except the caller treats rejection as a
# wrong answer and slashes the operator's bond. An operator storing the bytes
# faithfully and answering correctly lost its bond, and the tests were green
# because every one of them passed `test-mock-proof`, which the production
# path short-circuits under `cfg!(test)`.
#
# Correcting the three fields is not enough and that is the part worth
# guarding. To state the commitment the verifier needs the 65 path words and
# the two seeded registers and it holds none of them, and `storage_root` is 32
# bytes while the VM's Merkle root is a single 64-bit field element with no
# conversion defined. Until the path is designed, the honest position is a
# flag that says so, and a penalty that does not fire on it.
#
# What the gate checks.
#
# 1. The flag exists and is a plain constant function, not something an
#    operator can switch on. Turning it on would turn on a verifier that
#    rejects honest work.
# 2. While it reports false, the verification arm it guards must be reachable
#    only through that guard: the `(Some, Some)` match arm has to test the flag
#    before running the adapter.
# 3. The carve-out must not swallow the case it was not written for. An answer
#    with no proof is a fact about the answer, so the no-proof arm must still
#    produce `Mismatched`.
# 4. There must be a test asserting each half, named here so it cannot be
#    quietly deleted.
#
# When the path is designed and the flag flips to true, this gate fails on
# check 1 and the next person has to come back and rewrite it deliberately.
# That is the intent: the flag is a debt marker, and the gate is the interest.
#
# Usage:
#   bash scripts/check-uncheckable-proof-paths-do-not-slash.sh              # gate
#   bash scripts/check-uncheckable-proof-paths-do-not-slash.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import re
import sys

root = sys.argv[1]
src_path = os.path.join(root, "src", "domain", "storage_deal.rs")

if not os.path.isfile(src_path):
    print(f"FAIL: no storage_deal.rs at {src_path}", file=sys.stderr)
    sys.exit(2)

src = open(src_path, encoding="utf-8").read()


def blank(text):
    return "".join("\n" if c == "\n" else " " for c in text)



def strip_rust_literals(text):
    # Tek gecisli Rust literal tarayicisi (Strix MEDIUM, CWE-184, PR #149
    # follow-up). Regex tabanli yaklasimlarin kokten siniri: ordinary string
    # icindeki bir `r` (onunde bosluk/noktalama olsa bile) raw-string
    # eslesmesini tetikleyip sonraki tirnaga kadar canli kodu silebiliyor.
    # Burada ordinary/byte string, char/byte char ve raw string (r#, br#,
    # hash sayisi eslesmesiyle) tek geciste, gercek Rust lexical kurallariyla
    # ayirt edilir; string'ler once komple blank'lendigi icin iclerindeki
    # hicbir bayt sonraki adimlari kandirmaz.
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "'":
            # Char literal (`'{'`, `'}'`, `'\\n'`) kapanis tirnagi olan
            # `'...'` desenidir; Rust lifetime `'a` kapanis tirnagi
            # OLMADIGI icin char sanilip gercek kodu yutmaz (Strix MEDIUM,
            # CWE-184, PR #149 follow-up).
            start = i
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2  # escape'li char: '\n', '\\', '\''
            else:
                j += 1
            if j < n and text[j] == "'":
                out.append(blank(text[start : j + 1]))
                i = j + 1
                continue
            out.append(text[i])
            i += 1
            continue
        if text[i] == '"' or (text[i] == 'b' and i + 1 < n and text[i + 1] == '"'):
            start = i
            i += 2 if text[i] == 'b' else 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            out.append(blank(text[start:i]))
            continue
        if text[i] == 'r' or (text[i] == 'b' and i + 1 < n and text[i + 1] == 'r'):
            start = i
            prefix = 2 if text[i] == 'b' else 1
            j = i + prefix
            while j < n and text[j] == '#':
                j += 1
            hashes = j - (i + prefix)
            if j < n and text[j] == '"' and (
                i == 0
                or text[i - 1]
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_\"'"
            ):
                closing = '"' + ('#' * hashes)
                end = j + 1
                while end < n:
                    if text.startswith(closing, end):
                        end += len(closing)
                        out.append(blank(text[start:end]))
                        i = end
                        break
                    end += 1
                else:
                    out.append(text[i])
                    i += 1
                continue
        out.append(text[i])
        i += 1
    return "".join(out)

def strip_block_comments(text):
    # Rust block comments nest (`/* outer /* inner */ tail */`); a flat
    # non-greedy regex stops at the first `*/` and leaves the tail looking
    # like executable code (Strix MEDIUM, deneme round 3 PR #280).
    out = []
    i = 0
    depth = 0
    n = len(text)
    while i < n:
        if i + 1 < n and text[i : i + 2] == "/*":
            depth += 1
            out.append("  ")
            i += 2
            continue
        if depth and i + 1 < n and text[i : i + 2] == "*/":
            depth -= 1
            out.append("  ")
            i += 2
            continue
        if depth:
            out.append("\n" if text[i] == "\n" else " ")
            i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


# Prose describing a rule must not satisfy a check about the rule: strip
# Rust literals (single-pass scanner), nested block comments and line
# comments (preserving line structure) so only live code can satisfy the
# gate (Strix MEDIUM, CWE-183/184, deneme round 3 PR #280; raw strings,
# string-embedded comment markers and in-string `r`: Strix MEDIUM, CWE-184,
# PR #149 follow-up).
#
# Strip order matters:
#   1. literals first via a single-pass Rust literal scanner (ordinary
#      byte strings and raw strings with matching hash count; Rust
#      char literals cannot contain gate patterns, and `'a` lifetime
#      markers must not be mistaken for char literals). A `/*` or `*/` *inside* a
#      string is data, not a comment, and an `r` inside a string must not
#      start a raw-string match, so literals are blanked before the comment
#      walks.
#   2. block comments with a depth counter (they nest in Rust).
#   3. line comments last - after literals and blocks are gone, a `//` can
#      only be a real line comment.
code = strip_rust_literals(src)
code = strip_block_comments(code)
code = re.sub(r"//[^\n]*", "", code)

problems = []
checked = 0

FLAG = "storage_challenge_proofs_are_checkable"

# 1. The flag exists and is a constant.
m = re.search(
    rf"fn\s+{FLAG}\s*\(\s*\)\s*->\s*bool\s*\{{\s*(true|false)\s*\}}",
    code,
)
if not m:
    problems.append(
        f"`{FLAG}` is missing or is no longer a plain constant. It gates whether "
        f"a storage challenge proof can be checked at all; if it became "
        f"configurable, an operator could switch on a verifier that rejects "
        f"honest work and slashes for it."
    )
else:
    checked += 1
    if m.group(1) == "true":
        problems.append(
            f"`{FLAG}` now reports true. If the path really can state an honest "
            f"proof, this gate and the two tests it names have to be rewritten "
            f"deliberately rather than left pointing at a rule that no longer "
            f"holds. That rewrite is the point of failing here."
        )

# 2. The verification arm is guarded by the flag.
guard = re.search(
    rf"\(Some\(_\),\s*Some\(_\)\)\s*if\s*!\s*Self::{FLAG}\(\)\s*=>\s*Ok\(\(\)\)",
    code,
)
if not guard:
    problems.append(
        f"the `(Some, Some)` arm of the verification match is not guarded by "
        f"`!Self::{FLAG}()`. Without that guard a proof-carrying answer reaches "
        f"a verifier that rejects everything, and the caller reads the rejection "
        f"as a wrong answer and takes the operator's bond."
    )
else:
    checked += 1
    # The guard must come before the arm that actually verifies, otherwise it
    # never runs.
    verify_arm = code.find("DefaultAdapter::verify")
    if verify_arm != -1 and guard.start() > verify_arm:
        problems.append(
            f"the `{FLAG}` guard appears after `DefaultAdapter::verify` is "
            f"reached, so it does not gate anything."
        )
    else:
        checked += 1

# 3. The no-proof arm still slashes.
if not re.search(r"\(Some\(_\),\s*None\)\s*=>\s*Err\(", code):
    problems.append(
        "the no-proof arm no longer returns `Err`. An answer with no proof is a "
        "fact about the answer rather than a limitation of the verifier, so it "
        "must still resolve as `Mismatched` and cost the bond. A carve-out that "
        "swallows this case makes every wrong answer free."
    )
else:
    checked += 1

# 4. Both halves are tested, by name.
REQUIRED_TESTS = [
    (
        "an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable",
        "the containment itself: a proof-carrying answer must not move the bond "
        "while the verifier cannot state an honest proof",
    ),
    (
        "the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof",
        "the boundary: an answer with no proof must still slash",
    ),
]
for name, why in REQUIRED_TESTS:
    if not re.search(rf"fn\s+{re.escape(name)}\s*\(", code):
        problems.append(f"the test `{name}` is gone. It holds {why}.")
    else:
        checked += 1

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(
    f"uncheckable-proof containment OK: {checked} checks, the storage challenge "
    f"verifier cannot slash on a rejection it cannot justify"
)
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/src/domain"
    printf '%s\n' "$body" >"$dir/src/domain/storage_deal.rs"
  }

  GOOD='    pub(crate) fn storage_challenge_proofs_are_checkable() -> bool {
        false
    }
        let verification: Result<(), StorageError> = match (deal.storage_root, proof_bytes) {
            (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),
            (Some(root), Some(proof)) => {
                Self::verify_answer_challenge_zk_proof_for_chain(&context, &root, &range_hash, proof)
            }
            (Some(_), None) => Err(StorageError::InvalidMerkleProof(
                "ZK proof is mandatory".into(),
            )),
            (None, _) => Ok(()),
        };
        bud_proof::DefaultAdapter::verify(&envelope, &expected_inputs, &program)
    fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {
    }
    fn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {
    }'

  # 1. The contained shape must pass, otherwise the gate is unusable.
  mk "$tmp/good" "$GOOD"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the contained tree was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: no flag at all, the verifier runs and slashes.
  mk "$tmp/noflag" '        let verification: Result<(), StorageError> = match (deal.storage_root, proof_bytes) {
            (Some(root), Some(proof)) => {
                Self::verify_answer_challenge_zk_proof_for_chain(&context, &root, &range_hash, proof)
            }
            (Some(_), None) => Err(StorageError::InvalidMerkleProof(
                "ZK proof is mandatory".into(),
            )),
            (None, _) => Ok(()),
        };
        bud_proof::DefaultAdapter::verify(&envelope, &expected_inputs, &program)
    fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {
    }
    fn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {
    }'
  if ( scan "$tmp/noflag" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unguarded verifier wired to a slash was accepted!" >&2
    exit 1
  fi

  # 3. The flag flipped to true without the rewrite.
  mk "$tmp/flagtrue" "$(printf '%s' "$GOOD" | sed 's/^        false$/        true/')"
  if ( scan "$tmp/flagtrue" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: the flag reporting true was accepted with no rewrite!" >&2
    exit 1
  fi

  # 4. The carve-out swallowing the no-proof case, which makes every wrong
  #    answer free.
  mk "$tmp/swallow" '    pub(crate) fn storage_challenge_proofs_are_checkable() -> bool {
        false
    }
        let verification: Result<(), StorageError> = match (deal.storage_root, proof_bytes) {
            (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),
            (Some(root), Some(proof)) => {
                Self::verify_answer_challenge_zk_proof_for_chain(&context, &root, &range_hash, proof)
            }
            (Some(_), None) => Ok(()),
            (None, _) => Ok(()),
        };
        bud_proof::DefaultAdapter::verify(&envelope, &expected_inputs, &program)
    fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {
    }
    fn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {
    }'
  if ( scan "$tmp/swallow" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a carve-out that also frees the no-proof case was accepted!" >&2
    exit 1
  fi

  # 5. A configurable flag: an operator could switch on a verifier that
  #    rejects honest work.
  mk "$tmp/configurable" '    pub(crate) fn storage_challenge_proofs_are_checkable() -> bool {
        std::env::var("BUDLUM_STORAGE_PROOFS").is_ok()
    }
        let verification: Result<(), StorageError> = match (deal.storage_root, proof_bytes) {
            (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),
            (Some(root), Some(proof)) => {
                Self::verify_answer_challenge_zk_proof_for_chain(&context, &root, &range_hash, proof)
            }
            (Some(_), None) => Err(StorageError::InvalidMerkleProof("x".into())),
            (None, _) => Ok(()),
        };
        bud_proof::DefaultAdapter::verify(&envelope, &expected_inputs, &program)
    fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {
    }
    fn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {
    }'
  if ( scan "$tmp/configurable" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a runtime-configurable flag was accepted!" >&2
    exit 1
  fi

  # 6. A deleted test must fail rather than pass for having nothing to check.
  mk "$tmp/notest" '    pub(crate) fn storage_challenge_proofs_are_checkable() -> bool {
        false
    }
        let verification: Result<(), StorageError> = match (deal.storage_root, proof_bytes) {
            (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),
            (Some(root), Some(proof)) => {
                Self::verify_answer_challenge_zk_proof_for_chain(&context, &root, &range_hash, proof)
            }
            (Some(_), None) => Err(StorageError::InvalidMerkleProof("x".into())),
            (None, _) => Ok(()),
        };
        bud_proof::DefaultAdapter::verify(&envelope, &expected_inputs, &program)
    fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {
    }'
  if ( scan "$tmp/notest" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing boundary test was accepted!" >&2
    exit 1
  fi

  # 7. Prose alone must not satisfy the checks.
  mk "$tmp/prose" '        // pub(crate) fn storage_challenge_proofs_are_checkable() -> bool { false }
        // (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),
        // (Some(_), None) => Err(StorageError::InvalidMerkleProof("x".into())),
        // fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {}
        // fn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {}'
  if ( scan "$tmp/prose" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: comments describing the rule satisfied the rule!" >&2
    exit 1
  fi

  # 8. A missing file must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no storage_deal.rs was accepted!" >&2
    exit 1
  fi

  # 9. A guard hidden in a raw string literal must not satisfy the checks.
  #    `r#"..."#` does not process escapes, so a flat string regex stops at
  #    the first quote and the tail looks like live code (Strix MEDIUM,
  #    CWE-184, PR #149 follow-up).
  mk "$tmp/rawstr" '        // pub(crate) fn storage_challenge_proofs_are_checkable() -> bool { false }
        let prose = r#"
            (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),
            fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {}
        "#;'
  if ( scan "$tmp/rawstr" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a guard hidden in a raw string literal was accepted!" >&2
    exit 1
  fi

  # 11. An ordinary string containing `r` (e.g. `let prose = "r";`) must not
  #     be mistaken for a raw-string start; the raw-string strip blanks only
  #     real `r`/`br` prefixes (lookbehind), so live code after such a string
  #     stays visible to the gate (Strix MEDIUM, CWE-184, PR #149 follow-up).
  mk "$tmp/rinstring" '        // pub(crate) fn storage_challenge_proofs_are_checkable() -> bool { false }
        let prose = " r";
        (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Err(StorageError::InvalidMerkleProof("x".into())),
        let tail = "(r";'
  if ( scan "$tmp/rinstring" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: code hidden after an ordinary string containing r was accepted!" >&2
    exit 1
  fi

  # 10. A `/*` or `*/` embedded inside an ordinary string literal must not
  #     make the block-comment walk treat following live code as comment
  #     tail. String literals are blanked before the depth counter, so a
  #     string carrying comment markers cannot hide a guard that must exist
  #     or hide code that must not exist (Strix MEDIUM, CWE-184, PR #149
  #     follow-up).
  mk "$tmp/strmarker" '        // pub(crate) fn storage_challenge_proofs_are_checkable() -> bool { false }
        let prose_a = "/* ";
        (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Err(StorageError::InvalidMerkleProof("x".into())),
        let prose_b = " */";'
  if ( scan "$tmp/strmarker" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: code hidden by comment markers inside strings was accepted!" >&2
    exit 1
  fi

  echo "uncheckable-proof gate self-test OK: an unguarded verifier, a flag flipped to true, a carve-out that frees the no-proof case, a runtime-configurable flag, a deleted boundary test, comment-only prose, a raw-string-hidden guard, code hidden by comment markers inside strings, code hidden after an ordinary string containing r and a missing file are all rejected; the contained tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
