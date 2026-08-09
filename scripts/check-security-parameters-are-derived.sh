#!/usr/bin/env bash
# ============================================================================
# check-security-parameters-are-derived.sh
#
# The security parameters absorbed into the transcript must be read out of the
# FRI configuration, not written down a second time.
#
# Why this gate exists.
#
# The Fiat-Shamir transcript carries the degrees, the commitments and the
# public values. It did not carry the FRI parameters, and those are what decide
# what a proof is worth: `num_queries` and `log_blowup` set the soundness
# error, the proof-of-work bits set the grinding cost. Measured on the current
# configuration, `log_blowup = 3`, `num_queries = 100` and 16 grinding bits are
# roughly 316 bits of security. `num_queries = 1`, `log_blowup = 1` and no
# grinding is one bit, and produces a proof of exactly the same shape.
#
# Least Authority's audit of Plonky3 found this class directly: a challenger
# that absorbed neither the FRI config nor the polynomial degree let a prover
# tamper with unabsorbed data. Our degrees were already absorbed. The FRI
# parameters were not.
#
# `fiat_shamir_binding.rs` now requires both sides to absorb
# `security_parameters` before the first challenge. That test proves the
# absorption happens. It cannot prove the absorbed values are the real ones: a
# `security_parameters()` returning a hard-coded array, or a `build_config`
# writing the numbers out by hand next to the `FriParameters` literal, would
# satisfy it and bind nothing. Two sources of truth for one set of numbers is
# how they drift.
#
# What the gate checks.
#
# 1. The trait declares `security_parameters`, and both prover and verifier
#    absorb it before their first `sample_algebra_element`.
# 2. `build_config` builds the absorbed vector out of the `fri_params` binding
#    it hands to the PCS. Every entry must be a field read from that binding;
#    a bare integer literal in that vector is the drift this gate is named for.
# 3. Every field of the `FriParameters` literal that carries a number is
#    represented. A parameter that governs the proof but is left out of the
#    vector is unabsorbed, which is the original bug in miniature.
#
# Usage:
#   bash scripts/check-security-parameters-are-derived.sh              # gate
#   bash scripts/check-security-parameters-are-derived.sh --self-test  # canary
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
cfg = os.path.join(root, "budzero", "bud-proof", "src", "bud_stark", "config.rs")
prover = os.path.join(root, "budzero", "bud-proof", "src", "bud_stark", "prover.rs")
verifier = os.path.join(root, "budzero", "bud-proof", "src", "bud_stark", "verifier.rs")
build = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_prover.rs")

for path, what in ((cfg, "config"), (prover, "prover"), (verifier, "verifier"), (build, "build_config")):
    if not os.path.isfile(path):
        print(f"FAIL: no {what} at {path}", file=sys.stderr)
        sys.exit(2)

cfg_src = open(cfg, encoding="utf-8").read()
prover_src = open(prover, encoding="utf-8").read()
verifier_src = open(verifier, encoding="utf-8").read()
build_src = open(build, encoding="utf-8").read()

def blank(text):
    return "".join("\n" if c == "\n" else " " for c in text)


def strip_rust_raw_strings(text):
    # Delimiter-aware raw-string stripping. A raw string ends only at the
    # quote followed by the SAME hash run that opened it: `r##"..."##`.
    # A regex that accepts any hash count on the close (`"#+`) splits on
    # the first embedded quote whose tail happens to carry a hash, leaving
    # the rest of the literal looking like executable code (Strix MEDIUM,
    # CWE-180, PR #145 follow-up).
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("br", i) or text.startswith("rb", i):
            j = i + 2
        elif text.startswith("r", i):
            j = i + 1
        else:
            out.append(text[i])
            i += 1
            continue

        hash_start = j
        while j < n and text[j] == "#":
            j += 1
        if j >= n or text[j] != '"':
            out.append(text[i])
            i += 1
            continue

        hashes = text[hash_start:j]
        closing = '"' + hashes
        end = text.find(closing, j + 1)
        if end == -1:
            out.append(text[i])
            i += 1
            continue

        out.append(blank(text[i : end + len(closing)]))
        i = end + len(closing)

    return "".join(out)


def strip_rust_block_comments(text):
    # Rust block comments nest (`/* outer /* inner */ tail */`), so a flat
    # non-greedy regex stops at the first `*/` and leaves the tail of the
    # outer comment looking like executable code (Strix MEDIUM, CWE-180,
    # PR #145 follow-up). Walk the text with a depth counter instead.
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


def strip_comments(s):
    # Rust-aware sanitization: a string or character literal is inert
    # (never executed as code), so it must not be able to satisfy a
    # regex evidence check. A comment-only strip would let a contributor
    # hide `observe_slice(&config.security_parameters())` or
    # `new_with_security(0, security, ...)` inside a string literal and
    # keep the vulnerable implementation while the gate reports success
    # (Strix MEDIUM, CWE-180, PR #145 follow-up). Replace literals with
    # same-length spaces so line structure and ordering checks still
    # behave correctly; keep newlines inside block comments so line
    # numbers do not shift.
    s = re.sub(r"//[^\n]*", "", s)
    s = strip_rust_block_comments(s)
    # Raw strings first: `r"..."`, `r#"..."#`, `br#"..."#`. Inside a raw
    # string a quote is not special and only the closing quote plus the
    # same hash run ends it, so the ordinary string regex below would
    # split on an embedded quote and leave the tail looking like
    # executable code. The delimiter-aware scanner keeps the hash count
    # matched on both ends.
    s = strip_rust_raw_strings(s)
    # re.DOTALL matters here: a `\` line-continuation inside a string is
    # `\\.` with the dot spanning the newline. Without DOTALL the regex
    # cannot find the closing quote, swallows real code past the literal
    # and falsely blanks out executable statements (prover.rs multi-line
    # panic! strings hit this). PR #145 follow-up.
    s = re.sub(r'b?"(?:\\.|[^"\\])*"', lambda m: blank(m.group(0)), s, flags=re.DOTALL)
    s = re.sub(r"b?'(?:\\.|[^'\\])'", lambda m: blank(m.group(0)), s, flags=re.DOTALL)
    return s

problems = []
checked = 0

# 1. The trait must declare it, and both sides must absorb it before the
#    first challenge.
checked += 1
if not re.search(r"fn\s+security_parameters\s*\(&self\)", cfg_src):
    problems.append(
        "config.rs does not declare `security_parameters`, so the FRI "
        "parameters are outside the Fiat-Shamir transcript. num_queries and "
        "log_blowup set the soundness error and the proof-of-work bits set the "
        "grinding cost; a proof produced under weaker parameters has the same "
        "shape as one produced under the real ones."
    )

for src, name in ((prover_src, "prover"), (verifier_src, "verifier")):
    code = strip_comments(src)
    lines = code.split("\n")
    checked += 1
    stops = [i for i, l in enumerate(lines) if "sample_algebra_element()" in l]
    if not stops:
        problems.append(f"{name}.rs samples no challenge; this gate cannot place the absorption.")
        continue
    stop = stops[0]
    before = "\n".join(lines[:stop])
    if "security_parameters()" not in before:
        problems.append(
            f"{name}.rs does not absorb `security_parameters()` before its first "
            f"challenge. A parameter set the prover controls and the transcript "
            f"does not cover can be chosen after the challenge is drawn."
        )
    else:
        # A bare read is not absorption: `let _unused = security_parameters();`
        # leaves the parameters outside the transcript (Strix MEDIUM, deneme
        # round 2 PR #222). The value read must reach the challenger through
        # an observe call before the first challenge.
        # Find the line that calls security_parameters() and check that the
        # value it returns is what reaches the challenger. A bare `observe`
        # somewhere later is not enough: `let _unused = security_parameters();
        # challenger.observe(123u64);` would satisfy a presence check while
        # the FRI parameters stay outside the transcript (Strix MEDIUM,
        # CWE-345, PR #145 follow-up). The observe must carry either the
        # direct call or the binding the read was stored into.
        sec_line = next(i for i, l in enumerate(lines[:stop]) if "security_parameters()" in l)
        sec_stmt = lines[sec_line]
        after_sec = "\n".join(lines[sec_line:stop])
        bind_match = re.search(
            r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\b\s*=.*security_parameters\s*\(",
            sec_stmt,
        )
        direct_observed = (
            re.search(
                r"observe(?:_slice)?\s*\(\s*&?\s*(?:config\.)?security_parameters\s*\([^\n;]*\)\s*\)",
                after_sec,
            )
            is not None
        )
        bound_observed = False
        shadowed_before_observe = False
        if bind_match:
            binding = bind_match.group(1)
            # The binding must still refer to the derived value when it is
            # observed: a `let x = security_parameters(); let x = attacker;`
            # shadow lets an attacker-chosen value reach the challenger while
            # the identifier name matches (Strix MEDIUM, CWE-345, PR #145
            # follow-up).
            rest = after_sec[len(sec_stmt):]
            # Any rebinding before the observe is a shadow: a second `let`,
            # or a plain mutable assignment (`x = attacker;`), overwrites the
            # derived value while the identifier name still matches (Strix
            # MEDIUM, CWE-345, PR #145 follow-up).
            observe_match = re.search(
                rf"observe(?:_slice)?\s*\(\s*&?\s*{re.escape(binding)}\s*\)",
                after_sec,
            )
            before_observe = (
                after_sec[: observe_match.start()] if observe_match is not None else rest
            )
            shadowed_before_observe = (
                re.search(
                    rf"\blet\s+(?:mut\s+)?{re.escape(binding)}\b\s*=",
                    before_observe,
                )
                is not None
                or re.search(
                    rf"\b{re.escape(binding)}\b\s*=(?!=)",
                    before_observe,
                )
                is not None
            )
            bound_observed = observe_match is not None
        if (shadowed_before_observe and bound_observed) or not (
            direct_observed or bound_observed
        ):
            if shadowed_before_observe:
                problems.append(
                    f"{name}.rs shadows the `security_parameters()` binding "
                    f"before observing it, so an attacker-chosen value can "
                    f"reach the transcript while the identifier matches."
                )
            else:
                problems.append(
                    f"{name}.rs reads `security_parameters()` but never observes the "
                    f"value (or its binding) into the challenger before the first "
                    f"challenge. An unrelated observe call leaves the FRI parameters "
                    f"outside the transcript."
                )
            problems.append(
                f"{name}.rs reads `security_parameters()` but never observes the "
                f"value (or its binding) into the challenger before the first "
                f"challenge. An unrelated observe call leaves the FRI parameters "
                f"outside the transcript."
            )

# 2. The absorbed vector must be derived from the FriParameters binding.
m = re.search(
    r"let\s+fri_params\s*=\s*p3_fri::FriParameters\s*\{(.*?)\};", build_src, re.DOTALL
)
checked += 1
if not m:
    problems.append(
        "plonky3_prover.rs does not build a `fri_params` binding this gate can "
        "read. Either the configuration moved, in which case update the gate in "
        "the same commit, or there is no single place the FRI parameters are "
        "stated."
    )
else:
    fri_body = strip_comments(m.group(1))
    # Numeric fields of the literal, excluding the mmcs handle.
    fri_fields = set()
    for fm in re.finditer(r"(\w+)\s*:\s*([0-9]+)\s*,", fri_body):
        fri_fields.add(fm.group(1))

    sm = re.search(r"let\s+security\s*=\s*vec!\[(.*?)\];", build_src, re.DOTALL)
    if not sm:
        problems.append(
            "plonky3_prover.rs builds no `security` vector, so nothing states "
            "which parameters reach the transcript. Derive one from the "
            "`fri_params` binding."
        )
    else:
        sec_body = strip_comments(sm.group(1))

        # Every entry must read from fri_params, never be a literal.
        entries = [e.strip() for e in sec_body.split(",") if e.strip()]
        for e in entries:
            if re.fullmatch(r"[0-9]+\s*(as\s+u64)?", e):
                problems.append(
                    f"the absorbed security vector contains the literal `{e}` "
                    f"instead of reading the field from `fri_params`. A "
                    f"hand-written copy is a second source of truth and can "
                    f"drift from the parameters that actually govern the proof."
                )
            elif "fri_params." not in e:
                problems.append(
                    f"the absorbed security vector entry `{e}` does not read "
                    f"from `fri_params`, so this gate cannot tell that it "
                    f"describes the configuration in use."
                )

        # Every numeric FRI field must appear.
        for field in sorted(fri_fields):
            if f"fri_params.{field}" not in sec_body:
                problems.append(
                    f"`{field}` is set on the FRI parameters but is not absorbed "
                    f"into the transcript. A parameter that governs the proof "
                    f"and sits outside the transcript is the exact shape of the "
                    f"bug this binding was added for."
                )
        checked += len(fri_fields)

        # The derived `security` vector must be the one passed into the final
        # config; a discarded `let security = vec![...]` followed by a
        # different vector in `new_with_security` is a false positive
        # (Strix MEDIUM, deneme round 2 PR #222). A rebinding of `security`
        # after the derive is the same evasion with a shadow: reject it too
        # (Strix MEDIUM, CWE-345, PR #145 follow-up).
        config_tail = strip_comments(build_src[sm.end():])
        security_rebound = (
            re.search(r"\blet\s+(?:mut\s+)?security\b\s*=", config_tail)
            is not None
        )
        # `security` must be a bare argument: preceded by a comma (argument
        # separator), not by an opening paren. `new_with_security(pcs,
        # challenger, security)` matches; `mutate(security)` does not (Strix
        # MEDIUM, CWE-345, PR #145 follow-up).
        if security_rebound or not re.search(
            r"new_with_security\s*\([^;]*?,\s*&?\s*security\s*(?:,|\))",
            config_tail,
            re.DOTALL,
        ):
            problems.append(
                "the derived `security` vector is never passed into "
                "`new_with_security` (or is rebound first): the transcript "
                "absorbs one parameter set while the config is built from "
                "another."
            )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"security parameters OK: {checked} checks, every FRI field is derived and absorbed")
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" cfg="$2" pv="$3" build="$4"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-proof/src/bud_stark"
    printf '%s\n' "$cfg" >"$dir/budzero/bud-proof/src/bud_stark/config.rs"
    printf '%s\n' "$pv" >"$dir/budzero/bud-proof/src/bud_stark/prover.rs"
    printf '%s\n' "$pv" >"$dir/budzero/bud-proof/src/bud_stark/verifier.rs"
    printf '%s\n' "$build" >"$dir/budzero/bud-proof/src/plonky3_prover.rs"
  }

  GOOD_CFG='    fn security_parameters(&self) -> Vec<Val<Self>>;'
  GOOD_PV='    challenger.observe_slice(&config.security_parameters());
    let rand_1: SC::Challenge = challenger.sample_algebra_element();'
  GOOD_BUILD='    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let security = vec![
        fri_params.log_blowup as u64,
        fri_params.num_queries as u64,
        fri_params.commit_proof_of_work_bits as u64,
    ];
    StarkConfig::new_with_security(0, security, fri_params.mmcs.clone());'

  # 1. The corrected shape must pass.
  mk "$tmp/good" "$GOOD_CFG" "$GOOD_PV" "$GOOD_BUILD"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: nobody absorbs the parameters.
  mk "$tmp/noabsorb" "$GOOD_CFG" '    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ( scan "$tmp/noabsorb" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a transcript that never absorbs the parameters was accepted!" >&2
    exit 1
  fi

  # 3. Absorbed after the first challenge is the same bug with extra steps.
  mk "$tmp/late" "$GOOD_CFG" '    let rand_1: SC::Challenge = challenger.sample_algebra_element();
    challenger.observe_slice(&config.security_parameters());' "$GOOD_BUILD"
  if ( scan "$tmp/late" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: parameters absorbed after the challenge were accepted!" >&2
    exit 1
  fi

  # 4. Hand-written literals instead of reading the binding. This is the drift
  #    the gate is named for: it absorbs numbers, just not necessarily the
  #    ones in force.
  mk "$tmp/literal" "$GOOD_CFG" "$GOOD_PV" '    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let security = vec![3, 100, 16];'
  if ( scan "$tmp/literal" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: hand-written literals were accepted as the absorbed parameters!" >&2
    exit 1
  fi

  # 5. A FRI field that governs the proof but is left out of the vector.
  mk "$tmp/missing" "$GOOD_CFG" "$GOOD_PV" '    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let security = vec![
        fri_params.log_blowup as u64,
        fri_params.num_queries as u64,
    ];'
  if ( scan "$tmp/missing" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a FRI parameter left out of the transcript was accepted!" >&2
    exit 1
  fi

  # 6. The trait declaration removed: the binding is gone entirely.
  mk "$tmp/notrait" '    fn is_zk(&self) -> bool;' "$GOOD_PV" "$GOOD_BUILD"
  if ( scan "$tmp/notrait" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a config with no security_parameters declaration was accepted!" >&2
    exit 1
  fi

  # 7. Only one side absorbing. Prover and verifier must agree or the honest
  #    prover is the one that fails.
  rm -rf "$tmp/oneside"
  mkdir -p "$tmp/oneside/budzero/bud-proof/src/bud_stark"
  printf '%s\n' "$GOOD_CFG" >"$tmp/oneside/budzero/bud-proof/src/bud_stark/config.rs"
  printf '%s\n' "$GOOD_PV" >"$tmp/oneside/budzero/bud-proof/src/bud_stark/prover.rs"
  printf '%s\n' '    let rand_1: SC::Challenge = challenger.sample_algebra_element();' \
    >"$tmp/oneside/budzero/bud-proof/src/bud_stark/verifier.rs"
  printf '%s\n' "$GOOD_BUILD" >"$tmp/oneside/budzero/bud-proof/src/plonky3_prover.rs"
  if ( scan "$tmp/oneside" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: only the prover absorbing was accepted!" >&2
    exit 1
  fi

  # 8. A missing tree must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no sources was accepted!" >&2
    exit 1
  fi

  # 9. Inert string literals must not satisfy the gate (Strix MEDIUM,
  #    CWE-180, PR #145 follow-up). The text below contains the exact
  #    absorption call, but only as a string: no executable code performs
  #    the absorption.
  mk "$tmp/strlit" "$GOOD_CFG" '    let _doc = "challenger.observe_slice(&config.security_parameters());";
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ( scan "$tmp/strlit" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a string literal containing the absorption call was accepted as real code!" >&2
    exit 1
  fi

  # 10. The same trick against the whole build: the fri literal, the
  #     derived vector and the config wiring exist only inside a string.
  mk "$tmp/strlitbuild" "$GOOD_CFG" "$GOOD_PV" '    let _doc = "let fri_params = p3_fri::FriParameters { log_blowup: 3, num_queries: 100, commit_proof_of_work_bits: 16, mmcs: m }; let security = vec![1, 2, 3]; StarkConfig::new_with_security(0, security, m);";'
  if ( scan "$tmp/strlitbuild" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a string literal containing the config wiring was accepted as real code!" >&2
    exit 1
  fi

  # 11. A string literal sitting next to the real call must not disturb
  #     the gate: the executable absorption is still detected.
  mk "$tmp/strlitgood" "$GOOD_CFG" '    let _doc = "challenger.observe_slice(&config.security_parameters());";
    challenger.observe_slice(&config.security_parameters());
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ! ( scan "$tmp/strlitgood" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a real absorption next to a harmless string literal was rejected!" >&2
    exit 1
  fi

  # 12. Raw string literals must not satisfy the gate (Strix MEDIUM,
  #     CWE-180, PR #145 follow-up). A quote embedded inside a raw string
  #     used to split the ordinary string regex and leave the absorption
  #     text looking like executable code.
  mk "$tmp/rawstr" "$GOOD_CFG" '    let _doc = r#"quote: " challenger.observe_slice(&config.security_parameters())"#;
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ( scan "$tmp/rawstr" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a raw string literal containing the absorption call was accepted as real code!" >&2
    exit 1
  fi

  # 13. Hash-free raw string: r"..." must be blanked too.
  mk "$tmp/rawplain" "$GOOD_CFG" '    let _doc = r"challenger.observe_slice(&config.security_parameters())";
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ( scan "$tmp/rawplain" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a hash-free raw string literal was accepted as real code!" >&2
    exit 1
  fi

  # 14. Raw byte string carrying the whole build wiring inside.
  mk "$tmp/rawbuild" "$GOOD_CFG" "$GOOD_PV" '    let _doc = br#"let fri_params = p3_fri::FriParameters { log_blowup: 3, num_queries: 100, commit_proof_of_work_bits: 16, mmcs: m }; let security = vec![1, 2, 3]; StarkConfig::new_with_security(0, security, m);"#;'
  if ( scan "$tmp/rawbuild" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a raw byte string containing the config wiring was accepted as real code!" >&2
    exit 1
  fi

  # 15. A raw string sitting next to the real call must not disturb the
  #     gate: the executable absorption is still detected.
  mk "$tmp/rawgood" "$GOOD_CFG" '    let _doc = r#"the real absorption is on the next line"#;
    challenger.observe_slice(&config.security_parameters());
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ! ( scan "$tmp/rawgood" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a real absorption next to a raw string literal was rejected!" >&2
    exit 1
  fi

  # 16. Delimiter mismatch: a raw string whose closing hash run differs
  #     from the opening one must not be split at the first embedded
  #     quote-plus-hash (Strix MEDIUM, CWE-180, PR #145 follow-up).
  mk "$tmp/rawmismatch" "$GOOD_CFG" '    let _doc = r##"prefix "# challenger.observe_slice(&config.security_parameters()) "##;
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ( scan "$tmp/rawmismatch" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a raw string with mismatched hash delimiters was accepted as real code!" >&2
    exit 1
  fi

  # 17. Nested Rust block comments must not leave executable-looking tail
  #     text (Strix MEDIUM, CWE-180, PR #145 follow-up): `/* outer /*
  #     inner */ observe_slice(...) */` is one comment, all of it inert.
  mk "$tmp/nestedc" "$GOOD_CFG" '    /* outer /* inner */ challenger.observe_slice(&config.security_parameters()) */
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ( scan "$tmp/nestedc" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a nested block comment containing the absorption call was accepted as real code!" >&2
    exit 1
  fi

  # 18. A nested block comment next to the real call must not disturb the
  #     gate: the executable absorption is still detected.
  mk "$tmp/nestedgood" "$GOOD_CFG" '    /* outer /* inner */ harmless */
    challenger.observe_slice(&config.security_parameters());
    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ! ( scan "$tmp/nestedgood" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a real absorption next to a nested block comment was rejected!" >&2
    exit 1
  fi

  echo "security parameter gate self-test OK: no absorption, late absorption, hand-written literals, a missing FRI field, a removed trait method, one-sided absorption, a missing tree, inert string-literal lookalikes, a string next to the real call, raw string lookalikes, a raw string next to the real call, a mismatched-delimiter raw string, nested block comment lookalikes and a nested comment next to the real call are handled correctly; the derived tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
