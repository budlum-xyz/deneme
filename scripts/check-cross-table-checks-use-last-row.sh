#!/usr/bin/env bash
# ============================================================================
# check-cross-table-checks-use-last-row.sh
#
# A constraint that reads a side table must fire on the last row, not on the
# last CPU row.
#
# Why this gate exists.
#
# The AIR packs several tables into one matrix. The CPU table has one row per
# executed step. The register table has one row per register event, three per
# step. The memory table has one row per memory event. They share a row index
# and nothing keeps them the same length.
#
# "The last CPU row" is written `when(is_halt).when(cpu_active)`, and it is the
# right place for anything built out of CPU columns: gas, exit code, the final
# state root. It is the wrong place for anything built out of a side table,
# because that table may still be mid-fold when the CPU side reaches its Halt.
#
# This already happened once. The register image accumulator was checked on the
# last CPU row, and since one step contributes three register events the
# register table outruns the CPU table on every program. Four honest proofs
# stopped verifying and CI caught it as `d2_proves_nullifier_check_invalid_secret`
# plus three `proves_verify_merkle_valid_*`. The fix was `when_last_row`.
#
# The memory image accumulator had the identical shape and did not fail,
# because no opcode currently produces two memory events in one step: four
# opcodes set `memory_addr` on their step and six push an extra event from the
# stack or storage buffers, and the two sets do not intersect. So `n_mem` is at
# most `n_cpu` and the fold happens to be finished in time. That is a fact
# about today's opcode table, not something the AIR states, and the first
# opcode that pairs a memory access with a stack push breaks it silently, in a
# constraint nobody was editing.
#
# What the gate checks.
#
# For each accumulator column that belongs to a side table, the constraint
# binding it to a public input must use `when_last_row`, and must not be gated
# on `is_halt` or `cpu_active`. The columns are listed explicitly: a regex that
# tried to discover "every column not in the CPU block" would sweep in the
# selectors and the decode columns, which are CPU columns and are correctly
# checked on the last CPU row.
#
# The gate deliberately does not ban `when(is_halt)` outright. Most of its uses
# are correct and banning them would train the next reader to route around the
# gate.
#
# Usage:
#   bash scripts/check-cross-table-checks-use-last-row.sh              # gate
#   bash scripts/check-cross-table-checks-use-last-row.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import re
import sys

root = sys.argv[1]
air = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_air.rs")

if not os.path.isfile(air):
    print(f"FAIL: no AIR at {air}", file=sys.stderr)
    sys.exit(2)

src = open(air, encoding="utf-8").read()

# Accumulator columns that live on a side table. Each is folded across that
# table's rows, so the finished value is only guaranteed on the very last row
# of the matrix.
SIDE_TABLE_ACCUMULATORS = [
    ("COL_MEM_INIT_ACC", "the memory table"),
    ("COL_REG_INIT_ACC", "the register table"),
]

problems = []
checked = 0


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
    # like executable code, so a binding hidden in the tail of a nested
    # comment could satisfy the gate (Strix MEDIUM, CWE-184, PR #149
    # follow-up). Walk with a depth counter instead.
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


for column, table in SIDE_TABLE_ACCUMULATORS:
    if column not in src:
        problems.append(
            f"{column} is gone from the AIR. If the accumulator was removed the "
            f"entry here should go with it, in the same commit, with the reason."
        )
        continue

    # Find the block that binds this accumulator to a public input. The
    # binding reads the column into a local and compares it against
    # `public_inputs[..]`, so look for the brace-delimited block containing
    # both. Work on a comment- and literal-stripped view first so a
    # commented-out or quoted block cannot be mistaken for the real binding
    # (Strix HIGH, CWE-184, deneme round 3 PR #280).
    #
    # Strip order matters (Strix MEDIUM, CWE-184, PR #149 follow-up):
    #   1. literals first via a single-pass Rust literal scanner (ordinary,
    #      byte, char, raw with matching hash count). A `/*` or `*/` *inside*
    #      a string is data, not a comment, and an `r` inside a string must
    #      not start a raw-string match, so literals are blanked before the
    #      comment walks.
    #   2. block comments with a depth counter (they nest in Rust; a flat
    #      regex leaves the tail of a nested comment visible as fake code).
    #   3. line comments last - after literals and blocks are gone, a `//`
    #      can only be a real line comment.
    scrubbed = strip_rust_literals(src)
    scrubbed = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), scrubbed, flags=re.DOTALL)  # MUTATION: flat
    scrubbed = re.sub(
        r'//[^\n]*',
        lambda m: "\n" * m.group(0).count("\n"),
        scrubbed,
        flags=re.DOTALL,
    )
    blocks = []
    for m in re.finditer(
        rf"\{{[^{{}}]*{re.escape(column)}[^{{}}]*\}}", scrubbed, re.DOTALL
    ):
        body = m.group(0)
        if "public_inputs" in body:
            blocks.append((m.start(), body))

    if not blocks:
        problems.append(
            f"{column} is never compared against a public input, so the "
            f"accumulator is folded and then dropped. Either it binds "
            f"something or it should not exist."
        )
        continue

    for start, body in blocks:
        checked += 1
        line = src[:start].count("\n") + 1
        code = re.sub(r"//[^\n]*", "", body)

        if "when_last_row" not in code:
            problems.append(
                f"AIR line ~{line}: the binding for {column} does not use "
                f"`when_last_row`. {column.split('_')[1].lower()} lives on "
                f"{table}, whose length is not the CPU table's, so the fold "
                f"may still be running when the CPU side halts."
            )

        for gate in ("is_halt", "cpu_active"):
            if re.search(rf"\.when\(\s*{gate}", code):
                problems.append(
                    f"AIR line ~{line}: the binding for {column} is gated on "
                    f"`{gate}`, which names the last *CPU* row. {column} is "
                    f"folded across {table}; when that table is longer the "
                    f"accumulator is mid-fold there and honest proofs fail. "
                    f"This is what happened to the register image."
                )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(
    f"cross-table checks OK: {checked} side-table bindings, all on the last row"
)
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-proof/src"
    printf '%s\n' "$body" >"$dir/budzero/bud-proof/src/plonky3_air.rs"
  }

  GOOD='pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'

  # 1. The corrected shape must pass, otherwise the gate is unusable.
  mk "$tmp/good" "$GOOD"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected AIR was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: the memory binding gated on the last CPU row.
  mk "$tmp/halted" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/halted" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a side-table accumulator checked on the last CPU row was accepted!" >&2
    exit 1
  fi

  # 3. The register half regressing the same way. Both columns are covered,
  #    not just the one that happened to be wrong.
  mk "$tmp/regressed" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder
                .when(is_halt.clone())
                .assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/regressed" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: the register accumulator gated on is_halt was accepted!" >&2
    exit 1
  fi

  # 4. Belt and braces is still wrong: `when_last_row` present but the CPU
  #    gate left on top of it narrows the check to rows that are both.
  mk "$tmp/both" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder
                .when_last_row()
                .when(cpu_active.clone())
                .assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/both" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a last-row check narrowed by a CPU gate was accepted!" >&2
    exit 1
  fi

  # 5. An accumulator folded and never bound to anything is not a pass.
  mk "$tmp/unbound" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let nacc: AB::Expr = nxt[COL_MEM_INIT_ACC].into();
            builder.when_transition().assert_eq(nacc, acc);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/unbound" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an accumulator bound to nothing was accepted!" >&2
    exit 1
  fi

  # 6. A deleted column must fail rather than pass for having nothing to check.
  mk "$tmp/gone" 'pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/gone" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing accumulator column was accepted!" >&2
    exit 1
  fi

  # 7. A missing AIR must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no AIR was accepted!" >&2
    exit 1
  fi

  # 8. A binding hidden in the tail of a nested block comment must not
  #    satisfy the gate. Rust block comments nest, so `/* outer /* inner */`
  #    closes at the inner `*/` and a flat regex would leave the outer tail
  #    looking like live code; the depth counter must swallow the whole
  #    comment so the memory accumulator reads as unbound.
  mk "$tmp/nested" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        /* outer explanation
           /* inner note */
           {
               let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
               let expected = public_inputs[10].into();
               builder.when_last_row().assert_eq(acc_last, expected);
           }
        */
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/nested" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a binding hidden in a nested block comment was accepted!" >&2
    exit 1
  fi

  # 9. A binding hidden in a raw string literal must not satisfy the gate.
  #    `r#"..."#` does not process escapes, so a flat string regex stops at
  #    the first quote and the tail looks like live code; the raw-string
  #    strip must swallow the whole literal (Strix MEDIUM, CWE-184, PR #149
  #    follow-up).
  mk "$tmp/rawstr" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        let prose = r#"a binding hidden in prose:
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }
        "#;
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/rawstr" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a binding hidden in a raw string literal was accepted!" >&2
    exit 1
  fi

  # 11. An ordinary string containing `r` (e.g. `let prose = "r";`) must not
  #     be mistaken for a raw-string start; the raw-string strip blanks only
  #     real `r`/`br` prefixes (lookbehind), so live code after such a string
  #     stays visible to the gate (Strix MEDIUM, CWE-184, PR #149 follow-up).
  mk "$tmp/rinstring" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        let prose = " r";
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder.when(is_halt.clone()).when(cpu_active.clone()).assert_eq(acc_last, expected);
        }
        let tail = "(r";'
  if ( scan "$tmp/rinstring" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: code hidden after an ordinary string containing r was accepted!" >&2
    exit 1
  fi

  # 10. A `/*` or `*/` embedded inside an ordinary string literal must not
  #     make the block-comment walk treat following live code as comment
  #     tail. String literals are blanked before the depth counter, so a
  #     string carrying comment markers cannot hide the bad binding (Strix
  #     MEDIUM, CWE-184, PR #149 follow-up).
  mk "$tmp/strmarker" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        let prose_a = "/* ";
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder.when(is_halt.clone()).when(cpu_active.clone()).assert_eq(acc_last, expected);
        }
        let prose_b = " */";
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/strmarker" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a bad binding hidden by comment markers inside strings was accepted!" >&2
    exit 1
  fi

  echo "cross-table gate self-test OK: a memory accumulator on the last CPU row, a register accumulator on is_halt, a last-row check narrowed by a CPU gate, an unbound accumulator, a deleted column, a missing AIR, a binding hidden in a nested comment, a binding hidden in a raw string, a bad binding hidden by comment markers inside strings and code hidden after an ordinary string containing r are all rejected; the corrected tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
