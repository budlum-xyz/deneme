#!/usr/bin/env bash
# ============================================================================
# check-no-orphan-source-files.sh, a .rs file no `mod` declares is not code.
#
# src/network/proto_bridge.rs sat in the tree carrying:
#
#   use crate::consensus::pos::SlashingEvidence;
#   use crate::network::protocol::NetworkMessage;
#   use crate::{Block, BlockHeader, Transaction};
#
#   #[allow(clippy::all)]
#   pub mod pb {
#       include!(concat!(env!("OUT_DIR"), "/budlum.network.rs"));
#   }
#
# Nothing declared it. `mod proto_bridge;` appears in no file, so rustc never
# read it: not compiled, not linted, not covered, not counted. Its `pb` module
# was byte-identical to the one in proto_conversions.rs, which is the copy the
# tree actually uses.
#
# Why this matters beyond tidiness. An orphan file reads exactly like live
# code to a human: it has imports, it appears in grep results, it shows up in
# a review diff. Someone auditing the protobuf bridge could have read it,
# concluded something about the wire format, and been reasoning about a file
# the compiler had never seen. Worse, edits to it are silent -- a security fix
# applied to the wrong copy compiles fine and changes nothing.
#
# `cargo` itself will not complain: an unreferenced file is simply not part of
# the crate. Neither will clippy, nor dead-code analysis, nor coverage, since
# all of them work from what the compiler was given.
#
# Files under src/bin/ are exempt: Cargo auto-discovers them as binary targets
# without any `mod` declaration, which is the documented layout, not an
# accident.
#
# Usage:
#   bash scripts/check-no-orphan-source-files.sh              # gate
#   bash scripts/check-no-orphan-source-files.sh --self-test  # canary
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Roots to check. Each is a crate source tree where every .rs file should be
# reachable from a module declaration.
SCAN_ROOTS=(src budzero wallet-core)

scan() {
  local root="$1"
  [ -d "$root/src" ] || fail "no src directory at $root/src - wrong root?"

  python3 - "$root" "${SCAN_ROOTS[*]}" <<'PY'
import os, re, sys

root = sys.argv[1]
scan_roots = sys.argv[2].split()

# Cargo discovers these without a `mod` declaration.
def exempt(rel):
    parts = rel.replace(os.sep, '/').split('/')
    if os.path.basename(rel) in ('lib.rs', 'main.rs', 'mod.rs', 'build.rs'):
        return True
    # Cargo auto-discovers targets in these directories without any `mod`:
    #   <crate>/src/bin/*.rs   binaries
    #   <crate>/tests/*.rs     integration tests
    #   <crate>/benches/*.rs   benchmarks
    #   <crate>/examples/*.rs  examples
    # The first form sits under src/; the other three are siblings of it. An
    # earlier version of this rule only matched the src/ case and flagged four
    # perfectly ordinary budzero integration tests.
    for i, p in enumerate(parts[:-1]):
        if p == 'bin' and i > 0 and parts[i - 1] == 'src':
            return True
        if p in ('tests', 'benches', 'examples'):
            return True
    return False

MOD_DECL = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;', re.M)
# `mod NAME {` opens an inline module scope; declarations inside it resolve
# against the active lexical module path (Strix MEDIUM, CWE-706, PR #145
# follow-up).
MOD_INLINE = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*\{')
# `#[path = "..."] mod x;` points a module at an arbitrary file.
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')


def blank(text):
    return "".join("\n" if c == "\n" else " " for c in text)


def strip_rust_raw_strings(text):
    # Delimiter-aware raw-string stripping; identical to the security-
    # parameters gate so both gates agree on what is inert text.
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


def sanitize(text):
    # Blank out comments and literals (preserving line structure) so braces
    # and `mod` keywords inside them cannot perturb module scope tracking
    # (Strix MEDIUM, CWE-706, PR #145 follow-up).
    text = re.sub(r"//[^\n]*", "", text)
    text = strip_rust_block_comments(text)
    text = strip_rust_raw_strings(text)
    text = re.sub(r'b?"(?:\\.|[^"\\])*"', lambda m: blank(m.group(0)), text, flags=re.DOTALL)
    text = re.sub(r"b?'(?:\\.|[^'\\])'", lambda m: blank(m.group(0)), text, flags=re.DOTALL)
    return text


def iter_nested_mod_decls(text):
    """Yield (scope, name) for every `mod X;` declaration, tracking inline
    `mod Y { ... }` scopes lexically so a declaration resolves against the
    active module path. `mod outer { mod inner; }` yields inner with scope
    ('outer',), which names src/outer/inner.rs, not src/inner.rs (Strix
    MEDIUM, CWE-706, PR #145 follow-up)."""
    scope = []
    for line in sanitize(text).split("\n"):
        rest = line.strip()
        # A leading `}` closes the innermost open block scope.
        while rest.startswith("}"):
            if scope:
                scope.pop()
            rest = rest[1:].strip()
        im = MOD_INLINE.match(line)
        opens = rest.count("{")
        if im:
            scope.append(im.group(1))
            # The inline `mod X {` brace is the module scope itself.
            opens -= 1
        dm = MOD_DECL.match(line)
        if dm:
            yield tuple(scope), dm.group(1)
        # Balance braces that open later on the same line: non-module
        # blocks push a guard so their closing brace pops a guard, not a
        # module name.
        closes = rest.count("}")
        net = opens - closes
        if net > 0:
            for _ in range(net):
                scope.append(None)
        elif net < 0:
            for _ in range(-net):
                if scope:
                    scope.pop()

declared_paths = set()
path_targets = set()
files = []

for sub in scan_roots:
    base = os.path.join(root, sub)
    if not os.path.isdir(base):
        continue
    for dirpath, dirs, names in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ('target', '.git')]
        for name in names:
            if not name.endswith('.rs'):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            files.append((full, rel))
            text = open(full, encoding='utf-8', errors='replace').read()
            # Resolve `mod X;` to the concrete files it can name: X.rs and
            # X/mod.rs in the declaring module's effective directory.
            # Matching by path rather than by bare module name stops a
            # same-stemmed file in another directory from satisfying the
            # declaration (Strix MEDIUM, CWE-706, deneme round 2 PR #213).
            for scope, mod_name in iter_nested_mod_decls(text):
                # A `mod child;` declaration resolves relative to the
                # active lexical module path. `mod outer { mod inner; }`
                # inside src/lib.rs names src/outer/inner.rs, not
                # src/inner.rs (Strix MEDIUM, CWE-706, PR #145 follow-up).
                # `mod.rs`, `lib.rs` and `main.rs` are all crate roots:
                # children resolve next to them (`src/ast.rs`), while a child
                # of a non-root parent (`src/foo.rs`) resolves into a
                # directory named after the parent (`src/foo/child.rs`).
                if os.path.basename(full) in ('mod.rs', 'lib.rs', 'main.rs'):
                    module_dir = os.path.join(os.path.dirname(full), *scope)
                else:
                    module_dir = os.path.join(
                        os.path.dirname(full),
                        os.path.splitext(os.path.basename(full))[0],
                        *scope,
                    )
                for candidate in (
                    os.path.join(module_dir, mod_name + '.rs'),
                    os.path.join(module_dir, mod_name, 'mod.rs'),
                ):
                    declared_paths.add(os.path.normpath(candidate))
            for target in PATH_ATTR.findall(text):
                # `#[path = "..."]` is relative to the directory containing
                # the declaring file. Track the resolved concrete path, not
                # the basename stem: a same-stemmed file in another directory
                # must not count as declared (Strix MEDIUM, CWE-706, PR #145
                # follow-up).
                target_path = os.path.normpath(os.path.join(os.path.dirname(full), target))
                path_targets.add(target_path)

if not files:
    print("FAIL: no .rs files found - wrong root, the gate would be vacuous", file=sys.stderr)
    sys.exit(1)

orphans = []
for full, rel in files:
    if exempt(rel):
        continue
    abs_path = os.path.normpath(full)
    stem = os.path.basename(rel)[:-3]
    declared_here = abs_path in declared_paths or abs_path in path_targets
    if not declared_here:
        lines = sum(1 for _ in open(full, encoding='utf-8', errors='replace'))
        orphans.append(f"{rel}  ({lines} lines)")

if orphans:
    print("FAIL: these .rs files are declared by no `mod` and are not compiled:", file=sys.stderr)
    for o in sorted(orphans):
        print(f"  - {o}", file=sys.stderr)
    print(
        "\nrustc never reads them, so they are not linted, not covered and not tested,\n"
        "while reading exactly like live code in grep and in review. Declare the module\n"
        "or delete the file.",
        file=sys.stderr)
    sys.exit(1)

print(f"Orphan-file gate OK: all {len(files)} .rs files are reachable from a module declaration.")
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  # 1. The case that shipped: a file nothing declares.
  rm -rf "$tmp/orphan"; mkdir -p "$tmp/orphan/src"
  printf 'pub mod real;\n' > "$tmp/orphan/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/orphan/src/real.rs"
  printf 'pub fn ghost() {}\n' > "$tmp/orphan/src/proto_bridge.rs"
  if ( scan "$tmp/orphan" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a file no mod declares was accepted!" >&2
    exit 1
  fi

  # 2. A tree where everything is declared must pass.
  rm -rf "$tmp/good"; mkdir -p "$tmp/good/src"
  printf 'pub mod real;\n' > "$tmp/good/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/good/src/real.rs"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a fully declared tree was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    exit 1
  fi

  # 3. src/bin/*.rs is auto-discovered by Cargo and must not be flagged.
  rm -rf "$tmp/bin"; mkdir -p "$tmp/bin/src/bin"
  printf 'pub mod real;\n' > "$tmp/bin/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/bin/src/real.rs"
  printf 'fn main() {}\n' > "$tmp/bin/src/bin/tool.rs"
  if ! ( scan "$tmp/bin" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: src/bin/*.rs was flagged as an orphan!" >&2
    exit 1
  fi

  # 4. A nested module declared from its parent must pass.
  rm -rf "$tmp/nested"; mkdir -p "$tmp/nested/src/deep"
  printf 'pub mod deep;\n' > "$tmp/nested/src/lib.rs"
  printf 'pub mod inner;\n' > "$tmp/nested/src/deep/mod.rs"
  printf 'pub fn a() {}\n' > "$tmp/nested/src/deep/inner.rs"
  if ! ( scan "$tmp/nested" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a nested declared module was flagged!" >&2
    exit 1
  fi

  # 5. `#[path = "..."]` reaches a file that no plain `mod name;` names.
  rm -rf "$tmp/pathattr"; mkdir -p "$tmp/pathattr/src"
  printf '#[path = "renamed.rs"]\npub mod alias;\n' > "$tmp/pathattr/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/pathattr/src/renamed.rs"
  if ! ( scan "$tmp/pathattr" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a #[path]-attached file was flagged as an orphan!" >&2
    exit 1
  fi

  # 6. A missing src must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no src was accepted!" >&2
    exit 1
  fi

  # 7. Inline nested modules resolve against the lexical module path:
  #    `mod outer { mod inner; }` names src/outer/inner.rs, so a bare
  #    src/inner.rs must stay an orphan (Strix MEDIUM, CWE-706, PR #145
  #    follow-up).
  rm -rf "$tmp/inline"; mkdir -p "$tmp/inline/src"
  printf 'mod outer {\n    mod inner;\n}\n' > "$tmp/inline/src/lib.rs"
  printf 'pub fn ghost() {}\n' > "$tmp/inline/src/inner.rs"
  if ( scan "$tmp/inline" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an inline-nested module declaration satisfied a file outside the lexical scope!" >&2
    exit 1
  fi

  # 8. The same inline nesting with the file in the real location must
  #    pass: src/outer/inner.rs is what `mod inner;` inside `mod outer`
  #    actually names.
  rm -rf "$tmp/inlinegood"; mkdir -p "$tmp/inlinegood/src/outer"
  printf 'mod outer {\n    mod inner;\n}\n' > "$tmp/inlinegood/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/inlinegood/src/outer/inner.rs"
  if ! ( scan "$tmp/inlinegood" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: an inline-nested module at its real path was flagged!" >&2
    exit 1
  fi

  # 9. Nested Rust block comments must not perturb module scope tracking:
  #    a `}` inside `/* ... /* ... */ ... */` is comment text, not a scope
  #    close (Strix MEDIUM, CWE-180, PR #145 follow-up).
  rm -rf "$tmp/nestedc"; mkdir -p "$tmp/nestedc/src"
  printf 'mod outer {\n    /* x /* y */ } */\n    mod inner;\n}\n' > "$tmp/nestedc/src/lib.rs"
  printf 'pub fn ghost() {}\n' > "$tmp/nestedc/src/inner.rs"
  if ( scan "$tmp/nestedc" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a nested block comment perturbed module scope tracking!" >&2
    exit 1
  fi

  # 10. The same nesting with the file at the real path passes.
  rm -rf "$tmp/nestedcgood"; mkdir -p "$tmp/nestedcgood/src/outer"
  printf 'mod outer {\n    /* x /* y */ } */\n    mod inner;\n}\n' > "$tmp/nestedcgood/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/nestedcgood/src/outer/inner.rs"
  if ! ( scan "$tmp/nestedcgood" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a nested comment next to a real module declaration was flagged!" >&2
    exit 1
  fi

  echo "orphan-file gate self-test OK: an undeclared file, a missing src, an inline-nested declaration pointing outside its lexical scope and a nested block comment perturbing scope are rejected; declared modules, nested modules, #[path] aliases, src/bin targets, inline-nested modules and nested comments next to real declarations all pass."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
