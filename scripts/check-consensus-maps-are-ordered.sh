#!/usr/bin/env bash
# ============================================================================
# check-consensus-maps-are-ordered.sh, every map folded into a hash must
# iterate in a defined order.
#
# A `root()` / `leaf_hash()` / `calculate_state_root()` walks a collection and
# feeds each entry into a digest. If that collection is a `HashMap` or
# `HashSet`, the iteration order is whatever the hasher's random seed decides
# for that process, so two honest nodes with identical state hash the same
# entries in different sequences and produce different roots.
#
# This is the single most-cited source of consensus divergence in the
# ecosystem: Thorchain halted on a Go map iteration, Cosmos SDK documents it
# as a standing hazard, and Tendermint's application guide lists
# "nondeterministic serialisation" first among the things that break replicated
# state machines. Rust has exactly the same exposure - `std::collections::HashMap`
# uses `RandomState`, reseeded per process.
#
# `determinism.yml` already runs the suite on three operating systems and
# compares digests. That catches a divergence that shows up *between the
# platforms the matrix happens to run*. It does not catch one that depends on
# a per-process random seed, because both runs are equally likely to agree by
# chance on a small map. This gate reads the source instead: if a hashing
# function iterates a collection, the collection's declared type must be
# ordered.
#
# The check is deliberately structural rather than exhaustive: it finds the
# `for x in self.FIELD.values()/.keys()/.iter()` shape inside a hashing
# function, resolves FIELD to its struct declaration, and fails when the
# declared type is `HashMap` or `HashSet`.
#
# Usage:
#   bash scripts/check-consensus-maps-are-ordered.sh              # gate
#   bash scripts/check-consensus-maps-are-ordered.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-.}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os, re, sys

root = sys.argv[1]

# Functions whose output is, or feeds, a consensus commitment.
HASHING = re.compile(
    r'\s*(?:pub(?:\([a-z()]+\))? )?fn '
    r'(root|calculate_state_root|leaf_hash|compute_hash|state_root|digest)\b'
)
# `for <binding> in self.<field>.values()` and friends.
#
# The binding is matched with `.+?` rather than `[^\s]+` because the most
# common way to walk a map is `for (key, value) in ...`, and a no-space
# pattern cannot cross the space inside that tuple. With `[^\s]+` this gate
# saw `for e in self.x.iter()` and missed every `for (k, v) in self.x`, which
# is the shape almost every `root()` in this tree actually uses. A gate that
# matches nothing reports nothing.
#
# The bare `&self.field` form is included too: iterating a map directly is
# the same hazard as calling `.iter()` on it, and it is how most of these
# loops are written.
# Whitespace is allowed around every `.` because the joined window that
# recovers a wrapped `for` header leaves `self .entries .iter()`.
ITER = re.compile(
    r'for\s+.+?\s+in\s+(?:&)?self\s*\.\s*([a-z_][a-z0-9_]*)'
    r'(?:\s*\.\s*(?:values|keys|iter)\s*\(\))?\s*[{&]'
)

findings = []
scanned = 0

for dirpath, _, filenames in os.walk(root):
    if any(part in dirpath for part in ('/target', '/.git')):
        continue
    for filename in filenames:
        if not filename.endswith('.rs'):
            continue
        path = os.path.join(dirpath, filename)
        try:
            lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
        except OSError:
            continue

        # (module scope, field) -> declared collection type or alias name.
        # Rust resolves names lexically per module: an inner `mod attacker`
        # can shadow an outer alias of the same name, so a file-wide flat map
        # would let a safe outer alias mask an unsafe inner one (Strix
        # MEDIUM, CWE-184, PR #149 follow-up).
        declared = {}
        # (module scope, alias) -> resolved collection type (or another alias).
        aliases = {}

        def scoped_get(table, scope, name):
            for i in range(len(scope), -1, -1):
                key = (scope[:i], name)
                if key in table:
                    return table[key]
            return None

        def blank(text):
            return "".join("\n" if c == "\n" else " " for c in text)

        def strip_rust_literals(text):
            # Tek gecisli Rust literal tarayicisi (Strix MEDIUM, CWE-184,
            # PR #149 follow-up). Ordinary/byte string, raw string (r#, br#,
            # hash sayisi eslesmesiyle) ve char literal tek geciste ayirt
            # edilir. Char literal (`'{'`, `'}'`, `'\\n'`) kapanis tirnagi
            # olan `'...'` desenidir; Rust lifetime `'a` kapanis tirnagi
            # OLMADIGI icin char sanilip gercek kodu yutmaz.
            out = []
            i = 0
            n = len(text)
            while i < n:
                if text[i] == "'":
                    start = i
                    j = i + 1
                    if j < n and text[j] == "\\":
                        j += 2  # escape'li char: '\n', '\\', '\''
                    else:
                        j += 1
                    if j < n and text[j] == "'":
                        # Kapanis tirnagi var -> char literal, blank'le.
                        out.append(blank(text[start : j + 1]))
                        i = j + 1
                        continue
                    # Kapanis tirnagi yok -> lifetime ('a): dokunma.
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
            # Rust block comment'leri ic ice olabilir; depth counter ile.
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

        # Modul scope takibi yorum/string icindeki suslu parantezlerden
        # etkilenmemeli: string/raw literal'ler, block comment'ler ve line
        # comment'ler once blank'lenir (satir yapisi korunur), braces sayimi
        # ve modul/alias/field desenleri bu temiz gorunumde aranir (Strix
        # MEDIUM, CWE-184, PR #149 follow-up).
        scrubbed_all = strip_block_comments(strip_rust_literals("\n".join(lines)))
        scrubbed_all = re.sub(
            r"//[^\n]*",
            lambda m: "\n" * m.group(0).count("\n"),
            scrubbed_all,
            flags=re.DOTALL,
        )
        scrubbed_lines = scrubbed_all.split("\n")

        module_stack = []
        block_depth = 0
        line_scopes = []
        for idx, line in enumerate(lines):
            sline = scrubbed_lines[idx] if idx < len(scrubbed_lines) else line
            mod = re.match(r'\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{', sline)
            if mod:
                module_stack.append((mod.group(1), block_depth + sline.count('{')))

            scope = tuple(name for name, _ in module_stack)
            line_scopes.append(scope)
            block_depth += sline.count('{') - sline.count('}')
            alias = re.match(
                r'\s*(?:pub(?:\([^)]*\))?\s+)?type\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>]+>)?\s*=\s*'
                r'([A-Za-z_][A-Za-z0-9_:]*)',
                sline,
            )
            if alias:
                aliases[(scope, alias.group(1))] = alias.group(2).split('::')[-1]
            m = re.match(
                r'\s*(?:pub(?:\([^)]*\))? )?([a-z_][a-z0-9_]*)\s*:\s*'
                r'(BTreeMap|BTreeSet|HashMap|HashSet|Vec)\s*<',
                sline,
            )
            if m:
                declared[(scope, m.group(1))] = m.group(2)
            else:
                # A field whose declared type is a user alias must be
                # resolved to the underlying collection type before deciding
                # whether its iteration order is unordered. Aliases may be
                # lowercase (`type entries = HashMap<..>`) or uppercase; the
                # type pattern accepts both, so `rows: entries` resolves the
                # same as `rows: Entries`. Generic aliases (`type Entries<K, V>
                # = HashMap<K, V>` used as `rows: Entries<u64, u64>`) and
                # nested generic applications (`Entries<HashMap<..>, ..>`)
                # are also recognised, so generic parameters cannot hide an
                # unordered map (Strix MEDIUM, CWE-184, deneme round 3
                # PR #272; lowercase, generic, nested-generic and
                # path-qualified aliases: PR #149 follow-up). A field type may
                # be path-qualified (`rows: super::entries`); the last path
                # segment is what the alias map resolves.
                am = re.match(
                    r'\s*(?:pub(?:\([^)]*\))? )?([a-z_][a-z0-9_]*)\s*:\s*'
                    r'([A-Za-z_][A-Za-z0-9_:]*)(?:\s*<.*>)?\s*,?\s*$',
                    sline,
                )
                if am:
                    declared[(scope, am.group(1))] = am.group(2).split('::')[-1]
            # Pop modules whose brace block has closed. `module_stack` entries
            # carry the block depth at which the module opened; once the
            # running depth drops below it, the module is out of scope.
            while module_stack and block_depth < module_stack[-1][1]:
                module_stack.pop()

        inside = False
        depth = 0
        fname = None
        start = 0
        for i, line in enumerate(lines):
            m = HASHING.match(line)
            if m and not inside:
                inside, depth, fname, start = True, 0, m.group(1), i
            if not inside:
                continue
            scanned += line.count('{')
            depth += line.count('{') - line.count('}')
            # rustfmt splits a long `for` header across lines:
            #
            #     for (k, v) in self
            #         .entries
            #         .iter()
            #
            # Matching one line at a time sees `for (k, v) in self` and stops,
            # so the field name is never read and the loop is invisible. Join
            # the next two lines before searching.
            # Four lines, not three: rustfmt puts the opening brace of the
            # loop body on its own line after the receiver chain, and the
            # pattern needs that brace to know the header ended.
            #
            #     for (k, v) in self      <- i
            #         .entries            <- i+1
            #         .iter()             <- i+2
            #     {                       <- i+3
            window = ' '.join(
                l.strip() for l in lines[i:min(i + 4, len(lines))]
            )
            it = ITER.search(line) or ITER.search(window)
            if it:
                field = it.group(1)
                scope = line_scopes[i] if i < len(line_scopes) else ()
                kind = scoped_get(declared, scope, field)
                # Resolve alias chains: `type Entries = HashMap<..>` then
                # `entries: Entries` iterates a HashMap. The chain follows
                # scope too: an alias visible at the use site may itself be
                # shadowed deeper in a module (Strix MEDIUM, CWE-184, deneme
                # round 3 PR #272; nested/shadowed aliases: PR #149
                # follow-up).
                seen = set()
                while kind is not None and kind not in seen:
                    seen.add(kind)
                    nxt = scoped_get(aliases, scope, kind)
                    if nxt is None:
                        break
                    kind = nxt
                if kind in ('HashMap', 'HashSet'):
                    # Order matters only when the loop FOLDS into a shared
                    # accumulator. A loop that writes each entry to its own
                    # slot, `cached_leaves[pos] = ..` with `pos` from a sorted
                    # binary search, produces the same array whichever order it
                    # visits, because no two iterations touch the same cell.
                    #
                    # `calculate_state_root` does exactly that, and calling it
                    # a divergence would be an alarm that is not true. A gate
                    # that cries wolf teaches people to skip it, which costs
                    # more than the check is worth.
                    body = '\n'.join(lines[i:i + 40])
                    end = body.find('\n        }')
                    if end != -1:
                        body = body[:end]
                    folds = re.search(
                        r'\w+\s*\.\s*update\(|\w+\s*\.\s*push\(|'
                        r'\w+\s*[-+^|]=|\w+\s*=\s*\w+\s*[-+^|]',
                        body,
                    )
                    writes_own_slot = re.search(r'\w+\s*\[\s*\w+\s*\]\s*=', body)
                    if folds and not writes_own_slot:
                        findings.append((path, i + 1, fname, field, kind))
            if depth <= 0 and i > start:
                inside, fname = False, None

if not findings:
    print("Consensus-map ordering OK: every collection hashed into a commitment is ordered.")
    sys.exit(0)

print("FAIL: a hashing function iterates an unordered collection:", file=sys.stderr)
for path, line, fname, field, kind in findings:
    print(f"  {path}:{line}  fn {fname}() iterates self.{field}: {kind}<..>", file=sys.stderr)
print("", file=sys.stderr)
print("HashMap/HashSet iteration order comes from a per-process random seed, so", file=sys.stderr)
print("two honest nodes with identical state produce different digests. Use", file=sys.stderr)
print("BTreeMap/BTreeSet, or collect and sort before hashing.", file=sys.stderr)
sys.exit(1)
PY
}

self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap 'rm -rf "${SELF_TEST_TMP:-}"' EXIT
  local tmp="$SELF_TEST_TMP"
  mkdir -p "$tmp/src"

  # An ordered map inside a root() must pass.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: BTreeMap<u64, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in self.entries.values() {
            hasher.update(entry.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if ! (scan "$tmp" >/dev/null 2>&1); then
    echo "FAIL: self-test could not make an ordered tree pass" >&2
    exit 1
  fi

  # Swap the declaration to HashMap; the gate must notice.
  sed -i 's/BTreeMap<u64, u64>/HashMap<u64, u64>/' "$tmp/src/ok.rs"
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a HashMap hashed into a root was accepted!" >&2
    exit 1
  fi

  # The same HashMap outside a hashing function is fine, iteration order
  # only matters where it reaches a digest.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: HashMap<u64, u64>,
}
impl Registry {
    pub fn total(&self) -> u64 {
        let mut sum = 0;
        for entry in self.entries.values() {
            sum += entry;
        }
        sum
    }
}
RS
  if ! (scan "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate flagged a HashMap that never reaches a digest" >&2
    exit 1
  fi

  # Tuple destructuring is how almost every map in this tree is walked, and
  # the first version of this gate could not see it: the binding pattern was
  # matched with `[^\s]+`, which cannot cross the space in `(k, v)`. The gate
  # reported the tree clean because it was looking at nothing.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: HashMap<u64, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in &self.entries {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a HashMap walked as (key, value) pairs was accepted!" >&2
    exit 1
  fi

  # A lowercase type alias must resolve the same as an uppercase one. If the
  # gate only recognised `type Entries = HashMap<..>`, declaring
  # `type entries = HashMap<u64, u64>;` and using `rows: entries` would hide
  # the unordered iteration from the check (Strix MEDIUM, CWE-184, PR #149
  # follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
type entries = HashMap<u64, u64>;
pub struct Registry {
    rows: entries,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in &self.rows {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a lowercase alias hiding a hashed HashMap was accepted!" >&2
    exit 1
  fi

  # A generic alias must resolve the same as a plain one. Declaring
  # `type Entries<K, V> = HashMap<K, V>;` and using `rows: Entries<u64, u64>`
  # would hide the unordered iteration if the field pattern did not accept
  # generic arguments after the alias name (Strix MEDIUM, CWE-184, PR #149
  # follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
type Entries<K, V> = HashMap<K, V>;
pub struct Registry {
    rows: Entries<u64, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in &self.rows {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a generic alias hiding a hashed HashMap was accepted!" >&2
    exit 1
  fi

  # A nested generic application must resolve the same as a plain one.
  # `rows: Entries<HashMap<u64, u64>, u64>` has nested angle brackets; if the
  # field pattern stopped at the first `>`, the alias would not be recognised
  # and the unordered iteration would evade the gate (Strix MEDIUM, CWE-184,
  # PR #149 follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
type Entries<K, V> = HashMap<K, V>;
pub struct Registry {
    rows: Entries<HashMap<u64, u64>, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in &self.rows {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a nested generic alias hiding a hashed HashMap was accepted!" >&2
    exit 1
  fi

  # A path-qualified alias use must resolve the same as a plain one. If the
  # field pattern did not accept `::` in the type name, `rows: super::entries`
  # would not be recognised as the `entries` alias and the unordered iteration
  # would evade the gate (Strix MEDIUM, CWE-184, PR #149 follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
type entries = HashMap<u64, u64>;
pub struct Registry {
    rows: super::entries,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in &self.rows {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a path-qualified alias hiding a hashed HashMap was accepted!" >&2
    exit 1
  fi

  # A path-qualified visibility (`pub(in crate::m) type entries = HashMap<..>`)
  # must resolve the same as a plain one; the visibility parentheses may hold
  # an arbitrary path, not just bare `crate`/`super` keywords (Strix MEDIUM,
  # CWE-184, PR #149 follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
pub(in crate::m) type entries = HashMap<u64, u64>;
pub struct Registry {
    rows: entries,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in &self.rows {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a visibility-qualified alias hiding a hashed HashMap was accepted!" >&2
    exit 1
  fi

  # A shadowed alias inside a module must not be masked by a safe outer alias
  # of the same name. Rust resolves names lexically per module, so the inner
  # `type Entries = HashMap<..>` is the one `root()` iterates even though an
  # outer `type Entries = BTreeMap<..>` exists. The module may itself carry a
  # visibility qualifier (`pub(crate) mod`), which the scope walk must accept
  # (Strix MEDIUM, CWE-184, PR #149 follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
use std::collections::{BTreeMap, HashMap};
use sha2::{Digest, Sha256};

type Entries = BTreeMap<u64, u64>;

pub(crate) mod attacker {
    use super::*;
    type Entries = HashMap<u64, u64>;
    pub struct Registry {
        rows: Entries,
    }
    impl Registry {
        pub fn root(&self) -> [u8; 32] {
            let mut hasher = Sha256::new();
            for (k, v) in &self.rows {
                hasher.update(k.to_le_bytes());
                hasher.update(v.to_le_bytes());
            }
            hasher.finalize().into()
        }
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: an inner module shadowing an outer alias was accepted!" >&2
    exit 1
  fi

  # A stray `}` inside a comment or string must not pop the module scope
  # early. If braces were counted on raw lines, `// }` inside the module
  # would close it, the inner HashMap alias would resolve to the outer safe
  # BTreeMap, and the unordered iteration would pass (Strix MEDIUM, CWE-184,
  # PR #149 follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
use std::collections::{BTreeMap, HashMap};
use sha2::{Digest, Sha256};

type Entries = BTreeMap<u64, u64>;

pub(crate) mod attacker {
    use super::*;
    type Entries = HashMap<u64, u64>;
    pub struct Registry {
        rows: Entries,
        // }  this brace is inside a comment
    }
    impl Registry {
        pub fn root(&self) -> [u8; 32] {
            let marker = "}";  // and this one inside a string
            let mut hasher = Sha256::new();
            for (k, v) in &self.rows {
                hasher.update(k.to_le_bytes());
                hasher.update(v.to_le_bytes());
            }
            hasher.finalize().into()
        }
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: comment/string braces popping module scope early was accepted!" >&2
    exit 1
  fi

  # A `}` inside a char literal must not pop the module scope early.
  # `const X: char = '}';` inside the module is data, not a closing brace
  # (Strix MEDIUM, CWE-184, PR #149 follow-up).
  cat > "$tmp/src/ok.rs" <<'RS'
use std::collections::{BTreeMap, HashMap};
use sha2::{Digest, Sha256};

type Entries = BTreeMap<u64, u64>;

pub(crate) mod attacker {
    use super::*;
    const CLOSER: char = '}';
    type Entries = HashMap<u64, u64>;
    pub struct Registry {
        rows: Entries,
    }
    impl Registry {
        pub fn root(&self) -> [u8; 32] {
            let mut hasher = Sha256::new();
            for (k, v) in &self.rows {
                hasher.update(k.to_le_bytes());
                hasher.update(v.to_le_bytes());
            }
            hasher.finalize().into()
        }
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a char literal brace popping module scope early was accepted!" >&2
    exit 1
  fi

  # And the same shape wrapped across lines by the formatter.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: HashMap<u64, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in self
            .entries
            .iter()
        {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a wrapped HashMap iterator was accepted!" >&2
    exit 1
  fi

  # A loop that writes each entry to its own slot is order-independent: no
  # two iterations touch the same cell, so the result is identical whichever
  # order the map yields. `calculate_state_root` does this, and calling it a
  # divergence would be an alarm that is not true.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    dirty: HashSet<u64>,
    leaves: Vec<[u8; 32]>,
}
impl Registry {
    pub fn calculate_state_root(&mut self) -> [u8; 32] {
        for key in &self.dirty {
            let pos = *key as usize;
            let mut h = Sha256::new();
            h.update(key.to_le_bytes());
            self.leaves[pos] = h.finalize().into();
        }
        self.leaves[0]
    }
}
RS
  if ! (scan "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate flagged a loop that writes each entry to its own slot" >&2
    exit 1
  fi

  echo "Consensus-map ordering self-test OK: a hashed HashMap, one walked as \
(key, value) pairs, one wrapped across lines, one hidden behind a lowercase \
alias, one behind a generic alias, one behind a nested generic application, \
one behind a path-qualified alias use, one behind a visibility-qualified \
alias, one behind a path-qualified visibility, one shadowed inside a \
module, one whose scope is protected from comment/string braces and one \
protected from a char-literal brace are all rejected; an ordered map, a \
non-hashing HashMap and a write-to-own-slot loop all pass."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${1:-$ROOT}"
