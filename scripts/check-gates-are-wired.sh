#!/usr/bin/env bash
# ============================================================================
# check-gates-are-wired.sh, every gate script must actually run somewhere.
#
# A script in `scripts/` that no workflow invokes proves nothing about any
# commit, but it still shows up when someone counts the gates. Four of them
# had accumulated that way (`check-bloat.sh`, `check-kani.sh`,
# `check-machete.sh`, `check-taplo.sh`, all added in one commit), and three
# duplicated work that `extra-tooling.yml` was already doing properly with
# pinned tool versions and real canaries.
#
# This gate closes the door behind them: a new `scripts/check-*.sh` has to be
# referenced by a workflow, or CI fails and says so by name.
#
# Run with --self-test to prove the check can fail.
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-.}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Scripts that are deliberately not invoked by a workflow.
#
# Empty on purpose. An entry here is a standing claim that a gate is worth
# keeping without running, which is a hard claim to make honestly, if it is
# worth keeping, wire it up. Anything added here needs the reason in the same
# commit.
ALLOWED_UNWIRED=()

is_allowed() {
  local name="$1"
  local allowed
  for allowed in ${ALLOWED_UNWIRED[@]+"${ALLOWED_UNWIRED[@]}"}; do
    [ "$name" = "$allowed" ] && return 0
  done
  return 1
}

# A script counts as wired only when a non-comment workflow line references
# its basename under `scripts/`, so comments and other inert strings do not
# satisfy the gate (Strix LOW, CWE-354, deneme round 2 PR #205).
check_wired() {
  local root="$1"
  local workflows="$root/.github/workflows"
  [ -d "$workflows" ] || fail "no workflow directory at $workflows"

  local found_any=0
  local unwired=()
  local script name

  for script in "$root"/scripts/check-*.sh; do
    [ -e "$script" ] || continue
    found_any=1
    name="$(basename "$script")"
    is_allowed "$name" && continue
    # Only executable workflow `run:` content counts: metadata fields like
    # workflow/job `name:` and regex metacharacters in a basename must not
    # satisfy the gate (Strix LOW, CWE-184, PR #145 follow-up). Extract the
    # `run:` blocks (inline and folded `|`/`>`), drop comments, then look for
    # the script path with the basename regex-escaped.
    # Collect the run: blocks, then decide wiring by parsing each line as a
    # shell command. A mention of `scripts/<name>` inside a here-document
    # body or an assignment is not execution; only a command position where
    # the line invokes an interpreter (bash/sh/dash/zsh) on the script
    # counts as wired (Strix LOW, PR #145 follow-up). Piping straight into
    # `grep -q` would SIGPIPE the awk producer under pipefail, so the run
    # content is captured first.
    local run_content
    run_content="$(find "$workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 2>/dev/null \
      | xargs -0 awk '
          /^[[:space:]]*#/ { next }
          /^[[:space:]]*-?[[:space:]]*run:[[:space:]]*[|>][[:space:]]*$/ {
            in_run = 1
            run_indent = match($0, /[^ ]/) - 1
            next
          }
          /^[[:space:]]*-?[[:space:]]*run:[[:space:]]*/ { print; next }
          in_run {
            current = match($0, /[^ ]/)
            if (current == 0) next
            indent = current - 1
            if (indent <= run_indent) {
              in_run = 0
              next
            }
            if ($0 !~ /^[[:space:]]*#/) print
          }
        ' 2>/dev/null || true)"
    if ! python3 - "$run_content" "$name" <<'PY'
import re
import shlex
import sys

run_content, name = sys.argv[1], sys.argv[2]
target = f"scripts/{name}"
shells = {"bash", "sh", "dash", "zsh"}


def is_target(word):
    # Only the repository `scripts/<name>` counts, optionally under the CI
    # `current/` checkout prefix used by semver.yml. A different directory
    # such as `./other/scripts/check-x.sh` must not satisfy the root gate
    # (Strix LOW, PR #145 follow-up).
    while word.startswith("./"):
        word = word[2:]
    if word == target:
        return True
    if word.startswith("current/"):
        return word[len("current/"):] == target
    return False


def unwrap_env(words):
    # `env` may carry `NAME=value` assignments and `-u NAME`/`-i` options
    # before the real command; skip those so `env FAKE=./scripts/x bash
    # ./scripts/y` does not mark `x` as executed (Strix LOW, PR #145
    # follow-up).
    idx = 1
    while idx < len(words):
        token = words[idx]
        if token == "--":
            return words[idx + 1 :]
        if token == "-i":
            idx += 1
            continue
        if token in ("-u", "--unset"):
            idx += 2
            continue
        if token.startswith("-u") and token != "-u":
            idx += 1
            continue
        if "=" in token and not token.startswith("-"):
            idx += 1
            continue
        return words[idx:]
    return []


def interpreter_target(words):
    # For `bash script args...`, the target is the first non-flag argument.
    # `bash -c "..."` executes a string, not a script file, so no target.
    idx = 1
    while idx < len(words):
        token = words[idx]
        if token == "--":
            idx += 1
            break
        if token == "-c":
            return None
        if token.startswith("-") and token != "-":
            idx += 1
            continue
        break
    if idx >= len(words):
        return None
    return words[idx]


heredoc_delims = []


def note_heredocs(line):
    # `cat <<EOF ... EOF` bodies are data, not commands: a script path
    # mentioned only inside a here-document is never executed (Strix LOW,
    # CWE-180, PR #145 follow-up).
    for _, delim in re.findall(r"<<-?\s*(['\"]?)([^\s'\"]+)\1", line):
        heredoc_delims.append(delim)


for line in run_content.splitlines():
    stripped = line.strip()
    if heredoc_delims:
        if stripped == heredoc_delims[0]:
            heredoc_delims.pop(0)
        continue
    if line.startswith("#"):
        continue
    note_heredocs(line)
    try:
        words = shlex.split(line)
    except ValueError:
        continue
    if not words:
        continue
    # The awk extractor prints inline `- run: ...` lines verbatim, so drop
    # the YAML list dash and the `run:` keyword before looking at command
    # position.
    while words and words[0] in ("-", "run:"):
        words = words[1:]
    if not words:
        continue
    first = words[0]
    if first == "env":
        words = unwrap_env(words)
        if not words:
            continue
        first = words[0]
    if first not in shells and first not in {f"/usr/bin/{i}" for i in shells}:
        continue
    # Only the interpreter's actual script target counts: an assignment or an
    # extra argument to another script is not execution of this gate.
    if is_target(interpreter_target(words) or ""):
        sys.exit(0)
sys.exit(1)
PY
    then
      unwired+=("$name")
    fi
  done

  # Guard against the gate silently passing on an empty or misnamed tree.
  [ "$found_any" -eq 1 ] || fail "no scripts/check-*.sh found under $root - wrong root?"

  if [ "${#unwired[@]}" -gt 0 ]; then
    echo "FAIL: these gate scripts are never invoked by any workflow:" >&2
    printf '  - %s\n' "${unwired[@]}" >&2
    echo "Wire them into .github/workflows/, or delete them. A gate that does not run is not a gate." >&2
    exit 1
  fi

  local total
  total="$(find "$root/scripts" -maxdepth 1 -name 'check-*.sh' | wc -l | tr -d ' ')"
  echo "Gate wiring OK: all $total scripts/check-*.sh are referenced by a workflow."
}

self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap 'rm -rf "${SELF_TEST_TMP:-}"' EXIT
  local tmp="$SELF_TEST_TMP"

  mkdir -p "$tmp/scripts" "$tmp/.github/workflows"
  printf '#!/usr/bin/env bash\ntrue\n' > "$tmp/scripts/check-wired-example.sh"
  cat > "$tmp/.github/workflows/ci.yml" <<'YML'
jobs:
  example:
    steps:
      - run: bash ./scripts/check-wired-example.sh
YML

  # A tree where the only gate is wired must pass, otherwise the negative
  # case below would prove nothing.
  if ! (check_wired "$tmp" >/dev/null 2>&1); then
    echo "FAIL: self-test could not make a correctly wired tree pass" >&2
    exit 1
  fi

  # Add a gate nothing references; the check must notice.
  printf '#!/usr/bin/env bash\ntrue\n' > "$tmp/scripts/check-orphan-example.sh"
  if (check_wired "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate accepted a tree containing an unwired script (vacuous gate)" >&2
    exit 1
  fi

  # A script path mentioned only inside a here-document body is data, not an
  # invocation (Strix LOW, CWE-180, PR #145 follow-up).
  rm -rf "$tmp/heredoc"; mkdir -p "$tmp/heredoc/scripts" "$tmp/heredoc/.github/workflows"
  printf '#!/usr/bin/env bash\ntrue\n' > "$tmp/heredoc/scripts/check-heredoc-example.sh"
  cat > "$tmp/heredoc/.github/workflows/ci.yml" <<'YML'
jobs:
  example:
    steps:
      - run: |
          cat <<EOF
          bash ./scripts/check-heredoc-example.sh
          EOF
YML
  if (check_wired "$tmp/heredoc" >/dev/null 2>&1); then
    echo "FAIL: gate counted a here-document body as an executed script invocation" >&2
    exit 1
  fi

  echo "Gate wiring self-test OK"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

check_wired "${1:-$ROOT}"
