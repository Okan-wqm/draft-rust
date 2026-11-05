#!/usr/bin/env bash
# Requirement traceability check (QA, docs/handoff/remaining-work.md section 6).
#
# Every requirement id of docs/spec/requirements.md (for example `PWD-07`)
# must appear, lowercased with `-` replaced by `_` (`pwd_07`), in the name
# of at least one test function of the workspace (`#[test]`,
# `#[tokio::test]`, `#[sqlx::test]`, proptest `#[test]`). Ids that are
# deliberately not tested in this repository (Phase 2 / out of scope per
# docs/roadmap.md) are listed with a reason in
# scripts/requirement-coverage-allowlist.txt; an allow-listed id that is
# covered or unknown is an error too, so the list cannot rot.
#
# Deterministic, offline, no dependencies beyond python3 (run isolated).
# Usage: scripts/check-requirement-coverage.sh [--verbose]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$(mktemp)"
trap 'rm -f "$script"' EXIT

cat >"$script" <<'PY'
import os
import re
import sys

root = sys.argv[1]
verbose = "--verbose" in sys.argv[2:]
spec_path = os.path.join(root, "docs", "spec", "requirements.md")
allow_path = os.path.join(root, "scripts", "requirement-coverage-allowlist.txt")

ID = re.compile(r"\b([A-Z]{2,4}-[0-9]{2})\b")
with open(spec_path, encoding="utf-8") as f:
    ids = sorted(set(ID.findall(f.read())))
if not ids:
    print("no requirement ids found in docs/spec/requirements.md", file=sys.stderr)
    sys.exit(2)

allow = {}
with open(allow_path, encoding="utf-8") as f:
    for number, line in enumerate(f, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not ID.fullmatch(parts[0]):
            print(f"{allow_path}:{number}: expected '<ID> <reason>'", file=sys.stderr)
            sys.exit(2)
        allow[parts[0]] = parts[1]

# A test function: `fn name` that follows an attribute whose path ends in
# `test` (#[test], #[tokio::test(...)], #[sqlx::test(...)], proptest's
# #[test]) with only attributes, comments and whitespace in between (no
# `{` or `;`, so an attribute never reaches a later item).
ATTR_TEST = re.compile(r"#\[\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*test\b")
FN = re.compile(r"[^{};]*?\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
LINE_COMMENT = re.compile(r"//[^\n]*")
SKIP_DIRS = {"target", ".git", "node_modules"}

tests = set()
for base in ("crates", "fuzz"):
    for dirpath, dirnames, filenames in os.walk(os.path.join(root, base)):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                text = LINE_COMMENT.sub("", f.read())
            for attr in ATTR_TEST.finditer(text):
                m = FN.match(text, attr.end())
                if m:
                    tests.add(m.group(1).lower())

missing, covered_allowed = [], []
for rid in ids:
    key = rid.lower().replace("-", "_")
    hits = sorted(t for t in tests if key in t)
    if hits and rid in allow:
        covered_allowed.append(rid)
    elif not hits and rid not in allow:
        missing.append(rid)
    if verbose:
        state = f"{len(hits)} test(s)" if hits else f"allow-listed: {allow.get(rid, '-')}"
        print(f"{rid}: {state}")

unknown = sorted(set(allow) - set(ids))
status = 0
if missing:
    status = 1
    print(f"requirement ids without a test whose name contains them ({len(missing)}):")
    for rid in missing:
        print(f"  {rid}")
if covered_allowed:
    status = 1
    print("allow-listed ids that now have a test (remove them from the allow-list):")
    for rid in covered_allowed:
        print(f"  {rid}")
if unknown:
    status = 1
    print("allow-listed ids that are not in docs/spec/requirements.md:")
    for rid in unknown:
        print(f"  {rid}")
if status == 0:
    print(f"requirement coverage: {len(ids) - len(allow)}/{len(ids)} ids have a test "
          f"({len(tests)} test functions scanned), {len(allow)} allow-listed")
sys.exit(status)
PY

python3 -I "$script" "$root" "$@"
