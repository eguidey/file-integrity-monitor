#!/usr/bin/env bash
# Integration test: baseline -> clean check -> tamper -> detect.
set -u
BIN="${1:-./fim}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

mkdir -p "$T/data/sub"
echo one > "$T/data/a.txt"; echo two > "$T/data/b.txt"; echo three > "$T/data/sub/c.txt"

"$BIN" baseline "$T/data" "$T/base.txt" >/dev/null && ok "baseline created" || bad "baseline"

"$BIN" check "$T/data" "$T/base.txt" >/dev/null
[ $? -eq 0 ] && ok "clean tree returns 0" || bad "clean tree"

echo tampered > "$T/data/a.txt"
out=$("$BIN" check "$T/data" "$T/base.txt"); rc=$?
[ $rc -eq 2 ] && ok "change returns 2" || bad "exit code on change"
echo "$out" | grep -q "MODIFIED.*a.txt" && ok "detects modified" || bad "modified"

echo new > "$T/data/d.txt"
"$BIN" check "$T/data" "$T/base.txt" | grep -q "ADDED.*d.txt" && ok "detects added" || bad "added"

rm "$T/data/b.txt"
"$BIN" check "$T/data" "$T/base.txt" | grep -q "REMOVED.*b.txt" && ok "detects removed" || bad "removed"

exit $fail
