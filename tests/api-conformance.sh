#!/usr/bin/env bash
#
# API conformance suite. Every documented option gets a fixture, a run, and a
# concrete assertion about the repository afterwards.
#
# It exists because the options were not all exercised. The redact path was
# tested hard against two real repositories; the rest of the surface was not,
# and a sweep of it found that PowerShell was missing SEVEN safety features the
# bash script had grown -- including the rule that stops it rewriting values
# live in HEAD -- and that --secrets-from was being silently filtered by the
# same heuristics it exists to override.
#
# Usage:  tests/api-conformance.sh /tmp/scratch
#
# API conformance harness for Git-Secret-Scrubber.
# Every option gets a fixture, a run, and a concrete assertion.
TOOL_SH="${TOOL_SH:-$(cd "$(dirname "$0")/.." && pwd)/clean-secrets.sh}"
W="$1/apitest"; rm -rf "$W"; mkdir -p "$W"
PASS=0; FAIL=0
res(){ if [ "$1" = ok ]; then PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %-34s %s\n' "$2" "$3"; else FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %-34s %s\n' "$2" "$3"; fi; }

# fixture: secret only in history (safe to redact)
mkfix_hist(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; ( cd "$d" && git init -q -b main && git config user.email t@t.t && git config user.name T
  printf 'db: "Server=pg;User Id=a;Password=Kp9mX2#vT7wQ4nL;Database=a;"\nkeep: LOKI_S3_ACCESS_KEY_ID\n' > values.yaml
  git add -A && git commit -qm c1
  printf 'db: "Server=pg;User Id=a;Password=FROM_VAULT;Database=a;"\nkeep: LOKI_S3_ACCESS_KEY_ID\n' > values.yaml
  git add -A && git commit -qm c2 ); echo "$d"; }
# fixture: secret live in HEAD
mkfix_live(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; ( cd "$d" && git init -q -b main && git config user.email t@t.t && git config user.name T
  printf 'db: "Server=pg;User Id=a;Password=Kp9mX2#vT7wQ4nL;Database=a;"\n' > values.yaml
  git add -A && git commit -qm c1 && echo "x: 1" >> values.yaml && git add -A && git commit -qm c2 ); echo "$d"; }
# fixture: a whole file of secrets, for delete mode
mkfix_file(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; ( cd "$d" && git init -q -b main && git config user.email t@t.t && git config user.name T
  printf 'AWS_SECRET=9K2m8pLZBhNqR5wX3dF7gHjMnPvQcT6yW4eU8aBcDfGh\n' > .env
  echo "app" > README.md; git add -A && git commit -qm c1
  git rm -q .env && git commit -qm "remove env" ); echo "$d"; }

echo "── BASH ─────────────────────────────────────────────────────────────"

# 1 --help
o=$("$TOOL_SH" --help 2>&1); rc=$?
[ $rc -eq 0 ] && echo "$o" | grep -q -- "--redact" && res ok "--help" "exit 0, documents --redact" || res no "--help" "rc=$rc"

# 2 unknown option
"$TOOL_SH" --bogus-flag >/dev/null 2>&1; rc=$?
[ $rc -ne 0 ] && res ok "unknown option" "rejected, rc=$rc" || res no "unknown option" "accepted"

# 3 --redact --dry-run  (must not modify)
d=$(mkfix_hist r1); before=$(git -C "$d" rev-parse HEAD)
( cd "$d" && "$TOOL_SH" --redact --dry-run >/dev/null 2>&1 )
[ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && res ok "--redact --dry-run" "history unchanged" || res no "--redact --dry-run" "history CHANGED"

# 4 --redact  (history redacted, HEAD untouched)
d=$(mkfix_hist r2)
( cd "$d" && echo YES | "$TOOL_SH" --redact >/dev/null 2>&1 )
old=$(git -C "$d" show HEAD~1:values.yaml 2>/dev/null); head=$(git -C "$d" show HEAD:values.yaml 2>/dev/null)
echo "$old" | grep -q REPLACE_WITH_SECRET && echo "$head" | grep -q FROM_VAULT && echo "$head" | grep -q LOKI_S3_ACCESS_KEY_ID \
  && res ok "--redact" "history redacted, HEAD intact" || res no "--redact" "unexpected result"

# 5 HEAD-safety default (live value skipped)
d=$(mkfix_live r3)
o=$( cd "$d" && echo YES | "$TOOL_SH" --redact 2>&1 )
echo "$o" | grep -q "STILL PRESENT in the current checkout" && git -C "$d" show HEAD:values.yaml | grep -q "Kp9mX2" \
  && res ok "HEAD-safety (default)" "live value reported + skipped" || res no "HEAD-safety (default)" "live value not protected"

# 6 --include-head-values
d=$(mkfix_live r4)
( cd "$d" && echo YES | "$TOOL_SH" --redact --include-head-values >/dev/null 2>&1 )
git -C "$d" show HEAD:values.yaml | grep -q REPLACE_WITH_SECRET \
  && res ok "--include-head-values" "HEAD rewritten on request" || res no "--include-head-values" "HEAD not rewritten"

# 7 --min-secret-length (raise above the secret's length -> nothing to do)
d=$(mkfix_hist r5)
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run --min-secret-length 40 2>&1 )
echo "$o" | grep -q "No secret values found" && res ok "--min-secret-length" "threshold respected" || res no "--min-secret-length" "still proposed values"

# 8 --secrets-from (force-add a value the heuristics reject)
d=$(mkfix_hist r6); printf 'LOKI_S3_ACCESS_KEY_ID\n' > "$W/extra.txt"
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run --secrets-from "$W/extra.txt" 2>&1 )
echo "$o" | grep -qE "len=21 +LOK" && res ok "--secrets-from" "operator value force-added" || res no "--secrets-from" "value not added"

# 9 --gitleaks-config (explicit config accepted and announced)
d=$(mkfix_hist r7); printf '[extend]\nuseDefault = true\n' > "$W/cfg.toml"
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run --gitleaks-config "$W/cfg.toml" 2>&1 )
echo "$o" | grep -q "Using gitleaks config: $W/cfg.toml" && res ok "--gitleaks-config" "config honoured + announced" || res no "--gitleaks-config" "config not used"

# 10 auto-detect .gitleaks.toml
d=$(mkfix_hist r8); printf '[extend]\nuseDefault = true\n' > "$d/.gitleaks.toml" && git -C "$d" add .gitleaks.toml && git -C "$d" commit -qm cfg
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run 2>&1 )
echo "$o" | grep -q "Using gitleaks config: .gitleaks.toml" && res ok "auto .gitleaks.toml" "detected in repo root" || res no "auto .gitleaks.toml" "not detected"

# 11 --path
d=$(mkfix_hist r9)
o=$( cd / && "$TOOL_SH" --redact --dry-run --path "$d" 2>&1 )
echo "$o" | grep -q "distinct value" && res ok "--path" "operated on named repo" || res no "--path" "did not operate"

# 12 positional PATH
d=$(mkfix_hist r10)
o=$( cd / && "$TOOL_SH" "$d" --redact --dry-run 2>&1 )
echo "$o" | grep -q "distinct value" && res ok "positional PATH" "operated on named repo" || res no "positional PATH" "did not operate"

# 13 --files (delete mode)
d=$(mkfix_file r11)
( cd "$d" && printf 'A
YES
' | "$TOOL_SH" --delete-files --files ".env" >/dev/null 2>&1 )
git -C "$d" log --all --oneline -- .env 2>/dev/null | grep -q . && res no "--files (delete)" ".env still in history" || res ok "--files (delete)" ".env gone from history"

# 14 --files-from
d=$(mkfix_file r12); printf '# comment\n.env\n' > "$W/list.txt"
( cd "$d" && printf 'A
YES
' | "$TOOL_SH" --delete-files --files-from "$W/list.txt" >/dev/null 2>&1 )
git -C "$d" log --all --oneline -- .env 2>/dev/null | grep -q . && res no "--files-from" ".env still in history" || res ok "--files-from" ".env gone from history"

# 15 --dry-run in delete mode
d=$(mkfix_file r13); before=$(git -C "$d" rev-parse HEAD)
# stdin closed: a delete-mode dry run still asks which files, and an inherited
# stdin that never closes hangs the suite there.
( cd "$d" && "$TOOL_SH" --delete-files --files ".env" --dry-run </dev/null >/dev/null 2>&1 )
[ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && res ok "--delete-files --dry-run" "history unchanged" || res no "--delete-files --dry-run" "history CHANGED"

# 16 --skip-gitleaks
d=$(mkfix_file r14)
o=$( cd "$d" && printf 'A
YES
' | "$TOOL_SH" --skip-gitleaks --files ".env" 2>&1 )
echo "$o" | grep -q "Step 3: Detecting secrets with gitleaks" && res no "--skip-gitleaks" "detection still ran" || res ok "--skip-gitleaks" "detection skipped"

# 17 --force (uncommitted changes present)
d=$(mkfix_hist r15); echo "dirty: true" >> "$d/values.yaml"
o=$( cd "$d" && echo YES | "$TOOL_SH" --redact --force 2>&1 ); rc=$?
[ $rc -eq 0 ] && res ok "--force" "proceeded with dirty tree" || res no "--force" "rc=$rc"

# 18 worktree guard
d=$(mkfix_hist r16); git -C "$d" worktree add -q "$W/wt16" HEAD 2>/dev/null
o=$( cd "$d" && printf 'n\nYES\n' | "$TOOL_SH" --redact 2>&1 )
echo "$o" | grep -q "linked worktree" && res ok "worktree guard" "refused / warned" || res no "worktree guard" "no warning"
git -C "$d" worktree remove --force "$W/wt16" 2>/dev/null

# 19 falsifiable verification control
d=$(mkfix_hist r17)
o=$( cd "$d" && echo YES | "$TOOL_SH" --redact 2>&1 )
echo "$o" | grep -q "able to fail" && echo "$o" | grep -q "gone from every object" && res ok "verification control" "control asserted + passed" || res no "verification control" "control missing"

# 20 exit code on clean repo
d="$W/clean"; mkdir -p "$d"; ( cd "$d" && git init -q -b main && git config user.email t@t.t && git config user.name T && echo hello > a.txt && git add -A && git commit -qm c1 )
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run 2>&1 ); rc=$?
[ $rc -eq 0 ] && echo "$o" | grep -q "No secret values found" && res ok "clean repo" "exit 0, nothing proposed" || res no "clean repo" "rc=$rc"

echo
echo "bash: $PASS passed, $FAIL failed"
echo "BASHRESULT $PASS $FAIL"
# CI reads the status, not the summary line.
[ "$FAIL" -eq 0 ]
