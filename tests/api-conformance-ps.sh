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
TOOL_PS="$(cd "$(dirname "$0")/.." && pwd)/clean-secrets.ps1"
W="$1/pstest"; rm -rf "$W"; mkdir -p "$W"
PASS=0; FAIL=0
res(){ if [ "$1" = ok ]; then PASS=$((PASS+1)); printf '  PASS  %-34s %s\n' "$2" "$3"; else FAIL=$((FAIL+1)); printf '  FAIL  %-34s %s\n' "$2" "$3"; fi; }
mkfix_hist(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; ( cd "$d" && git init -q -b main && git config user.email t@t.t && git config user.name T
  printf 'db: "Server=pg;User Id=a;Password=Kp9mX2#vT7wQ4nL;Database=a;"\nkeep: LOKI_S3_ACCESS_KEY_ID\n' > values.yaml
  git add -A && git commit -qm c1
  printf 'db: "Server=pg;User Id=a;Password=FROM_VAULT;Database=a;"\nkeep: LOKI_S3_ACCESS_KEY_ID\n' > values.yaml
  git add -A && git commit -qm c2 ); echo "$d"; }
mkfix_live(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; ( cd "$d" && git init -q -b main && git config user.email t@t.t && git config user.name T
  printf 'db: "Server=pg;User Id=a;Password=Kp9mX2#vT7wQ4nL;Database=a;"\n' > values.yaml
  git add -A && git commit -qm c1 && echo "x: 1" >> values.yaml && git add -A && git commit -qm c2 ); echo "$d"; }
mkfix_file(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; ( cd "$d" && git init -q -b main && git config user.email t@t.t && git config user.name T
  printf 'AWS_SECRET=9K2m8pLZBhNqR5wX3dF7gHjMnPvQcT6yW4eU8aBcDfGh\n' > .env; echo app > README.md
  git add -A && git commit -qm c1; git rm -q .env && git commit -qm rm ); echo "$d"; }

echo "── POWERSHELL ───────────────────────────────────────────────────────"
o=$(pwsh -NoProfile -File "$TOOL_PS" -Help 2>&1); rc=$?
[ $rc -eq 0 ] && echo "$o" | grep -qi -- "-Redact" && res ok "-Help" "exit 0, documents -Redact" || res no "-Help" "rc=$rc"

d=$(mkfix_hist p1); before=$(git -C "$d" rev-parse HEAD)
( cd "$d" && pwsh -NoProfile -File "$TOOL_PS" -Redact -DryRun >/dev/null 2>&1 )
[ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && res ok "-Redact -DryRun" "history unchanged" || res no "-Redact -DryRun" "CHANGED"

d=$(mkfix_hist p2)
( cd "$d" && echo YES | pwsh -NoProfile -File "$TOOL_PS" -Redact >/dev/null 2>&1 )
git -C "$d" show HEAD~1:values.yaml 2>/dev/null | grep -q REPLACE_WITH_SECRET && git -C "$d" show HEAD:values.yaml | grep -q FROM_VAULT \
  && res ok "-Redact" "history redacted, HEAD intact" || res no "-Redact" "unexpected"

d=$(mkfix_live p3)
o=$( cd "$d" && echo YES | pwsh -NoProfile -File "$TOOL_PS" -Redact 2>&1 )
echo "$o" | grep -q "STILL PRESENT in the current checkout" && git -C "$d" show HEAD:values.yaml | grep -q "Kp9mX2" \
  && res ok "HEAD-safety (default)" "live value skipped" || res no "HEAD-safety (default)" "NOT protected"

d=$(mkfix_live p4)
( cd "$d" && echo YES | pwsh -NoProfile -File "$TOOL_PS" -Redact -IncludeHeadValues >/dev/null 2>&1 )
git -C "$d" show HEAD:values.yaml | grep -q REPLACE_WITH_SECRET && res ok "-IncludeHeadValues" "HEAD rewritten" || res no "-IncludeHeadValues" "not rewritten"

d=$(mkfix_hist p5)
o=$( cd "$d" && pwsh -NoProfile -File "$TOOL_PS" -Redact -DryRun -MinSecretLength 40 2>&1 )
echo "$o" | grep -q "No secret values found" && res ok "-MinSecretLength" "threshold respected" || res no "-MinSecretLength" "still proposed"

d=$(mkfix_hist p6); printf 'LOKI_S3_ACCESS_KEY_ID\n' > "$W/extra.txt"
o=$( cd "$d" && pwsh -NoProfile -File "$TOOL_PS" -Redact -DryRun -SecretsFrom "$W/extra.txt" 2>&1 )
echo "$o" | grep -qE "len=21" && res ok "-SecretsFrom" "operator value added" || res no "-SecretsFrom" "not added"

d=$(mkfix_hist p7); printf '[extend]\nuseDefault = true\n' > "$d/.gitleaks.toml"; git -C "$d" add .gitleaks.toml; git -C "$d" commit -qm cfg
o=$( cd "$d" && pwsh -NoProfile -File "$TOOL_PS" -Redact -DryRun 2>&1 )
echo "$o" | grep -q "Using gitleaks config" && res ok "auto .gitleaks.toml" "detected" || res no "auto .gitleaks.toml" "not detected"

d=$(mkfix_hist p8); printf '[extend]\nuseDefault = true\n' > "$W/cfg.toml"
o=$( cd "$d" && pwsh -NoProfile -File "$TOOL_PS" -Redact -DryRun -GitleaksConfig "$W/cfg.toml" 2>&1 )
echo "$o" | grep -q "Using gitleaks config" && res ok "-GitleaksConfig" "config honoured" || res no "-GitleaksConfig" "not used"

d=$(mkfix_hist p9)
o=$( cd / && pwsh -NoProfile -File "$TOOL_PS" -Redact -DryRun -Path "$d" 2>&1 )
echo "$o" | grep -q "distinct value" && res ok "-Path" "operated on named repo" || res no "-Path" "did not operate"

d=$(mkfix_file p10)
( cd "$d" && printf 'A\nYES\n' | pwsh -NoProfile -File "$TOOL_PS" -DeleteFiles -Files ".env" >/dev/null 2>&1 )
git -C "$d" log --all --oneline -- .env 2>/dev/null | grep -q . && res no "-Files (delete)" ".env still present" || res ok "-Files (delete)" ".env gone"

d=$(mkfix_file p11); printf '# c\n.env\n' > "$W/list.txt"
( cd "$d" && printf 'A\nYES\n' | pwsh -NoProfile -File "$TOOL_PS" -DeleteFiles -FilesFrom "$W/list.txt" >/dev/null 2>&1 )
git -C "$d" log --all --oneline -- .env 2>/dev/null | grep -q . && res no "-FilesFrom" ".env still present" || res ok "-FilesFrom" ".env gone"

d=$(mkfix_file p12)
o=$( cd "$d" && printf 'A\nYES\n' | pwsh -NoProfile -File "$TOOL_PS" -SkipGitleaks -Files ".env" 2>&1 )
echo "$o" | grep -q "Step 3: Detecting secrets with gitleaks" && res no "-SkipGitleaks" "detection ran" || res ok "-SkipGitleaks" "detection skipped"

d=$(mkfix_hist p13); echo "dirty: 1" >> "$d/values.yaml"
o=$( cd "$d" && echo YES | pwsh -NoProfile -File "$TOOL_PS" -Redact -Force 2>&1 ); rc=$?
[ $rc -eq 0 ] && res ok "-Force" "proceeded with dirty tree" || res no "-Force" "rc=$rc"

d=$(mkfix_hist p14)
o=$( cd "$d" && echo YES | pwsh -NoProfile -File "$TOOL_PS" -Redact 2>&1 )
echo "$o" | grep -q "able to fail" && echo "$o" | grep -q "gone from every object" && res ok "verification control" "control asserted" || res no "verification control" "missing"

echo; echo "pwsh: $PASS passed, $FAIL failed"; echo "PSRESULT $PASS $FAIL"
