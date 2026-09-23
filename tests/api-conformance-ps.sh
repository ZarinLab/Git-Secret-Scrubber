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
# Usage:  tests/api-conformance-ps.sh /tmp/scratch
#
TOOL_PS="${TOOL_PS:-$(cd "$(dirname "$0")/.." && pwd)/clean-secrets.ps1}"
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

echo "── POWERSHELL REGRESSIONS (2026-09-17 review; bash twins in tests/regressions.sh) ──"
pfx='gl'; TOK="${pfx}pat-Zr8Kq2Wm5Nx7Pv3Ty9Lb"
newrepo(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; git -C "$d" init -q -b main; git -C "$d" config user.email t@t.t; git -C "$d" config user.name T; echo "$d"; }
all_objects(){ git -C "$1" cat-file --batch-all-objects --batch 2>/dev/null; }
runps(){ pwsh -NoProfile -File "$TOOL_PS" "$@"; }

# PR1 -- identifier-shaped connection-string passwords proposed; rejects listed.
d=$(newrepo pr1)
printf '{ "a": "Server=db1;User Id=u;Password=summerholiday;", "b": "Data Source=db3;User ID=u;Password=my_db_pass_word2" }\nspring.datasource.password=alphaonlyword\n' > "$d/cfg.txt"
git -C "$d" add -A; git -C "$d" commit -qm c1; printf 'gone\n' > "$d/cfg.txt"; git -C "$d" commit -qam c2
o=$( cd "$d" && runps -Redact -DryRun 2>&1 )
echo "$o" | grep -qE 'len=13 +sum' && echo "$o" | grep -qE 'len=16 +my_' && res ok "PR1a connstring passwords" "proposed" || res no "PR1a connstring passwords" "dropped"
echo "$o" | grep -E 'len=13 +alp' | grep -qi 'rejected: alphabetic' && echo "$o" | grep -q 'No -SecretsFrom' && res ok "PR1b rejects listed + warning" "shown" || res no "PR1b rejects listed + warning" "silent"

# PR1e -- shared list with an absent value and CRLF endings still verifies.
d=$(mkfix_hist pr1e); printf 'Kp9mX2#vT7wQ4nL\r\nNotInThisRepo-4f9Q\r\n' > "$W/shared-list.txt"
o=$( cd "$d" && echo YES | runps -Redact -SecretsFrom "$W/shared-list.txt" 2>&1 ); rc=$?
[ $rc -eq 0 ] && echo "$o" | grep -q 'occur nowhere' && res ok "PR1e shared/CRLF -SecretsFrom" "rc=0" || res no "PR1e shared/CRLF -SecretsFrom" "rc=$rc"

# PR2 -- a value skipped because it is live in HEAD: exit non-zero.
d=$(mkfix_live pr2)
( cd "$d" && runps -Redact -DryRun >/dev/null 2>&1 ); rc=$?
( cd "$d" && runps -Redact -DryRun -IncludeHeadValues >/dev/null 2>&1 ); rc2=$?
[ $rc -ne 0 ] && [ $rc2 -eq 0 ] && res ok "PR2 HEAD-skip exits non-zero" "rc=$rc" || res no "PR2 HEAD-skip exits non-zero" "rc=$rc override rc=$rc2"

# PR3 -- commit message + tag annotation; PR5 no backup branch; PR6 commit-map.
d=$(newrepo pr3)
printf 'token: %s\n' "$TOK" > "$d/ci.yaml"; git -C "$d" add -A; git -C "$d" commit -qm "add ci token $TOK"
git -C "$d" tag -a v1 -m "release; the token was $TOK"
printf 'token: ${akv:kv/ci}\n' > "$d/ci.yaml"; git -C "$d" commit -qam c2
o3=$( cd "$d" && echo YES | runps -Redact 2>&1 ); rc=$?
n=$(all_objects "$d" | grep -acF "$TOK")
[ "$n" -eq 0 ] && [ $rc -eq 0 ] && res ok "PR3 commit + tag messages" "0 objects hold it" || res no "PR3 commit + tag messages" "$n object(s) hold it, rc=$rc"
b=$(git -C "$d" branch --list 'backup-*' | wc -l | tr -d ' ')
[ "$b" -eq 0 ] && echo "$o3" | grep -q 'clone --mirror' && res ok "PR5 no fake backup branch" "mirror advised" || res no "PR5 no fake backup branch" "$b branch(es)"
[ -s "$W/pr3.commit-map" ] && echo "$o3" | grep -q 'refs/merge-requests' && echo "$o3" | grep -q 'Repository cleanup' \
  && res ok "PR6 commit-map kept + GitLab steps" "kept" || res no "PR6 commit-map kept + GitLab steps" "missing"

# PR4 -- stash guard.
d=$(mkfix_hist pr4); before=$(git -C "$d" rev-parse HEAD); echo 'wip: 1' >> "$d/values.yaml"; git -C "$d" stash -q
o=$( cd "$d" && echo YES | runps -Redact 2>&1 ); rc=$?
[ $rc -ne 0 ] && [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && echo "$o" | grep -qi stash && res ok "PR4 stash guard" "refused" || res no "PR4 stash guard" "rc=$rc"

# PR7 -- -Yes with stdin closed.
d=$(mkfix_hist pr7)
( cd "$d" && runps -Redact -Yes </dev/null >/dev/null 2>&1 ); rc=$?
git -C "$d" show HEAD~1:values.yaml | grep -q REPLACE_WITH_SECRET && res ok "PR7 -Yes" "rewrote" || res no "PR7 -Yes" "rc=$rc"

# PR10a -- a gitleaks exit code other than 0/1 is NOT a clean scan.
mkdir -p "$W/fakebin"; printf '#!/bin/sh\necho "fake gitleaks: refusing" >&2\nexit 2\n' > "$W/fakebin/gitleaks"; chmod +x "$W/fakebin/gitleaks"
d=$(mkfix_hist pr10a)
o=$( cd "$d" && echo YES | PATH="$W/fakebin:$PATH" pwsh -NoProfile -File "$TOOL_PS" -Redact 2>&1 )
echo "$o" | grep -q 'did NOT run' && ! echo "$o" | grep -q 'No secrets detected by gitleaks' && res ok "PR10a gitleaks exit 2 not clean" "reported unverified" || res no "PR10a gitleaks exit 2 not clean" "read as clean"

# PR10b -- the object dump must be the repository's bytes. A non-UTF-8 console
# encoding (every Windows OEM code page) turned a UTF-8 password into mojibake,
# the rule built from it matched nothing, and the real value survived.
d=$(newrepo pr10b)
printf 'db: "Server=pg;User Id=a;Password=Grüße2024x;"\n' > "$d/values.yaml"; git -C "$d" add -A; git -C "$d" commit -qm c1
printf 'db: "Server=pg;User Id=a;Password=${akv:kv/db};"\n' > "$d/values.yaml"; git -C "$d" commit -qam c2
( cd "$d" && echo YES | pwsh -NoProfile -Command "[Console]::OutputEncoding=[System.Text.Encoding]::GetEncoding('ISO-8859-1'); & '$TOOL_PS' -Redact; exit \$LASTEXITCODE" >/dev/null 2>&1 ); rc=$?
all_objects "$d" | grep -aqF 'Grüße2024x' && res no "PR10b non-UTF-8 console, UTF-8 secret" "value SURVIVED, rc=$rc" || res ok "PR10b non-UTF-8 console, UTF-8 secret" "gone, rc=$rc"

# PR11 -- -Replacement TEXT.
d=$(mkfix_hist pr11)
o=$( cd "$d" && runps -Redact -Replacement replacemetext -Yes </dev/null 2>&1 ); rc=$?
git -C "$d" show HEAD~1:values.yaml | grep -q 'Password=replacemetext;' && ! all_objects "$d" | grep -aq REPLACE_WITH_SECRET && echo "$o" | grep -q 'now read replacemetext' \
  && res ok "PR11a -Replacement" "rc=$rc" || res no "PR11a -Replacement" "rc=$rc"
bad=0
for t in '' 'a==>b'; do
  d=$(mkfix_hist pr11b); before=$(git -C "$d" rev-parse HEAD)
  o=$( cd "$d" && runps -Redact -Replacement "$t" -Yes </dev/null 2>&1 ) && bad=$((bad+1))
  echo "$o" | grep -q -- '--replacement' || bad=$((bad+1))
  [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] || bad=$((bad+1))
done
[ $bad -eq 0 ] && res ok "PR11b -Replacement rejects bad TEXT" "empty, ==>" || res no "PR11b -Replacement rejects bad TEXT" "$bad"
d=$(mkfix_hist pr11c); before=$(git -C "$d" rev-parse HEAD)
o=$( cd "$d" && runps -Redact -Replacement 'x-Kp9mX2#vT7wQ4nL-x' -Yes </dev/null 2>&1 ); rc=$?
[ $rc -ne 0 ] && [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && echo "$o" | grep -q 'contains a value' && res ok "PR11c TEXT containing a value refused" "rc=$rc" || res no "PR11c TEXT containing a value refused" "rc=$rc"

cat > "$W/anypw.toml" <<'TOML'
[[rules]]
id = "any-password"
regex = '''Password=([^;"$]+);'''
secretGroup = 1
TOML
# Own fixture: mkfix_hist keeps `Password=FROM_VAULT` in HEAD, which this rule
# reports -- a trusted gitleaks finding, live in HEAD, so the run rightly exits 3.
d=$(newrepo pr11d)
printf 'db: "Server=pg;User Id=a;Password=Kp9mX2#vT7wQ4nL;"\n' > "$d/values.yaml"; git -C "$d" add -A; git -C "$d" commit -qm c1
printf 'db: "Server=pg;User Id=a;Password=${akv:kv/db};"\n' > "$d/values.yaml"; git -C "$d" commit -qam c2
o=$( cd "$d" && runps -Redact -Replacement 'replace.me+text' -GitleaksConfig "$W/anypw.toml" -Yes </dev/null 2>&1 ); rc=$?
echo "$o" | grep -q 'matched only the replace.me+text placeholders' && echo "$o" | grep -qF "regexes = ['''^replace\.me\+text\$''']" && [ $rc -eq 0 ] \
  && res ok "PR11d placeholder check + allowlist use TEXT" "rc=$rc" || res no "PR11d placeholder check + allowlist use TEXT" "rc=$rc"

echo; echo "pwsh: $PASS passed, $FAIL failed"; echo "PSRESULT $PASS $FAIL"
# CI reads the status, not the summary line.
[ "$FAIL" -eq 0 ]
