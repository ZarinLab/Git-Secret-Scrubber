#!/usr/bin/env bash
#
# Regression suite for the 2026-09-17 review of f27e18a. One test per finding,
# named R<n> after it, each on a fixture that reproduces the finding.
#
# Every test here FAILED against f27e18a, except R1d, which pins behaviour that
# was already right (gitleaks findings skip the identifier heuristics) so that
# the R1 fix cannot quietly take it away. R1e is not from the review: it was
# found while fixing R1.
#
# Secrets are synthetic. Never AWS's AKIAIOSFODNN7EXAMPLE: gitleaks allowlists
# it, so a fixture built on it scans clean and a test using it passes against a
# dead scanner. The GitLab token is assembled at runtime because a literal one
# in this file is itself a push-protection hit.
#
# Usage:  tests/regressions.sh /tmp/scratch
#         TOOL_SH=/path/to/old/clean-secrets.sh tests/regressions.sh /tmp/scratch
#
TOOL_SH="${TOOL_SH:-$(cd "$(dirname "$0")/.." && pwd)/clean-secrets.sh}"
W="$1/regress"; rm -rf "$W"; mkdir -p "$W"
PASS=0; FAIL=0
res(){ if [ "$1" = ok ]; then PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %-40s %s\n' "$2" "$3"; else FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %-40s %s\n' "$2" "$3"; fi; }

pfx='gl'
TOK="${pfx}pat-Zr8Kq2Wm5Nx7Pv3Ty9Lb"
newrepo(){ d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; git -C "$d" init -q -b main; git -C "$d" config user.email t@t.t; git -C "$d" config user.name T; echo "$d"; }
# Every object in the repository, reachable or not -- commits and tags included.
all_objects(){ git -C "$1" cat-file --batch-all-objects --batch 2>/dev/null; }

# A secret that lives only in history: committed, then replaced.
mkfix_hist(){ d=$(newrepo "$1")
  printf 'db: "Server=pg;User Id=a;Password=Kp9mX2#vT7wQ4nL;Database=a;"\n' > "$d/values.yaml"
  git -C "$d" add -A; git -C "$d" commit -qm c1
  printf 'db: "Server=pg;User Id=a;Password=${akv:kv/db};Database=a;"\n' > "$d/values.yaml"
  git -C "$d" commit -qam c2; echo "$d"; }

echo "── REGRESSIONS (2026-09-17 review) ─────────────────────────────────"

# R1a -- identifier-shaped passwords inside a connection string. The sweep found
# them and the kebab/snake/alphabetic rules threw them away, silently: the dry
# run said "No secret values found" and exited 0.
d=$(newrepo r1a)
cat > "$d/appsettings.json" <<'EOF'
{ "a": "Server=db1;User Id=u;Password=summerholiday;",
  "b": "Server=db2;User Id=u;Password=my-db-pass-word;",
  "c": "Data Source=db3;User ID=u;Password=my_db_pass_word2" }
EOF
git -C "$d" add -A; git -C "$d" commit -qm c1
cat > "$d/appsettings.json" <<'EOF'
{ "a": "Server=db1;User Id=u;Password=${akv:kv/a};",
  "b": "Server=db2;User Id=u;Password=${akv:kv/b};",
  "c": "Data Source=db3;User ID=u;Password=${akv:kv/c}" }
EOF
git -C "$d" commit -qam c2
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run 2>&1 )
if echo "$o" | grep -qE 'len=13 +sum' && echo "$o" | grep -qE 'len=15 +my-' && echo "$o" | grep -qE 'len=16 +my_'; then
  res ok "R1a connection-string passwords" "all three proposed"
else res no "R1a connection-string passwords" "$(echo "$o" | grep -m1 -E 'No secret values|distinct value')"; fi

# R1b -- a rejected candidate must be LISTED, with the rule that rejected it.
d=$(newrepo r1b)
printf 'spring.datasource.password=summerholiday\n' > "$d/app.properties"
git -C "$d" add -A; git -C "$d" commit -qm c1
printf 'spring.datasource.password=${DB_PASSWORD}\n' > "$d/app.properties"
git -C "$d" commit -qam c2
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run 2>&1 )
if echo "$o" | grep -qiE 'rejected' && echo "$o" | grep -E 'len=13 +sum' | grep -qi 'alphabetic'; then
  res ok "R1b rejected candidates listed" "value + rule shown"
else res no "R1b rejected candidates listed" "rejection not reported"; fi

# R1c -- without --secrets-from, say loudly that only pattern hits are covered.
echo "$o" | grep -q 'No --secrets-from' && res ok "R1c --secrets-from absent warning" "warned" || res no "R1c --secrets-from absent warning" "silent"

# R1e -- one --secrets-from list serves many repositories, and may have been
# saved on Windows. A value absent from THIS repository, or a CRLF line ending,
# used to fail the verification control after the history was rewritten.
d=$(mkfix_hist r1e)
printf 'Kp9mX2#vT7wQ4nL\r\nNotInThisRepo-4f9Q\r\n' > "$W/shared-list.txt"
o=$( cd "$d" && echo YES | "$TOOL_SH" --redact --secrets-from "$W/shared-list.txt" 2>&1 ); rc=$?
[ $rc -eq 0 ] && echo "$o" | grep -q 'occur nowhere' && ! all_objects "$d" | grep -aqF 'Kp9mX2#vT7wQ4nL' \
  && res ok "R1e shared/CRLF --secrets-from list" "verified, rc=0" || res no "R1e shared/CRLF --secrets-from list" "rc=$rc"

# R1d -- a finding from the repository's own gitleaks rule skips the identifier
# heuristics (already true at f27e18a; pinned so R1 cannot undo it).
d=$(newrepo r1d)
cat > "$d/.gitleaks.toml" <<'EOF'
[extend]
useDefault = true

[[rules]]
id = "tes-connstring-password"
description = "Password field of a connection string"
regex = '''(?i)dbpass:\s*([^\s"]+)'''
secretGroup = 1
EOF
printf 'dbpass: my-db-pass-word\n' > "$d/cfg.yaml"
git -C "$d" add -A; git -C "$d" commit -qm c1
printf 'other: 1\n' > "$d/cfg.yaml"; git -C "$d" commit -qam c2
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run 2>&1 )
echo "$o" | grep -qE 'len=15 +my-' && res ok "R1d gitleaks rule bypasses heuristics" "kebab value proposed" || res no "R1d gitleaks rule bypasses heuristics" "dropped"

# R2 -- a value skipped because it is live in HEAD leaves the repository dirty;
# the run must not exit 0.
d=$(newrepo r2)
printf 'db: "Server=pg;User Id=a;Password=Qz7live8Value;"\n' > "$d/values.yaml"
git -C "$d" add -A; git -C "$d" commit -qm c1; echo "x: 1" >> "$d/values.yaml"; git -C "$d" commit -qam c2
( cd "$d" && "$TOOL_SH" --redact --dry-run >/dev/null 2>&1 ); rc=$?
( cd "$d" && "$TOOL_SH" --redact --dry-run --include-head-values >/dev/null 2>&1 ); rc2=$?
[ $rc -ne 0 ] && [ $rc2 -eq 0 ] && res ok "R2 HEAD-skip exits non-zero" "rc=$rc (override rc=$rc2)" || res no "R2 HEAD-skip exits non-zero" "rc=$rc override rc=$rc2"

# R3 -- a secret in a commit message and a tag annotation. Blob-only rewriting
# and blob-only verification left both behind and reported the value gone.
d=$(newrepo r3)
printf 'token: %s\n' "$TOK" > "$d/ci.yaml"; git -C "$d" add -A; git -C "$d" commit -qm "add ci token $TOK"
git -C "$d" tag -a v1 -m "release; the token was $TOK"
printf 'token: ${akv:kv/ci}\n' > "$d/ci.yaml"; git -C "$d" commit -qam c2
o3=$( cd "$d" && echo YES | "$TOOL_SH" --redact 2>&1 ); rc3=$?
n=$(all_objects "$d" | grep -acF "$TOK")
claimed=$(echo "$o3" | grep -c 'gone from every object')
[ "$n" -eq 0 ] && [ $rc3 -eq 0 ] && res ok "R3 commit + tag messages" "0 objects hold the token" || res no "R3 commit + tag messages" "$n object(s) still hold it; success claimed=$claimed rc=$rc3"

# R5 -- the run must not create a "backup" branch: filter-repo rewrites it with
# everything else, so it backs up nothing. Checked on R3's run.
b=$(git -C "$d" branch --list 'backup-*' | wc -l | tr -d ' ')
[ "$b" -eq 0 ] && echo "$o3" | grep -q 'clone --mirror' && res ok "R5 no fake backup branch" "mirror clone advised" || res no "R5 no fake backup branch" "$b backup branch(es)"

# R6 -- the commit-map must survive the run, and GitLab's server-side leftovers
# must be named. Checked on R3's run.
if [ -s "$W/r3.commit-map" ] && echo "$o3" | grep -q 'refs/merge-requests' && echo "$o3" | grep -q 'Repository cleanup'; then
  res ok "R6 commit-map kept + GitLab steps" "$W/r3.commit-map"
else res no "R6 commit-map kept + GitLab steps" "no copy / no GitLab steps"; fi

# R4 -- a stash must stop a real run before anything is rewritten.
d=$(mkfix_hist r4); before=$(git -C "$d" rev-parse HEAD)
echo 'wip: 1' >> "$d/values.yaml"; git -C "$d" stash -q
o=$( cd "$d" && echo YES | "$TOOL_SH" --redact 2>&1 ); rc=$?
[ $rc -ne 0 ] && [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && echo "$o" | grep -qi 'stash' \
  && res ok "R4 stash guard" "refused, rc=$rc" || res no "R4 stash guard" "rc=$rc, history $( [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && echo unchanged || echo REWRITTEN)"

# R7 -- --yes runs without reading stdin.
d=$(mkfix_hist r7)
( cd "$d" && "$TOOL_SH" --redact --yes </dev/null >/dev/null 2>&1 ); rc=$?
git -C "$d" show HEAD~1:values.yaml 2>/dev/null | grep -q REPLACE_WITH_SECRET && res ok "R7 --yes" "rewrote with stdin closed" || res no "R7 --yes" "rc=$rc, not rewritten"

# R8 -- Apple's /bin/bash 3.2 must be refused up front, with the fix named.
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'echo ${BASH_VERSINFO[0]}')" -lt 4 ]; then
  d=$(mkfix_hist r8); before=$(git -C "$d" rev-parse HEAD)
  o=$( cd "$d" && echo YES | /bin/bash "$TOOL_SH" --redact 2>&1 ); rc=$?
  [ $rc -ne 0 ] && echo "$o" | grep -q 'brew install bash' && ! echo "$o" | grep -q 'Step 1' && [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] \
    && res ok "R8 bash 3.2 refused up front" "rc=$rc" || res no "R8 bash 3.2 refused up front" "rc=$rc: $(echo "$o" | grep -m1 -iE 'unbound|error')"
else
  res ok "R8 bash 3.2 refused up front" "SKIPPED: /bin/bash is 4+ here"
fi

# R9 -- .gitleaksignore fingerprints carry commit SHAs; a rewrite kills them all.
d=$(mkfix_hist r9)
printf '0123456789abcdef0123456789abcdef01234567:values.yaml:generic-api-key:1\n' > "$d/.gitleaksignore"
git -C "$d" add -A; git -C "$d" commit -qm ignore
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run 2>&1 )
echo "$o" | grep -q '\.gitleaksignore' && echo "$o" | grep -q 'allowlist' && res ok "R9 .gitleaksignore warning" "warned" || res no "R9 .gitleaksignore warning" "silent"

# R10 -- a gitleaks exit code other than 0/1 is not a clean scan, at detection
# or at verification. (Verification was already right in bash; detection
# printed "No secrets detected by gitleaks!" under the failure.)
mkdir -p "$W/fakebin"; printf '#!/bin/sh\necho "fake gitleaks: refusing" >&2\nexit 2\n' > "$W/fakebin/gitleaks"; chmod +x "$W/fakebin/gitleaks"
d=$(mkfix_hist r10)
o=$( cd "$d" && echo YES | PATH="$W/fakebin:$PATH" "$TOOL_SH" --redact 2>&1 )
echo "$o" | grep -q 'did NOT run' && ! echo "$o" | grep -q 'No secrets detected by gitleaks' \
  && res ok "R10 gitleaks exit 2 not clean" "reported unverified" || res no "R10 gitleaks exit 2 not clean" "read as clean somewhere"

# R11 -- --replacement TEXT.
d=$(mkfix_hist r11)
o=$( cd "$d" && "$TOOL_SH" --redact --replacement replacemetext --yes </dev/null 2>&1 ); rc=$?
old=$(git -C "$d" show HEAD~1:values.yaml 2>/dev/null)
if [ $rc -eq 0 ] && echo "$old" | grep -q 'Password=replacemetext;' && ! all_objects "$d" | grep -aq 'REPLACE_WITH_SECRET' \
   && ! all_objects "$d" | grep -aqF 'Kp9mX2#vT7wQ4nL' && echo "$o" | grep -q 'now read replacemetext'; then
  res ok "R11a --replacement" "value -> replacemetext"
else res no "R11a --replacement" "rc=$rc"; fi

bad=0
for t in '' 'a==>b' "$(printf 'two\nlines')"; do
  d=$(mkfix_hist r11b); before=$(git -C "$d" rev-parse HEAD)
  # The refusal must be the tool's own validation, not "Unknown option".
  o=$( cd "$d" && "$TOOL_SH" --redact --replacement "$t" --yes </dev/null 2>&1 ) && bad=$((bad+1))
  echo "$o" | grep -q -- '--replacement' && ! echo "$o" | grep -q 'Unknown option' || bad=$((bad+1))
  [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] || bad=$((bad+1))
done
[ $bad -eq 0 ] && res ok "R11b --replacement rejects bad TEXT" "empty, ==>, newline" || res no "R11b --replacement rejects bad TEXT" "$bad accepted"

d=$(mkfix_hist r11c); before=$(git -C "$d" rev-parse HEAD)
o=$( cd "$d" && "$TOOL_SH" --redact --replacement 'x-Kp9mX2#vT7wQ4nL-x' --yes </dev/null 2>&1 ); rc=$?
[ $rc -ne 0 ] && [ "$(git -C "$d" rev-parse HEAD)" = "$before" ] && echo "$o" | grep -q 'contains a value' && res ok "R11c TEXT containing a value refused" "rc=$rc" || res no "R11c TEXT containing a value refused" "rc=$rc"

# R11d -- after a --replacement run, findings that are exactly TEXT are
# placeholders, and the printed allowlist names TEXT. The rule fires on any
# Password= value, so the rewritten history is guaranteed to trip it. The
# config lives outside the repository: inside, its own regex is a finding.
cat > "$W/anypw.toml" <<'TOML'
[[rules]]
id = "any-password"
regex = '''Password=([^;"$]+);'''
secretGroup = 1
TOML
d=$(mkfix_hist r11d)
o=$( cd "$d" && "$TOOL_SH" --redact --replacement 'replace.me+text' --gitleaks-config "$W/anypw.toml" --yes </dev/null 2>&1 ); rc=$?
echo "$o" | grep -q 'matched only the replace.me+text placeholders' && echo "$o" | grep -qF "regexes = ['''^replace\.me\+text\$''']" && [ $rc -eq 0 ] \
  && res ok "R11d placeholder check + allowlist use TEXT" "rc=$rc" || res no "R11d placeholder check + allowlist use TEXT" "rc=$rc"

# R12 -- from a large multi-repository rewrite. The sweep proposed
# code expressions, UI words and placeholders; a word in the list corrupts
# every file holding it. One fixture: a real password and three look-alikes,
# all history-only.
mkfix_r12(){ d=$(newrepo "$1")
  cat > "$d/Settings.cs" <<'EOF'
var cs = "Server=pg;User Id=a;Password=Kp9mX2#vT7wQ4nL;Database=a;";
ExpireDateOfPassword = DateTime.Now.AddDays(setting.PasswordExpiryDays);
var hashedPassword = Encryptor.EncryptString(txtPassword.Password, key);
EOF
  printf '{ "forgotPassword": "Forgot Password", "dbPassword": "postgres12x" }\n' > "$d/en.json"
  git -C "$d" add -A; git -C "$d" commit -qm c1
  printf 'var cs = "";\n' > "$d/Settings.cs"; printf '{}\n' > "$d/en.json"
  git -C "$d" commit -qam c2; echo "$d"; }

# R12a -- a call expression is rejected WITH its rule; the real password is not.
d=$(mkfix_r12 r12a)
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run 2>&1 )
if echo "$o" | grep -q 'code expression' && echo "$o" | grep -qE 'len=15 +Kp9' && ! echo "$o" | grep -E 'len=[0-9]+ +(Dat|Enc)' | grep -vq 'rejected'; then
  res ok "R12a code expressions rejected" "real value still proposed"
else res no "R12a code expressions rejected" "$(echo "$o" | grep -m1 -E 'distinct value|No secret')"; fi

# R12b -- a value with a space is UI text, rejected with its rule.
echo "$o" | grep -q 'contains a space' && res ok "R12b values with a space rejected" "" || res no "R12b values with a space rejected" ""

# R12c -- --exclude-from: an exact value is never redacted, and says why.
printf 'postgres12x\n' > "$W/r12.exclude"
d=$(mkfix_r12 r12c)
o=$( cd "$d" && "$TOOL_SH" --redact --exclude-from "$W/r12.exclude" --yes </dev/null 2>&1 ); rc=$?
if all_objects "$d" | grep -aqF 'postgres12x' && ! all_objects "$d" | grep -aqF 'Kp9mX2#vT7wQ4nL' && echo "$o" | grep -q 'exclude-from'; then
  res ok "R12c --exclude-from" "excluded kept, real value gone (rc=$rc)"
else res no "R12c --exclude-from" "rc=$rc"; fi

# R12d -- --candidates-out: exactly the values that will be replaced, mode 600.
d=$(mkfix_r12 r12d); rm -f "$W/r12.cand"
o=$( cd "$d" && "$TOOL_SH" --redact --dry-run --candidates-out "$W/r12.cand" 2>&1 )
m=$(stat -f %Lp "$W/r12.cand" 2>/dev/null || stat -c %a "$W/r12.cand" 2>/dev/null)
if [ "$m" = 600 ] && grep -qxF 'Kp9mX2#vT7wQ4nL' "$W/r12.cand" && ! grep -q 'DateTime' "$W/r12.cand"; then
  res ok "R12d --candidates-out" "mode $m, exact values"
else res no "R12d --candidates-out" "mode=$m"; fi

echo
echo "regressions: $PASS passed, $FAIL failed"
echo "REGRESSRESULT $PASS $FAIL"
[ "$FAIL" -eq 0 ]
