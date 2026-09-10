#!/usr/bin/env bash
#
# Requires bash 4.0+ (associative arrays). macOS ships bash 3.2 as /bin/bash, so this
# resolves bash from PATH instead -- install a modern one with `brew install bash`.
#
# Git Secret Scrubber - Remove secrets from Git history safely.
#
# Two modes, both driven by git filter-repo:
#
#   --delete-files (default)  Removes entire FILES from history
#                             (filter-repo --invert-paths). For .env, *.pem,
#                             secrets.json -- files that exist only to hold
#                             credentials.
#
#   --redact                  Replaces the secret VALUES in place and keeps
#                             the files (filter-repo --replace-text). For
#                             source and config that is still in use: a Helm
#                             values.yaml or an appsettings.json cannot be
#                             deleted from history without deleting the
#                             configuration with it.
#
# Deleting a live file is the mistake --redact exists to prevent. If the file
# is still referenced, --delete-files removes the configuration along with the
# credential and every historical commit loses it too.
#
# Usage:
#   ./clean-secrets.sh [PATH] [OPTIONS]
#
# Run with --help to see all available options.
#
# Arguments:
#   PATH             Path to the git repository to clean (optional)
#
# Common Options:
#   --redact         Replace secret VALUES in place, keeping the files
#   --delete-files   Remove whole files from history (default)
#   --dry-run        Preview what will be cleaned without making changes
#   --force          Proceed even with uncommitted changes
#   --skip-gitleaks  Skip gitleaks detection (manually specify files)
#   --no-download    Disable automatic downloading of gitleaks
#   --path FOLDER    Path to the git repository (alternative to positional arg)
#   --files LIST     Comma-separated list of files to clean
#   --files-from FILE  Read files to clean from a text file
#   -h, --help       Show full help message
#
# Examples:
#   ./clean-secrets.sh /path/to/repo          # Clean a specific repository
#   ./clean-secrets.sh --dry-run              # Preview changes
#   ./clean-secrets.sh                        # Full cleanup with gitleaks
#   ./clean-secrets.sh --skip-gitleaks        # Skip detection, enter manually
#   ./clean-secrets.sh --files ".env,secrets.json"  # Clean specific files
#
# Author: ZarinLab
# License: Apache 2.0
# Repository: https://github.com/ZarinLab/Git-Secret-Scrubber
# Version: 0.1.0
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Parse arguments
DRY_RUN=false
FORCE=false
SKIP_GITLEAKS=false
NO_DOWNLOAD=false
REPO_PATH=""
MANUAL_FILES=""
FILES_FROM=""
MODE="delete"
SECRETS_FROM=""
GITLEAKS_CONFIG=""
INCLUDE_HEAD_VALUES=false
# 8, not 16. The 2026-09-10 tes-cloud-chart scrub turned up a live 10-character
# database password; a higher floor would have left it in history. Length alone
# is a poor filter -- looks_like_secret() pairs it with character-class
# diversity, which is what actually keeps identifiers out of the list.
MIN_SECRET_LENGTH=8

while [[ $# -gt 0 ]]; do
    case $1 in
        --redact)
            MODE="redact"
            shift
            ;;
        --delete-files)
            MODE="delete"
            shift
            ;;
        --secrets-from)
            SECRETS_FROM="$2"
            shift 2
            ;;
        --gitleaks-config)
            GITLEAKS_CONFIG="$2"
            shift 2
            ;;
        --include-head-values)
            INCLUDE_HEAD_VALUES=true
            shift
            ;;
        --min-secret-length)
            MIN_SECRET_LENGTH="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --skip-gitleaks)
            SKIP_GITLEAKS=true
            shift
            ;;
        --no-download)
            NO_DOWNLOAD=true
            shift
            ;;
        --path)
            REPO_PATH="$2"
            shift 2
            ;;
        --files)
            # Comma-separated list of files
            MANUAL_FILES="$2"
            SKIP_GITLEAKS=true
            shift 2
            ;;
        --files-from)
            # Read files from a text file (one per line)
            FILES_FROM="$2"
            SKIP_GITLEAKS=true
            shift 2
            ;;
        -h|--help)
            echo "Git Secret Scrubber - Remove secrets from Git history"
            echo ""
            echo "Usage: $0 [OPTIONS] [PATH]"
            echo ""
            echo "Arguments:"
            echo "  PATH             Path to the git repository to clean (optional, default: current directory)"
            echo ""
            echo "Modes:"
            echo "  --delete-files   Remove whole FILES from history (default)"
            echo "                   For .env, *.pem, secrets.json -- files that exist only"
            echo "                   to hold credentials."
            echo "  --redact         Replace secret VALUES in place, keeping the files"
            echo "                   For files still in use (values.yaml, appsettings.json)"
            echo "                   where deleting the file would delete the configuration."
            echo ""
            echo "Options:"
            echo "  --include-head-values  Also redact values still present in HEAD"
            echo "                   (default: they are reported and SKIPPED -- see below)"
            echo "  --gitleaks-config FILE  gitleaks config to scan with"
            echo "                   (default: .gitleaks.toml in the repo, if present)"
            echo "  --secrets-from FILE  Extra literal secret values to redact, one per line"
            echo "                   (--redact only; merged with what gitleaks finds)"
            echo "  --min-secret-length N  Shortest value to redact (--redact only, default 8)"
            echo "  --dry-run        Preview what will be cleaned without making changes"
            echo "  --force          Proceed even with uncommitted changes"
            echo "  --skip-gitleaks  Skip gitleaks detection (prompt for manual input)"
            echo "  --no-download    Disable automatic downloading of gitleaks"
            echo "  --path FOLDER    Path to the git repository to clean (alternative to positional arg)"
            echo "  --files LIST     Comma-separated list of files to clean"
            echo "                   Example: --files 'secrets.txt,config/.env'"
            echo "  --files-from FILE  Read files to clean from a text file (one per line)"
            echo "                   Example: --files-from files-to-clean.txt"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 /path/to/repo                # Clean a specific repository"
            echo "  $0 --dry-run                    # Preview with gitleaks detection"
            echo "  $0 --path /path/to/repo         # Same as positional argument"
            echo "  $0 --files 'secrets.txt,.env'   # Clean specific files"
            echo "  $0 --files-from cleanup.txt     # Read files from cleanup.txt"
            echo "  $0 --skip-gitleaks              # Skip detection, enter files manually"
            echo "  $0 --redact                     # Redact secret values, keep the files"
            echo "  $0 --redact --dry-run           # Show what would be redacted"
            exit 0
            ;;
        *)
            # If it's not an option (doesn't start with -), treat as path
            if [[ "$1" != -* && -z "$REPO_PATH" ]]; then
                REPO_PATH="$1"
                shift
            else
                echo "Unknown option: $1"
                echo "Usage: $0 [OPTIONS] [PATH]"
                echo "Use --help for more information."
                exit 1
            fi
            ;;
    esac
done

# Resolve --files-from against the caller's directory BEFORE changing into the repo,
# otherwise a relative path stops resolving the moment we cd and the list reads as missing.
if [[ -n "$FILES_FROM" && "$FILES_FROM" != /* ]]; then
    FILES_FROM="$PWD/$FILES_FROM"
fi

# Change to specified path if provided
if [[ -n "$REPO_PATH" ]]; then
    if [[ -d "$REPO_PATH" ]]; then
        cd "$REPO_PATH" || { echo "Error: Cannot change to directory: $REPO_PATH"; exit 1; }
        echo "Working in: $REPO_PATH"
    else
        echo "Error: Path not found: $REPO_PATH"
        exit 1
    fi
fi

# Default to the repository's own config when one is present. Explicit
# --gitleaks-config always wins.
if [[ -z "$GITLEAKS_CONFIG" && -f ".gitleaks.toml" ]]; then
    GITLEAKS_CONFIG=".gitleaks.toml"
fi

# Helper functions
print_header() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_info() {
    echo -e "${GRAY}$1${NC}"
}

# Scan the full history with gitleaks and capture its JSON report.
#
# The report goes to a temp file, never to /dev/stdout. On macOS /dev/stdout is a symlink
# to /dev/fd/1, which cannot be reopened for writing while stdout is a pipe -- gitleaks
# pre-checks the path, aborts with "Report path is not writable", and scans nothing. With
# its stderr discarded that produced an empty report, which every caller read as "clean".
#
# Sets GITLEAKS_JSON. Returns the gitleaks exit code: 0 = clean, 1 = leaks found.
run_gitleaks_json() {
    local cmd="$1" report stderr_file rc
    local -a config_flag=()
    # Always defined before any early return: callers read it under `set -u`.
    GITLEAKS_JSON=""
    report=$(mktemp "${TMPDIR:-/tmp}/gss-report.XXXXXX") || return 2
    stderr_file=$(mktemp "${TMPDIR:-/tmp}/gss-stderr.XXXXXX") || return 2

    # Honour the repository's own gitleaks config.
    #
    # Without this the scan runs stock rules, which is wrong in BOTH directions
    # against a repo that has tuned them. It misses the shapes the repo added
    # rules for, and -- far worse for --redact -- it reports the values the repo
    # deliberately allowlisted: public reCAPTCHA site keys, OAuth client IDs,
    # the NAMES of vault secrets. Feeding those into --replace-text rewrites live
    # configuration in every commit to hide something that was never secret.
    #
    # An allowlist is a decision someone made and wrote down. Ignoring it here
    # and then rewriting history on the result is the most destructive way to
    # disagree with it.
    if [[ -n "$GITLEAKS_CONFIG" && -f "$GITLEAKS_CONFIG" ]]; then
        config_flag=(--config "$GITLEAKS_CONFIG")
    fi

    # `&& rc=0 || rc=$?` rather than toggling `set -e` around the call: errexit is a
    # shell-global option, so re-enabling it here would leak out of the function and
    # turn the ordinary "leaks found" exit code of 1 into an abort at the call site.
    "$cmd" detect --source . --log-opts="--all --full-history" --no-banner \
        "${config_flag[@]}" \
        --report-format json --report-path "$report" 2>"$stderr_file" && rc=0 || rc=$?

    GITLEAKS_JSON=$(cat "$report" 2>/dev/null)

    # Only 0 and 1 are scan results. Any other code means gitleaks never completed, and
    # an empty report must not be reported as a clean repository -- show what it said.
    if [[ "$rc" -ne 0 && "$rc" -ne 1 ]]; then
        print_error "gitleaks did not complete (exit code $rc):"
        sed 's/^/    /' "$stderr_file" >&2
    fi

    rm -f "$report" "$stderr_file"
    return "$rc"
}

# Report whether a path has ever existed anywhere in history.
#
# Deliberately not `git log ... | head -1`: under `set -o pipefail` head closes the pipe,
# git log dies of SIGPIPE (exit 141), and the pipeline reads as failure -- silently
# skipping the file. It is a race on how much git had written, so it dropped files
# inconsistently, and dropped the ones with the most history most often.
path_in_history() {
    [[ -n "$(git log --all --full-history --oneline -n 1 -- "$1" 2>/dev/null)" ]]
}

# ============================================================================
# Redaction mode (--redact)
# ============================================================================
# Temp files live for the whole run: the pre-rewrite blob dump is what makes the
# post-rewrite verification falsifiable, so it cannot be discarded early.
GSS_TMPDIR=""
# Sets the global. Deliberately NOT a function that echoes the path for `$(...)`
# capture: command substitution runs in a subshell, so the EXIT trap registered
# there fires the moment the subshell ends and deletes the directory it just
# created. The caller is then left holding a path to nothing.
gss_init_tmpdir() {
    if [[ -n "$GSS_TMPDIR" ]]; then
        return 0
    fi
    GSS_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/gss-work.XXXXXX") || return 1
    # The dumps below hold every secret in the repository in plaintext.
    chmod 700 "$GSS_TMPDIR"
    trap 'rm -rf "$GSS_TMPDIR"' EXIT
}

# Concatenate every blob in history into one file.
#
# Used twice: once to harvest candidate secrets, once after the rewrite to prove
# each one is gone. gitleaks' own report is NOT sufficient for either job -- on
# tes-cloud-chart it reported 79 findings where a pattern sweep of the blobs
# found 50 distinct secrets that its rules did not all match.
dump_history_blobs() {
    local out="$1" idx
    gss_init_tmpdir || return 1
    idx="$GSS_TMPDIR/blob-index"
    git rev-list --objects --all 2>/dev/null | awk '{print $1}' \
        | git cat-file --batch-check='%(objectname) %(objecttype)' 2>/dev/null \
        | awk '$2 == "blob" { print $1 }' | sort -u > "$idx"
    # One --batch pass, not a cat-file per blob: on a repo with real history the
    # per-blob loop takes minutes where this takes a second. The interleaved
    # "<sha> blob <size>" headers are harmless -- this file is only ever searched
    # for literal secret values.
    git cat-file --batch --buffer < "$idx" > "$out" 2>/dev/null || true
    rm -f "$idx"
}

# Decide whether a captured string is a credential or an identifier.
#
# Getting this wrong in the permissive direction is not a cosmetic problem:
# --replace-text rewrites the string EVERYWHERE in history, so redacting a short
# or common value corrupts unrelated prose and code.
looks_like_secret() {
    local s="$1" classes=0
    (( ${#s} >= MIN_SECRET_LENGTH )) || return 1

    # Placeholders and template expressions hold no credential.
    if [[ "$s" =~ ^(REPLACE|CHANGE|PLACEHOLDER|TODO|EXAMPLE|DUMMY|SAMPLE|CHANGEME|YOUR_|xxx|XXX) ]]; then
        return 1
    fi
    if [[ "$s" == '$'* || "$s" == '<'* || "$s" == 'lookup('* || "$s" == 'process.env.'* ]]; then
        return 1
    fi

    # A template expression ANYWHERE in the value, not just at the start. A Helm
    # value like `amir-{{ include (print ...) }}` was captured whole by the
    # quoted-value pattern and passed a start-anchored check; the literal never
    # appears in a rendered manifest, so replacing it redacts a template.
    if [[ "$s" == *'{{'* || "$s" == *'}}'* || "$s" == *'${'* ]]; then
        return 1
    fi

    # Segmented identifier paths with no digits: ApiKeys_SendGridApiKeyName,
    # Identity_Api_ClientSecret, Recaptcha_SiteKey, ApiKey.SendGridApiKey,
    # Identity:ClientSecret. These are configuration KEY names -- the
    # `Section__Key` env-var convention, and the token names that REFERENCE a
    # credential in a vault rather than containing one. Redacting them rewrites
    # the reference, breaking config while hiding nothing.
    #
    # Separators are . _ : because all three are used for this and none of them
    # appear in a generated credential often enough to matter. The no-digit
    # condition is what keeps real segmented tokens safe: a SendGrid key
    # (SG.<random>.<random>) is segmented too, but its segments carry digits.
    if [[ "$s" =~ ^[A-Za-z][A-Za-z0-9]*([._:]+[A-Za-z][A-Za-z0-9]*)+$ ]] && [[ ! "$s" =~ [0-9] ]]; then
        return 1
    fi

    # Provider tokens are segmented too, so they must be exempted BEFORE the
    # identifier rules below or glpat-/SG./ghp_ values are thrown away as names.
    if [[ "$s" == AKIA* || "$s" == glpat-* || "$s" == gh[pousr]_* || "$s" == SG.* || "$s" == xox[baprs]-* ]]; then
        return 0
    fi

    # Bracketed markers -- [REDACTED], [MASKED]. Output of a redaction stage, not
    # input to one.
    if [[ "$s" == \[* ]]; then
        return 1
    fi

    # Purely alphabetic values: accessKey, secretKey, hawkUsername. Field names,
    # not credentials -- a generated credential essentially always carries a
    # digit or a symbol. Redacting `secretKey` rewrites the KEY of every mapping
    # that uses it.
    if [[ "$s" =~ ^[A-Za-z]+$ ]]; then
        return 1
    fi

    # snake_case and SCREAMING_SNAKE_CASE identifiers: LOKI_S3_ACCESS_KEY_ID,
    # s3_access_key, appfile_s3_bucket_key.
    #
    # ⚠️ THIS IS THE RULE THAT MATTERS MOST IN A KUBERNETES REPOSITORY. Env var
    # names and ExternalSecret `remoteRef.key` values are written this way, and
    # they are everywhere. A dry run against a 5068-commit GitOps repo proposed
    # 17 values that were live in HEAD; almost all were names of exactly this
    # shape. Redacting them does not hide a credential -- it renames the field
    # that fetches one, in every commit.
    #
    # The digits in S3/L7/v2 are why the no-digit test used for dotted paths is
    # not enough here: the discriminator is that every segment is a word, and
    # the value carries no character outside [A-Za-z0-9_].
    if [[ "$s" =~ ^[A-Za-z][A-Za-z0-9]*(_[A-Za-z0-9]+)+$ ]]; then
        return 1
    fi

    # kebab-case is how Kubernetes Secret names, vault entries and DNS labels are
    # written -- tes-collision-connections, redis-credentials. The identifier
    # belongs in git; the credential it names lives elsewhere. Redacting these
    # breaks configuration and conceals nothing.
    if [[ "$s" =~ ^[a-z][a-z0-9]*(-[a-z0-9]+)+$ ]]; then
        return 1
    fi

    # Character-class diversity rather than Shannon entropy: it is cheap, and it
    # is the test that keeps a six-letter typo like "dsfasd" -- a real value found
    # under a SecretKey: key -- out of a global search-and-replace.
    if [[ "$s" =~ [a-z] ]]; then classes=$((classes + 1)); fi
    if [[ "$s" =~ [A-Z] ]]; then classes=$((classes + 1)); fi
    if [[ "$s" =~ [0-9] ]]; then classes=$((classes + 1)); fi
    if [[ "$s" =~ [^a-zA-Z0-9] ]]; then classes=$((classes + 1)); fi
    (( classes >= 2 ))
}

# The gate for values gitleaks itself reported.
#
# Deliberately weaker than looks_like_secret. A finding from gitleaks running
# under the repository's OWN config has already been through a human decision:
# the rules say what counts here, and the allowlists say what does not. Running
# the identifier heuristics over that verdict second-guesses it with less
# information, and it silently loses real credentials -- a Check Point agent
# token (`cp-<hex>`) is lowercase alphanumerics and hyphens, so the kebab-case
# rule threw it away as a Kubernetes Secret name. That miss left 21 live
# credentials in a repository the tool had just reported as cleaned.
#
# Only placeholders and template expressions are dropped, because those are not
# values at all.
looks_like_secret_minimal() {
    local s="$1"
    (( ${#s} >= MIN_SECRET_LENGTH )) || return 1
    if [[ "$s" =~ ^(REPLACE|CHANGE|PLACEHOLDER|TODO|EXAMPLE|DUMMY|SAMPLE|CHANGEME|YOUR_) ]]; then
        return 1
    fi
    if [[ "$s" == *'{{'* || "$s" == *'}}'* || "$s" == *'${'* || "$s" == '$'* || "$s" == '<'* ]]; then
        return 1
    fi
    return 0
}

# Harvest candidate secret values from the blob dump and from gitleaks' report.
#
# Every pattern here is case-insensitive. On the first pass of the
# tes-cloud-chart scrub they were not, and a lowercase `password=` survived the
# rewrite -- caught only because the verification scan re-read the result.
extract_secret_candidates() {
    local blobs="$1" out="$2" raw trusted
    gss_init_tmpdir || return 1
    raw="$GSS_TMPDIR/candidates.raw"
    trusted="$GSS_TMPDIR/candidates.trusted"

    # Values gitleaks reported, under whatever config is in force. Kept separate
    # from the sweep because they are judged by looks_like_secret_minimal, not by
    # the identifier heuristics -- see the comment on that function.
    : > "$trusted"
    if [[ -n "${GITLEAKS_OUTPUT:-}" && "$GITLEAKS_OUTPUT" != "[]" && "$GITLEAKS_OUTPUT" != "null" ]]; then
        printf '%s' "$GITLEAKS_OUTPUT" | "$PYTHON_CMD" -c '
import sys, json
try:
    for f in json.load(sys.stdin) or []:
        v = f.get("Secret") or ""
        if v:
            print(v)
except Exception:
    pass
' 2>/dev/null >> "$trusted" || true
    fi

    {
        # Connection-string credentials. THIS is the shape gitleaks misses most
        # often: the value is unquoted and semicolon-delimited, so rules written
        # around quoted secrets never see it. 27 of the 50 values in the
        # tes-cloud-chart scrub were of exactly this form.
        grep -aoiE 'password[[:space:]]*=[[:space:]]*[^;"'"'"'[:space:]]+' "$blobs" 2>/dev/null \
            | sed -E 's/^[^=]*=[[:space:]]*//' || true
        grep -aoiE '(secretkey|accesskeyid|access_key_id|apikey|api_key|clientsecret|client_secret)[[:space:]]*[:=][[:space:]]*"?[^",;[:space:]}]+' "$blobs" 2>/dev/null \
            | sed -E 's/^[^:=]*[:=][[:space:]]*"?//' || true

        # Credentials in a URL userinfo component (amqp://, mongodb://, postgres://).
        grep -aoE '://[^/[:space:]:@"]{2,}:[^@[:space:]"'"'"']{4,}@' "$blobs" 2>/dev/null \
            | sed -E 's|^://[^:]*:||; s|@$||' || true

        # Provider tokens with a fixed, unmistakable prefix.
        grep -aoE 'AKIA[0-9A-Z]{16}' "$blobs" 2>/dev/null || true
        grep -aoE 'glpat-[A-Za-z0-9_-]{15,}' "$blobs" 2>/dev/null || true
        grep -aoE 'gh[pousr]_[A-Za-z0-9]{20,}' "$blobs" 2>/dev/null || true
        grep -aoE 'SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' "$blobs" 2>/dev/null || true
        grep -aoE 'xox[baprs]-[A-Za-z0-9-]{10,}' "$blobs" 2>/dev/null || true

        # Quoted values under a credential-ish key.
        grep -aoiE '"?(password|passwd|pwd|secret|token|apikey)"?[[:space:]]*:[[:space:]]*"[^"]{8,}"' "$blobs" 2>/dev/null \
            | sed -E 's/^[^:]*:[[:space:]]*"//; s/"$//' || true

        # Anything the operator already knows about.
        if [[ -n "$SECRETS_FROM" && -f "$SECRETS_FROM" ]]; then
            cat "$SECRETS_FROM"
        fi
    } > "$raw" 2>/dev/null || true

    : > "$out"
    local line
    # Scanner findings: minimal gate only.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if looks_like_secret_minimal "$line"; then
            printf '%s\n' "$line"
        fi
    done < <(sort -u "$trusted") >> "$out"
    # Sweep findings: full heuristics, because nothing has vetted these.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if looks_like_secret "$line"; then
            printf '%s\n' "$line"
        fi
    done < <(sort -u "$raw") >> "$out"
    # De-duplicate across the two sources before ordering.
    sort -u "$out" -o "$out"

    # Longest first. --replace-text applies the rules in file order, so a secret
    # that is a prefix of a longer one must be replaced second or it truncates
    # the longer match and leaves its tail in history. The tes-cloud-chart scrub
    # had three such overlapping pairs.
    if [[ -s "$out" ]]; then
        awk '{ print length($0) "\t" $0 }' "$out" | sort -rn -k1,1 | cut -f2- > "$out.sorted"
        mv "$out.sorted" "$out"
    fi
}

# Show a secret without printing it. Length and a three-character prefix are
# enough for an operator to recognise a value they know; the rest stays hidden so
# a scrub does not end with the whole credential set in a terminal scrollback.
mask_secret() {
    local s="$1"
    printf 'len=%-4s %s...' "${#s}" "${s:0:3}"
}

# Refuse to rewrite while a linked worktree is checked out.
#
# A worktree pins the commits it references. git gc --prune=now cannot drop them,
# so the old objects -- and every secret in them -- survive the rewrite in the
# local repository, ready to be pushed back. On 2026-09-10 an abandoned worktree
# in a temp directory kept a full pre-rewrite history alive, with 94 live secrets
# on disk, through every prune.
check_stale_worktrees() {
    local count
    count=$(git worktree list --porcelain 2>/dev/null | grep -c '^worktree ' || true)
    [[ -z "$count" ]] && count=0
    if (( count > 1 )); then
        echo ""
        print_error "This repository has $((count - 1)) linked worktree(s):"
        git worktree list 2>/dev/null | tail -n +2 | sed 's/^/    /'
        echo ""
        print_warning "A worktree pins the commits it has checked out. They survive the"
        print_warning "rewrite and 'git gc --prune=now' cannot remove them, so the old"
        print_warning "history -- and its secrets -- stays in this repository."
        echo ""
        print_info "Remove them first:  git worktree remove <path>"
        print_info "Or prune abandoned ones:  git worktree prune"
        echo ""
        if [[ "$FORCE" != true ]]; then
            read -p "Type 'IGNORE' to rewrite anyway (not recommended): " WT_CONFIRM
            if [[ "$WT_CONFIRM" != "IGNORE" ]]; then
                print_info "Aborted. Remove the worktrees and re-run."
                exit 1
            fi
        fi
    fi
}

# Build the list, show it, and confirm. Replaces file selection in --redact mode.
SECRETS_FILE=""
PRE_BLOBS=""
REPLACEMENTS_FILE=""
redact_select_and_confirm() {
    print_header "Step 5: Collecting secret values to redact"

    gss_init_tmpdir
    PRE_BLOBS="$GSS_TMPDIR/blobs-before"
    SECRETS_FILE="$GSS_TMPDIR/secrets"
    REPLACEMENTS_FILE="$GSS_TMPDIR/replacements.txt"

    print_info "Reading every blob in history..."
    dump_history_blobs "$PRE_BLOBS"
    print_info "Scanned $(wc -c < "$PRE_BLOBS" | tr -d ' ') bytes of history"

    extract_secret_candidates "$PRE_BLOBS" "$SECRETS_FILE"

    # Split off anything still present in the CURRENT checkout.
    #
    # ⚠️ --replace-text rewrites HEAD like any other commit. A value that is live
    # in the working tree is live CONFIGURATION, and rewriting it does not hide a
    # credential -- it changes what the file means, everywhere, including the
    # commit the deploy tooling reads. Against a GitOps repository that is a
    # change to the running system, applied by a tool nobody thought was allowed
    # to make one.
    #
    # It is also where the remaining false positives live, because a value in
    # HEAD is usually there on purpose: fixtures in a redaction test, an example
    # key quoted in a scanner config, a field name. History-only values are the
    # opposite -- something removed once and left behind in the log.
    #
    # So: redact history-only values, and REPORT the live ones for a human. A
    # credential genuinely live in HEAD needs vaulting, not a silent rewrite.
    local head_file="$GSS_TMPDIR/head-content"
    git archive HEAD 2>/dev/null > "$head_file" || : > "$head_file"
    local live_file="$GSS_TMPDIR/secrets-in-head"
    local hist_file="$GSS_TMPDIR/secrets-history-only"
    : > "$live_file"; : > "$hist_file"
    local cand
    while IFS= read -r cand; do
        [[ -z "$cand" ]] && continue
        if [[ -s "$head_file" ]] && grep -aqF -- "$cand" "$head_file" 2>/dev/null; then
            printf '%s\n' "$cand" >> "$live_file"
        else
            printf '%s\n' "$cand" >> "$hist_file"
        fi
    done < "$SECRETS_FILE"

    local live_n
    live_n=$(wc -l < "$live_file" | tr -d ' ')
    if (( live_n > 0 )); then
        echo ""
        print_warning "$live_n value(s) are STILL PRESENT in the current checkout:"
        echo ""
        while IFS= read -r cand; do
            local where
            where=$(git grep -lF -- "$cand" HEAD 2>/dev/null | sed 's|^HEAD:||' | head -2 | tr '\n' ' ')
            echo -e "  ${GRAY}$(mask_secret "$cand")${NC}  ${GRAY}${where}${NC}"
        done < "$live_file"
        echo ""
        if [[ "$INCLUDE_HEAD_VALUES" == true ]]; then
            print_error "--include-head-values given: these WILL be rewritten in HEAD too."
            print_warning "That changes live configuration. Be sure each one is a credential."
        else
            print_info "SKIPPED -- rewriting these would change live configuration, and a"
            print_info "credential that is still live needs rotating and moving out of the"
            print_info "file, which a history rewrite does not do."
            print_info "Deal with them, then re-run. Use --include-head-values to override."
            cp "$hist_file" "$SECRETS_FILE"
        fi
    fi

    local n
    n=$(wc -l < "$SECRETS_FILE" | tr -d ' ')

    if (( n == 0 )); then
        print_success "No secret values found to redact."
        exit 0
    fi

    echo ""
    print_warning "$n distinct value(s) will be replaced everywhere in history:"
    echo ""
    local i=0 line
    while IFS= read -r line; do
        i=$((i + 1))
        echo -e "  ${CYAN}[$i]${NC} ${GRAY}$(mask_secret "$line")${NC}"
    done < "$SECRETS_FILE"
    echo ""
    print_info "Values are masked on purpose -- a scrub should not end with every"
    print_info "credential in your terminal history."
    echo ""
    print_warning "Review this list. Anything here that is NOT a credential will be"
    print_warning "replaced in every commit, which corrupts that content permanently."
    print_info "Narrow it with --min-secret-length, or add known values with --secrets-from."

    # literal: prefixes the match so filter-repo does not treat it as a regex --
    # a password containing . * + ? [ ] would otherwise match far more than itself.
    : > "$REPLACEMENTS_FILE"
    chmod 600 "$REPLACEMENTS_FILE"
    i=0
    while IFS= read -r line; do
        i=$((i + 1))
        printf 'literal:%s==>REPLACE_WITH_SECRET_%02d\n' "$line" "$i" >> "$REPLACEMENTS_FILE"
    done < "$SECRETS_FILE"

    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        print_success "DRY RUN MODE - No changes will be made"
        print_info "Would replace the $n value(s) above with REPLACE_WITH_SECRET_NN."
        exit 0
    fi
}

# Count gitleaks findings that are NOT the placeholders this tool introduced.
# Returns -1 on unparseable output so the caller takes the loud branch rather
# than reading a parse failure as a clean repository.
count_real_findings() {
    printf '%s' "$1" | "$PYTHON_CMD" -c '
import sys, json, re
try:
    data = json.load(sys.stdin) or []
except Exception:
    print("-1"); raise SystemExit(0)
pat = re.compile(r"^REPLACE_WITH_SECRET_[0-9]+$")
print(sum(1 for f in data if not pat.match((f.get("Secret") or "").strip())))
' 2>/dev/null || printf '%s' "-1"
}

# Prove the rewrite worked -- and prove the proof can fail.
#
# "gitleaks found nothing" is a weak claim: it is also what a scan that never ran
# says, and what a scan whose rules never matched the secret says. This checks
# each value directly, and it checks that the same test FINDS every value in the
# pre-rewrite dump. If it does not, the search is broken and its silence
# afterwards means nothing.
verify_redaction() {
    local post survivors=0 checked=0 found_before=0 line
    gss_init_tmpdir
    post="$GSS_TMPDIR/blobs-after"
    dump_history_blobs "$post"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        checked=$((checked + 1))
        if grep -aqF -- "$line" "$PRE_BLOBS" 2>/dev/null; then
            found_before=$((found_before + 1))
        fi
        if grep -aqF -- "$line" "$post" 2>/dev/null; then
            survivors=$((survivors + 1))
            print_error "  STILL PRESENT: $(mask_secret "$line")"
        fi
    done < "$SECRETS_FILE"

    echo ""
    if (( found_before != checked )); then
        print_error "✗ Verification is NOT trustworthy."
        print_info "  Only $found_before of $checked values were found in the pre-rewrite"
        print_info "  history, so this search cannot detect a failure. Do not treat a"
        print_info "  clean result as proof."
        return 1
    fi

    print_info "Control: all $checked value(s) were present before the rewrite,"
    print_info "so this check is able to fail."

    if (( survivors > 0 )); then
        print_error "✗ $survivors of $checked value(s) SURVIVED the rewrite."
        print_info "  Restore from the backup branch and re-run."
        return 1
    fi

    print_success "✓ All $checked value(s) are gone from every object in history."
    return 0
}

# Display important security reminder
echo ""
print_error "╔══════════════════════════════════════════════════════════════════╗"
print_error "║  ⚠️  IMPORTANT: ROTATE YOUR SECRETS IMMEDIATELY!                  ║"
print_error "║                                                                  ║"
print_error "║  Removing secrets from git history does NOT revoke them.        ║"
print_error "║  Any secrets that were exposed should be rotated/invalidated.   ║"
print_error "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in a git repository
if [[ ! -d ".git" ]]; then
    print_error "ERROR: Not in a git repository!"
    exit 1
fi

# Get current branch
CURRENT_BRANCH=$(git branch --show-current)
print_info "Current branch: $CURRENT_BRANCH"
echo ""

# ============================================================================
# Detection Method Selection (if not specified via command line)
# ============================================================================
DETECTION_METHOD=""

# Check if user already specified files via command line
if [[ -n "$MANUAL_FILES" ]]; then
    DETECTION_METHOD="files"
    print_info "Using files from --files argument"
elif [[ -n "$FILES_FROM" ]]; then
    DETECTION_METHOD="file"
    print_info "Using files from: $FILES_FROM"
elif [[ "$SKIP_GITLEAKS" == true ]]; then
    # User wants to skip gitleaks but didn't provide files - will prompt later
    DETECTION_METHOD="manual"
elif [[ "$MODE" == "redact" ]]; then
    # --redact does not work from a file list at all: it finds credential-shaped
    # VALUES by sweeping every blob, then replaces them wherever they appear. So
    # the "which files?" question has no meaning here -- asking it would only
    # collect an answer the mode cannot use.
    DETECTION_METHOD="gitleaks"
    print_info "Mode --redact: scanning history for secret values"
else
    # Ask user how they want to detect secrets
    echo ""
    print_header "How would you like to identify files with secrets?"
    echo ""
    echo -e "  ${CYAN}[1]${NC} Automatic detection using gitleaks (recommended)"
    echo -e "      Scans git history for secrets automatically"
    echo ""
    echo -e "  ${CYAN}[2]${NC} Enter a comma-separated list of files"
    echo -e "      Example: secrets.txt, config/.env, credentials.json"
    echo ""
    echo -e "  ${CYAN}[3]${NC} Load files from a text file"
    echo -e "      One file path per line, supports # comments"
    echo ""
    
    read -p "Select option [1/2/3] (default: 1): " DETECTION_CHOICE
    
    case "$DETECTION_CHOICE" in
        2)
            DETECTION_METHOD="files"
            SKIP_GITLEAKS=true
            echo ""
            print_info "Enter the file paths to clean from git history."
            print_info "Separate multiple files with commas."
            echo ""
            read -p "File paths: " MANUAL_FILES
            if [[ -z "$MANUAL_FILES" ]]; then
                print_error "No files specified. Exiting."
                exit 1
            fi
            ;;
        3)
            DETECTION_METHOD="file"
            SKIP_GITLEAKS=true
            echo ""
            print_info "Enter the path to a text file containing file paths to clean."
            print_info "The file should have one path per line. Lines starting with # are ignored."
            echo ""
            read -p "Text file path: " FILES_FROM
            if [[ -z "$FILES_FROM" ]]; then
                print_error "No file specified. Exiting."
                exit 1
            fi
            if [[ ! -f "$FILES_FROM" ]]; then
                print_error "File not found: $FILES_FROM"
                exit 1
            fi
            ;;
        1|"")
            DETECTION_METHOD="gitleaks"
            print_info "Using automatic detection with gitleaks"
            ;;
        *)
            print_warning "Invalid choice. Using automatic detection."
            DETECTION_METHOD="gitleaks"
            ;;
    esac
fi

echo ""

# Check for uncommitted changes
if [[ -n "$(git status --porcelain)" ]]; then
    # List of cleanup-related files that are safe to have uncommitted
    CLEANUP_FILES=("clean-secrets.sh" "clean-secrets.ps1" "docs/protected-branches.md" "docs/README.md" ".gitignore" "README.md")
    
    STATUS=$(git status --porcelain)
    NON_CLEANUP_FILES=()
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        
        # Extract file path from porcelain output
        # Format: XY filename  OR  XY old -> new (for renames)
        FILE=$(echo "$line" | sed 's/^[^ ]* *//' | sed 's/^"//;s/"$//')
        
        # Handle rename lines: "old -> new" - extract just the new filename
        if [[ "$FILE" == *" -> "* ]]; then
            FILE="${FILE##* -> }"
            # Also remove quotes from the new name if present
            FILE=$(echo "$FILE" | sed 's/^"//;s/"$//')
        fi
        
        IS_CLEANUP=false
        for CLEANUP_FILE in "${CLEANUP_FILES[@]}"; do
            if [[ "$FILE" == "$CLEANUP_FILE" ]] || [[ "$FILE" == *"/$CLEANUP_FILE" ]]; then
                IS_CLEANUP=true
                break
            fi
        done
        
        if [[ "$IS_CLEANUP" == false ]]; then
            NON_CLEANUP_FILES+=("$FILE")
        fi
    done <<< "$STATUS"
    
    if [[ ${#NON_CLEANUP_FILES[@]} -gt 0 ]]; then
        print_warning "WARNING: You have uncommitted changes in files that are NOT part of this cleanup tool!"
        print_warning "Modified files:"
        for FILE in "${NON_CLEANUP_FILES[@]}"; do
            echo -e "  ${YELLOW}- $FILE${NC}"
        done
        echo ""
        print_info "It's recommended to commit or stash these changes before cleaning git history."
        echo ""
        
        if [[ "$FORCE" == false ]]; then
            read -p "Do you want to proceed anyway? (yes/no) [default: no]: " PROCEED
            if [[ -z "$PROCEED" ]] || ([[ "$PROCEED" != "yes" ]] && [[ "$PROCEED" != "y" ]]); then
                print_info "Aborted. Please commit or stash your changes first, or use --force flag to skip this prompt."
                exit 0
            else
                print_warning "Proceeding with uncommitted changes in other files..."
                echo ""
            fi
        else
            print_warning "Proceeding with --force flag (you have uncommitted changes in other files)..."
            echo ""
        fi
    else
        print_info "Uncommitted changes are only in cleanup script files - this is OK."
        echo ""
    fi
fi

# ============================================================================
# Step 1: Setup git-filter-repo (prefer system binary, fallback to venv)
# ============================================================================
print_header "Step 1: Setting up git-filter-repo..."

# Create unique temp paths based on repo name to avoid collisions
REPO_NAME=$(basename "$(pwd)" | tr ' ' '_')
TEMP_BASE="${TMPDIR:-/tmp}/git-secret-scrubber-${REPO_NAME}-$$"
VENV_PATH="${TEMP_BASE}/venv"
BIN_DIR="${TEMP_BASE}/bin"

PYTHON_CMD=""
USE_SYSTEM_FILTER_REPO=false
FILTER_REPO_CMD=""

# Function to test if Python is actually working
test_python() {
    local python_path="$1"
    if "$python_path" --version &>/dev/null; then
        return 0
    fi
    return 1
}

# Check if git-filter-repo is already installed system-wide
if command -v git-filter-repo &> /dev/null; then
    FILTER_REPO_CMD="git-filter-repo"
    USE_SYSTEM_FILTER_REPO=true
    print_success "Found system git-filter-repo: $(command -v git-filter-repo)"
fi

# Check for Python in PATH (needed for gitleaks download parsing and fallback filter-repo)
for cmd in python3 python; do
    if command -v "$cmd" &> /dev/null; then
        PYTHON_PATH=$(command -v "$cmd")
        if test_python "$PYTHON_PATH"; then
            PYTHON_CMD="$PYTHON_PATH"
            print_success "Found Python: $PYTHON_CMD"
            break
        fi
    fi
done

# If not found in PATH, try common locations
if [[ -z "$PYTHON_CMD" ]]; then
    print_info "Python not found in PATH, checking common installation locations..."
    
    COMMON_PATHS=(
        "$HOME/.local/bin/python3"
        "/usr/bin/python3"
        "/usr/local/bin/python3"
        "/opt/homebrew/bin/python3"
    )
    
    for path in "${COMMON_PATHS[@]}"; do
        if [[ -f "$path" ]] && test_python "$path"; then
            PYTHON_CMD="$path"
            print_success "Found Python: $PYTHON_CMD"
            break
        fi
    done
fi

if [[ -z "$PYTHON_CMD" ]]; then
    print_error "ERROR: Python is not installed or not working!"
    echo ""
    print_info "Please install Python from one of these sources:"
    print_info "  1. Official Python: https://www.python.org/downloads/"
    print_info "  2. Package manager:"
    print_info "     - Ubuntu/Debian: sudo apt install python3 python3-venv"
    print_info "     - macOS: brew install python3"
    print_info "     - Fedora: sudo dnf install python3"
    echo ""
    print_warning "Note: If Python is installed but not found, make sure it's added to PATH"
    exit 1
fi

# If no system git-filter-repo, set up virtual environment
if [[ "$USE_SYSTEM_FILTER_REPO" == false ]]; then
    print_info "git-filter-repo not found in PATH, setting up via Python venv..."
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "$VENV_PATH" ]]; then
        print_info "Creating virtual environment at $VENV_PATH..."
        
        if ! "$PYTHON_CMD" -m venv "$VENV_PATH" 2>&1; then
            print_error "Failed to create virtual environment!"
            exit 1
        fi
        print_success "Virtual environment created"
    else
        print_info "Virtual environment already exists"
    fi

    # Get paths
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        PIP_PATH="$VENV_PATH/Scripts/pip"
        VENV_PYTHON="$VENV_PATH/Scripts/python"
    else
        PIP_PATH="$VENV_PATH/bin/pip"
        VENV_PYTHON="$VENV_PATH/bin/python"
    fi

    # Verify pip exists
    if [[ ! -f "$PIP_PATH" ]]; then
        print_error "pip not found in virtual environment: $PIP_PATH"
        print_info "The virtual environment may be corrupted. Try deleting $VENV_PATH and running again."
        exit 1
    fi

    # Install git-filter-repo
    print_info "Installing git-filter-repo..."
    if ! "$PIP_PATH" install git-filter-repo --quiet --disable-pip-version-check 2>&1; then
        print_error "Failed to install git-filter-repo!"
        exit 1
    fi
    print_success "git-filter-repo installed via pip"
else
    # Set VENV_PYTHON for consistency (used later in gitleaks parsing)
    VENV_PYTHON="$PYTHON_CMD"
fi

echo ""

# ============================================================================
# Step 2: Check for gitleaks (optional - may skip if not needed)
# ============================================================================
print_header "Step 2: Checking for gitleaks..."

GITLEAKS_PATH=""
if command -v gitleaks &> /dev/null; then
    GITLEAKS_PATH=$(command -v gitleaks)
    print_success "Found gitleaks: $GITLEAKS_PATH"
elif [[ "$SKIP_GITLEAKS" == false ]] && [[ "$NO_DOWNLOAD" == false ]]; then
    print_info "gitleaks not found in PATH. Attempting to download..."
    
    # Create bin directory for gitleaks in temp location
    mkdir -p "$BIN_DIR"
elif [[ "$SKIP_GITLEAKS" == false ]] && [[ "$NO_DOWNLOAD" == true ]]; then
    print_warning "gitleaks not found and --no-download specified."
    print_info "Please install gitleaks manually or use --skip-gitleaks"
    print_info "  macOS: brew install gitleaks"
    print_info "  Linux: Download from https://github.com/gitleaks/gitleaks/releases"
    SKIP_GITLEAKS=true
fi

if [[ "$SKIP_GITLEAKS" == false ]] && [[ -z "$GITLEAKS_PATH" ]] && [[ "$NO_DOWNLOAD" == false ]]; then
    
    # Determine OS and architecture
    OS=""
    ARCH=""
    EXT=""
    
    case "$(uname -s)" in
        Linux*)
            OS="linux"
            EXT=""
            ;;
        Darwin*)
            OS="darwin"
            EXT=""
            ;;
        *)
            print_warning "Unsupported OS. Please install gitleaks manually."
            SKIP_GITLEAKS=true
            ;;
    esac
    
    if [[ "$SKIP_GITLEAKS" == false ]]; then
        case "$(uname -m)" in
            x86_64|amd64)
                ARCH="amd64"
                ;;
            arm64|aarch64)
                ARCH="arm64"
                ;;
            *)
                print_warning "Unsupported architecture. Please install gitleaks manually."
                SKIP_GITLEAKS=true
                ;;
        esac
    fi
    
    if [[ "$SKIP_GITLEAKS" == false ]]; then
        # Get latest version from GitHub API
        print_info "Fetching latest gitleaks version..."
        if command -v curl &> /dev/null; then
            LATEST_RELEASE=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest)
        elif command -v wget &> /dev/null; then
            LATEST_RELEASE=$(wget -qO- https://api.github.com/repos/gitleaks/gitleaks/releases/latest)
        else
            print_warning "curl or wget not found. Cannot download gitleaks."
            SKIP_GITLEAKS=true
        fi
        
        if [[ "$SKIP_GITLEAKS" == false ]]; then
            # Extract version and download URL using Python (portable across all platforms)
            # We already verified Python is available earlier in the script
            ASSET_NAME_PATTERN="gitleaks_.*_${OS}_${ARCH}"
            
            read -r GITLEAKS_VERSION DOWNLOAD_URL CHECKSUM_URL <<< $(echo "$LATEST_RELEASE" | "$PYTHON_CMD" -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tag = data.get('tag_name', '')
    version = tag.lstrip('v')
    os_name = '${OS}'
    arch = '${ARCH}'
    asset_name = f'gitleaks_{version}_{os_name}_{arch}'
    url = ''
    checksum_url = ''
    for asset in data.get('assets', []):
        name = asset.get('name', '')
        if name.startswith(asset_name) and not name.endswith('.sig'):
            url = asset.get('browser_download_url', '')
        if name == 'gitleaks_' + version + '_checksums.txt':
            checksum_url = asset.get('browser_download_url', '')
    print(f'{tag} {url} {checksum_url}')
except Exception as e:
    print('')
" 2>/dev/null || echo "")
            
            VERSION=$(echo "$GITLEAKS_VERSION" | sed 's/^v//')
            
            if [[ -n "$DOWNLOAD_URL" ]]; then
                # Ask user for permission to download
                echo ""
                print_warning "gitleaks is required for automatic secret detection."
                print_warning "We can download it for you, or you can install it manually."
                echo ""
                print_info "Version: $GITLEAKS_VERSION"
                print_info "Download URL: $DOWNLOAD_URL"
                if [[ -n "$CHECKSUM_URL" ]]; then
                    print_info "Checksums: $CHECKSUM_URL"
                fi
                echo ""
                print_info "Manual installation options:"
                if [[ "$OS" == "darwin" ]]; then
                    print_info "  brew install gitleaks"
                elif [[ "$OS" == "linux" ]]; then
                    print_info "  apt install gitleaks  (or your package manager)"
                fi
                print_info "  Download from: https://github.com/gitleaks/gitleaks/releases"
                echo ""
                
                read -p "Download gitleaks automatically? (yes/no) [default: yes]: " DOWNLOAD_CHOICE
                if [[ -z "$DOWNLOAD_CHOICE" ]] || [[ "$DOWNLOAD_CHOICE" == "yes" ]] || [[ "$DOWNLOAD_CHOICE" == "y" ]]; then
                    print_info "Downloading gitleaks $GITLEAKS_VERSION..."
                    
                    # Determine the archive filename from URL
                    ARCHIVE_NAME=$(basename "$DOWNLOAD_URL")
                    ARCHIVE_PATH="$BIN_DIR/$ARCHIVE_NAME"
                    
                    # Download the archive
                    if command -v curl &> /dev/null; then
                        curl -L -o "$ARCHIVE_PATH" "$DOWNLOAD_URL" || {
                            print_warning "Download failed"
                            SKIP_GITLEAKS=true
                        }
                    elif command -v wget &> /dev/null; then
                        wget -O "$ARCHIVE_PATH" "$DOWNLOAD_URL" || {
                            print_warning "Download failed"
                            SKIP_GITLEAKS=true
                        }
                    fi
                    
                    # Verify checksum if available
                    if [[ -f "$ARCHIVE_PATH" ]] && [[ -n "$CHECKSUM_URL" ]] && [[ "$SKIP_GITLEAKS" == false ]]; then
                        print_info "Verifying checksum..."
                        
                        # Download checksums file
                        CHECKSUMS_FILE="$BIN_DIR/checksums.txt"
                        if command -v curl &> /dev/null; then
                            curl -sL -o "$CHECKSUMS_FILE" "$CHECKSUM_URL" 2>/dev/null
                        elif command -v wget &> /dev/null; then
                            wget -qO "$CHECKSUMS_FILE" "$CHECKSUM_URL" 2>/dev/null
                        fi
                        
                        if [[ -f "$CHECKSUMS_FILE" ]]; then
                            # Calculate SHA256 of downloaded file
                            if command -v sha256sum &> /dev/null; then
                                ACTUAL_HASH=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
                            elif command -v shasum &> /dev/null; then
                                ACTUAL_HASH=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')
                            else
                                ACTUAL_HASH=""
                                print_warning "Cannot verify checksum (sha256sum/shasum not found)"
                            fi
                            
                            if [[ -n "$ACTUAL_HASH" ]]; then
                                EXPECTED_HASH=$(grep "$ARCHIVE_NAME" "$CHECKSUMS_FILE" | awk '{print $1}')
                                if [[ -n "$EXPECTED_HASH" ]]; then
                                    if [[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
                                        print_success "Checksum verified: $ACTUAL_HASH"
                                    else
                                        print_error "Checksum mismatch!"
                                        print_error "Expected: $EXPECTED_HASH"
                                        print_error "Actual:   $ACTUAL_HASH"
                                        rm -f "$ARCHIVE_PATH" "$CHECKSUMS_FILE" 2>/dev/null
                                        SKIP_GITLEAKS=true
                                    fi
                                else
                                    print_warning "Could not find checksum for $ARCHIVE_NAME"
                                    print_info "SHA256: $ACTUAL_HASH"
                                fi
                            fi
                            rm -f "$CHECKSUMS_FILE" 2>/dev/null
                        else
                            print_warning "Could not download checksums file"
                        fi
                    fi
                    
                    # Extract the binary from the archive
                    if [[ -f "$ARCHIVE_PATH" ]] && [[ "$SKIP_GITLEAKS" == false ]]; then
                        print_info "Extracting gitleaks from archive..."
                        
                        if [[ "$ARCHIVE_NAME" == *.tar.gz ]] || [[ "$ARCHIVE_NAME" == *.tgz ]]; then
                            # Extract tar.gz archive
                            tar -xzf "$ARCHIVE_PATH" -C "$BIN_DIR" gitleaks 2>/dev/null || \
                            tar -xzf "$ARCHIVE_PATH" -C "$BIN_DIR" --strip-components=1 2>/dev/null || {
                                print_warning "Failed to extract gitleaks from tar.gz"
                                SKIP_GITLEAKS=true
                            }
                        elif [[ "$ARCHIVE_NAME" == *.zip ]]; then
                            # Extract zip archive
                            if command -v unzip &> /dev/null; then
                                unzip -o -j "$ARCHIVE_PATH" "gitleaks" -d "$BIN_DIR" 2>/dev/null || \
                                unzip -o "$ARCHIVE_PATH" -d "$BIN_DIR" 2>/dev/null || {
                                    print_warning "Failed to extract gitleaks from zip"
                                    SKIP_GITLEAKS=true
                                }
                            else
                                print_warning "unzip not found, cannot extract archive"
                                SKIP_GITLEAKS=true
                            fi
                        else
                            # Assume it's a raw binary (Windows .exe case)
                            mv "$ARCHIVE_PATH" "$BIN_DIR/gitleaks"
                        fi
                        
                        # Clean up archive
                        rm -f "$ARCHIVE_PATH" 2>/dev/null
                        
                        # Set path and permissions
                        GITLEAKS_PATH="$BIN_DIR/gitleaks"
                        if [[ -f "$GITLEAKS_PATH" ]]; then
                            chmod +x "$GITLEAKS_PATH"
                            # Try to canonicalize path with realpath if available (best-effort)
                            GITLEAKS_PATH=$(realpath "$GITLEAKS_PATH" 2>/dev/null || echo "$GITLEAKS_PATH")
                            
                            # Show version info
                            INSTALLED_VERSION=$("$GITLEAKS_PATH" version 2>/dev/null || echo "unknown")
                            print_success "gitleaks installed successfully"
                            print_info "Version: $INSTALLED_VERSION"
                        else
                            print_warning "gitleaks binary not found after extraction"
                            SKIP_GITLEAKS=true
                        fi
                    fi
                else
                    # User declined download
                    print_info "Skipping gitleaks download."
                    print_info "You can install it manually and run this script again."
                    SKIP_GITLEAKS=true
                fi
            else
                print_warning "Could not find binary for $OS/$ARCH in release assets"
                print_info "Please install gitleaks manually:"
                if [[ "$OS" == "darwin" ]]; then
                    print_info "  brew install gitleaks"
                fi
                print_info "  Or download from: https://github.com/gitleaks/gitleaks/releases"
                SKIP_GITLEAKS=true
            fi
        fi
    fi
fi

DETECTED_FILES=()

if [[ "$SKIP_GITLEAKS" == true ]]; then
    print_info "Skipping gitleaks (not installed or download failed)"
else
    print_header "Step 3: Detecting secrets with gitleaks..."
fi

if [[ "$SKIP_GITLEAKS" == false ]]; then
    print_info "Running gitleaks scan..."
    # Say which rules are in force. A scan is only as trustworthy as its config,
    # and "which config" is exactly the kind of thing that is assumed rather than
    # checked when a result looks reassuring.
    if [[ -n "$GITLEAKS_CONFIG" ]]; then
        print_info "Using gitleaks config: $GITLEAKS_CONFIG"
    else
        print_warning "No gitleaks config -- stock rules only."
        print_warning "If this repo has a .gitleaks.toml elsewhere, pass --gitleaks-config."
    fi
    
    # Use downloaded gitleaks if available, otherwise use system one
    GITLEAKS_CMD="${GITLEAKS_PATH:-gitleaks}"
    
    # Run gitleaks with JSON format (gitleaks native format, not SARIF)
    # Exit code: 0 = no secrets, 1 = secrets found, other = error
    # Run gitleaks with --log-opts to scan ENTIRE git history, not just working tree
    # IMPORTANT: Without this, gitleaks only scans current files, missing historical secrets
    print_info "Scanning entire git history (this may take a while for large repos)..."
    
    # Temporarily disable set -e to capture exit code properly
    set +e
    run_gitleaks_json "$GITLEAKS_CMD"
    GITLEAKS_EXIT=$?
    set -e
    GITLEAKS_OUTPUT="$GITLEAKS_JSON"
    
    # Log exit code for debugging
    if [[ "$GITLEAKS_EXIT" -eq 0 ]]; then
        print_info "gitleaks scan complete: no secrets detected"
    elif [[ "$GITLEAKS_EXIT" -eq 1 ]]; then
        print_info "gitleaks scan complete: secrets detected"
    else
        print_warning "gitleaks scan returned exit code: $GITLEAKS_EXIT"
    fi
    
    if [[ -n "$GITLEAKS_OUTPUT" ]] && [[ "$GITLEAKS_OUTPUT" != "null" ]] && [[ "$GITLEAKS_OUTPUT" != "[]" ]]; then
        # Parse gitleaks native JSON format using Python (portable)
        # gitleaks JSON format: array of findings with File, RuleID, etc.
        PARSE_RESULT=$(echo "$GITLEAKS_OUTPUT" | "$PYTHON_CMD" -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if not data or not isinstance(data, list):
        print('')
        sys.exit(0)
    
    # Group findings by file
    files = {}
    for finding in data:
        file_path = finding.get('File', '')
        rule_id = finding.get('RuleID', 'unknown')
        if file_path:
            if file_path not in files:
                files[file_path] = set()
            files[file_path].add(rule_id)
    
    # Output in format: file|rules|index (one per line)
    for idx, (path, rules) in enumerate(sorted(files.items()), 1):
        rules_str = ','.join(sorted(rules))
        print(f'{path}|{rules_str}|{idx}')
except Exception as e:
    print('')
" 2>/dev/null)
        
        if [[ -n "$PARSE_RESULT" ]]; then
            echo ""
            print_warning "Found secrets in the following files:"
            echo ""
            
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                IFS='|' read -r file_path rules index_num <<< "$line"
                echo -e "  ${YELLOW}[$index_num] $file_path${NC}"
                echo -e "      ${GRAY}Secrets: $rules${NC}"
                DETECTED_FILES+=("$line")
            done <<< "$PARSE_RESULT"
            
            echo ""
            print_warning "Total files with secrets: ${#DETECTED_FILES[@]}"
        fi
    fi
    
    if [[ ${#DETECTED_FILES[@]} -eq 0 ]]; then
        print_success "No secrets detected by gitleaks!"
        echo ""
        print_info "This could mean:"
        print_info "  1. No secrets are present in git history"
        print_info "  2. gitleaks didn't detect them (check manually)"
        echo ""
        print_info "You can manually specify files to clean in the next step."
    fi
fi

# Check which files actually exist in git history
echo ""
print_header "Step 4: Checking files in git history..."

FILES_IN_HISTORY=()

# Process files from command line arguments first
if [[ -n "$MANUAL_FILES" ]]; then
    print_info "Using files from --files argument..."
    IFS=',' read -ra FILES_ARRAY <<< "$MANUAL_FILES"
    for file in "${FILES_ARRAY[@]}"; do
        file=$(echo "$file" | xargs) # trim whitespace
        [[ -z "$file" ]] && continue
        if path_in_history "$file"; then
            FILES_IN_HISTORY+=("$file|manual")
            print_success "  ✓ Found in history: $file"
        else
            print_warning "  ✗ Not in history: $file"
        fi
    done
elif [[ -n "$FILES_FROM" ]]; then
    if [[ -f "$FILES_FROM" ]]; then
        print_info "Reading files from: $FILES_FROM"
        while IFS= read -r file || [[ -n "$file" ]]; do
            file=$(echo "$file" | xargs) # trim whitespace
            # Skip empty lines and comments
            [[ -z "$file" ]] && continue
            [[ "$file" == \#* ]] && continue
            
            if path_in_history "$file"; then
                FILES_IN_HISTORY+=("$file|manual")
                print_success "  ✓ Found in history: $file"
            else
                print_warning "  ✗ Not in history: $file"
            fi
        done < "$FILES_FROM"
    else
        print_error "File not found: $FILES_FROM"
        exit 1
    fi
elif [[ ${#DETECTED_FILES[@]} -gt 0 ]]; then
    # Use files detected by gitleaks
    for file_entry in "${DETECTED_FILES[@]}"; do
        IFS='|' read -r file_path rules _index <<< "$file_entry"
        if path_in_history "$file_path"; then
            FILES_IN_HISTORY+=("$file_path|$rules")
            print_success "  ✓ Found in history: $file_path"
        else
            print_info "  ✗ Not in history: $file_path"
        fi
    done
fi

# If still no files, prompt for manual input.
#
# Skipped in --redact mode: that mode never uses a file list. It sweeps every
# blob for credential-shaped values, so "gitleaks named no files" is not a
# reason to stop -- on tes-cloud-chart the sweep found 27 connection-string
# passwords that gitleaks' rules never matched.
if [[ ${#FILES_IN_HISTORY[@]} -eq 0 && "$MODE" != "redact" ]]; then
    echo ""
    if [[ "$SKIP_GITLEAKS" == true ]]; then
        print_info "No files specified. Please enter files to clean."
    else
        print_success "No files found in git history from gitleaks scan."
        print_info "If you know files with secrets, you can manually specify them."
    fi
    echo ""
    print_info "You can enter:"
    print_info "  - Comma-separated file paths: secrets.txt, config/.env"
    print_info "  - Path to a text file with one file per line: @files-to-clean.txt"
    echo ""
    read -p "Enter file paths (or @filename for file list, or press Enter to exit): " USER_INPUT
    
    if [[ -z "$USER_INPUT" ]]; then
        exit 0
    fi
    
    # Check if user provided a file reference
    if [[ "$USER_INPUT" == @* ]]; then
        INPUT_FILE="${USER_INPUT:1}" # Remove @ prefix
        if [[ -f "$INPUT_FILE" ]]; then
            print_info "Reading files from: $INPUT_FILE"
            while IFS= read -r file || [[ -n "$file" ]]; do
                file=$(echo "$file" | xargs)
                [[ -z "$file" ]] && continue
                [[ "$file" == \#* ]] && continue
                
                if path_in_history "$file"; then
                    FILES_IN_HISTORY+=("$file|manual")
                    print_success "  ✓ Found in history: $file"
                else
                    print_warning "  ✗ Not in history: $file"
                fi
            done < "$INPUT_FILE"
        else
            print_error "File not found: $INPUT_FILE"
            exit 1
        fi
    else
        # Comma-separated list
        IFS=',' read -ra FILES_ARRAY <<< "$USER_INPUT"
        for file in "${FILES_ARRAY[@]}"; do
            file=$(echo "$file" | xargs)
            [[ -z "$file" ]] && continue
            
            if path_in_history "$file"; then
                FILES_IN_HISTORY+=("$file|manual")
                print_success "  ✓ Found in history: $file"
            else
                print_warning "  ✗ Not in history: $file"
            fi
        done
    fi
fi

if [[ ${#FILES_IN_HISTORY[@]} -eq 0 && "$MODE" != "redact" ]]; then
    print_error "No valid files to clean! None of the specified files exist in git history."
    exit 1
fi

echo ""

# ============================================================================
# Step 5: Let user select which files to clean
# ============================================================================
if [[ "$MODE" == "redact" ]]; then

redact_select_and_confirm

else

print_header "Step 5: Select files to clean from history"

echo ""
echo -e "${YELLOW}Files found in git history:${NC}"
echo ""

INDEX=1
for file_entry in "${FILES_IN_HISTORY[@]}"; do
    IFS='|' read -r file_path rules <<< "$file_entry"
    echo -e "  ${CYAN}[$INDEX] $file_path${NC}"
    if [[ "$rules" != "manual" ]]; then
        echo -e "      ${GRAY}Secrets: $rules${NC}"
    fi
    ((INDEX++))
done

echo ""
echo -e "${GREEN}  [A] All files${NC}"
echo -e "${RED}  [N] None (cancel)${NC}"
echo ""

read -p "Enter file numbers (comma-separated) or 'A' for all, 'N' to cancel: " SELECTION

if [[ "$SELECTION" == "N" ]] || [[ "$SELECTION" == "n" ]]; then
    print_info "Cancelled by user."
    exit 0
fi

SELECTED_FILES=()
if [[ "$SELECTION" == "A" ]] || [[ "$SELECTION" == "a" ]]; then
    SELECTED_FILES=("${FILES_IN_HISTORY[@]}")
    print_success "Selected all ${#SELECTED_FILES[@]} files"
else
    IFS=',' read -ra INDICES <<< "$SELECTION"
    for idx in "${INDICES[@]}"; do
        idx=$(echo "$idx" | xargs) # trim
        if [[ "$idx" -ge 1 ]] && [[ "$idx" -le ${#FILES_IN_HISTORY[@]} ]]; then
            SELECTED_FILES+=("${FILES_IN_HISTORY[$((idx-1))]}")
        else
            print_warning "Invalid index: $idx (skipping)"
        fi
    done
    
    if [[ ${#SELECTED_FILES[@]} -eq 0 ]]; then
        print_error "No valid files selected!"
        exit 1
    fi
    
    print_success "Selected ${#SELECTED_FILES[@]} file(s)"
fi

echo ""
echo -e "${YELLOW}Files that will be removed from history:${NC}"
for file_entry in "${SELECTED_FILES[@]}"; do
    IFS='|' read -r file_path rules <<< "$file_entry"
    echo -e "  ${GRAY}- $file_path${NC}"
done
echo ""

if [[ "$DRY_RUN" == true ]]; then
    print_success "DRY RUN MODE - No changes will be made"
    echo ""
    print_info "Would remove these files from history:"
    for file_entry in "${SELECTED_FILES[@]}"; do
        IFS='|' read -r file_path rules <<< "$file_entry"
        echo -e "  ${GREEN}✓ $file_path${NC}"
    done
    exit 0
fi

fi  # end of --delete-files file selection

# ============================================================================
# Step 6: Confirm and proceed with cleanup
# ============================================================================
if [[ "$MODE" == "redact" ]]; then
    print_warning "Mode: --redact -- secret VALUES are replaced, files are kept."
else
    print_warning "Mode: --delete-files -- entire FILES are removed from history."
    print_warning "If any selected file is still in use, its configuration goes with it."
fi
echo ""
print_error "⚠️  WARNING: This will rewrite git history!"
print_error "⚠️  All commit SHAs will change!"
print_error "⚠️  You will need to force push!"
print_error "⚠️  All team members must re-clone the repository!"
echo ""
read -p "Type 'YES' to continue: " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
    print_info "Aborted."
    exit 0
fi

# Save remote information (git-filter-repo removes remotes)
echo ""
print_header "Step 7: Saving remote configuration..."
declare -A REMOTE_INFO
# `declare -A X` alone leaves X unset, and `${#X[@]}` / `${!X[@]}` on an unset
# variable is an error under `set -u`. A repository with no remote therefore
# crashed at Step 11 -- after the history had already been rewritten, which is
# the worst possible moment to abort. The empty assignment makes it a real,
# zero-length array.
REMOTE_INFO=()
while IFS= read -r remote; do
    [[ -z "$remote" ]] && continue
    REMOTE_URL=$(git remote get-url "$remote" 2>/dev/null || echo "")
    if [[ -n "$REMOTE_URL" ]]; then
        REMOTE_INFO["$remote"]="$REMOTE_URL"
        print_info "Saved remote '$remote': $REMOTE_URL"
    fi
done < <(git remote)

# A linked worktree keeps the pre-rewrite objects reachable, so check before
# rewriting rather than discovering it in verification.
check_stale_worktrees

# Create backup branch
echo ""
print_header "Step 8: Creating backup branch..."
BACKUP_BRANCH="backup-before-secret-cleanup-$(date +%Y%m%d-%H%M%S)"
git branch "$BACKUP_BRANCH"
print_success "Backup branch created: $BACKUP_BRANCH"

# Remove files from history
echo ""
if [[ "$MODE" == "redact" ]]; then
    print_header "Step 9: Redacting secret values in git history..."
else
    print_header "Step 9: Removing files from git history..."
fi
print_info "This may take a while..."

# Build git-filter-repo command
if [[ "$MODE" == "redact" ]]; then
    FILTER_REPO_ARGS=("--replace-text" "$REPLACEMENTS_FILE" "--force")
    # Deliberately not echoed with its argument expanded: the replacements file
    # is a plaintext list of every credential in the repository.
    print_info "Running: git filter-repo --replace-text <replacements> --force"
else
    FILTER_REPO_ARGS=("--invert-paths" "--force")
    for file_entry in "${SELECTED_FILES[@]}"; do
        IFS='|' read -r file_path rules <<< "$file_entry"
        FILTER_REPO_ARGS+=("--path")
        FILTER_REPO_ARGS+=("$file_path")
    done
    print_info "Running: git filter-repo ${FILTER_REPO_ARGS[*]}"
fi

# Use system git-filter-repo if available, otherwise use python module
if [[ "$USE_SYSTEM_FILTER_REPO" == true ]]; then
    if ! "$FILTER_REPO_CMD" "${FILTER_REPO_ARGS[@]}"; then
        echo ""
        print_error "ERROR: git-filter-repo failed!"
        print_warning "You can restore from backup branch: $BACKUP_BRANCH"
        exit 1
    fi
else
    if ! "$VENV_PYTHON" -m git_filter_repo "${FILTER_REPO_ARGS[@]}"; then
        echo ""
        print_error "ERROR: git-filter-repo failed!"
        print_warning "You can restore from backup branch: $BACKUP_BRANCH"
        exit 1
    fi
fi

# Clean up
echo ""
print_header "Step 10: Cleaning up git references..."
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Restore remotes (git-filter-repo removes them)
echo ""
print_header "Step 11: Restoring remote configuration..."
for remote in "${!REMOTE_INFO[@]}"; do
    REMOTE_URL="${REMOTE_INFO[$remote]}"
    if git remote add "$remote" "$REMOTE_URL" 2>/dev/null; then
        print_success "Restored remote '$remote': $REMOTE_URL"
    elif git remote set-url "$remote" "$REMOTE_URL" 2>/dev/null; then
        print_success "Updated remote '$remote': $REMOTE_URL"
    else
        print_warning "Could not restore remote '$remote' - you may need to add it manually"
    fi
done

if [[ ${#REMOTE_INFO[@]} -eq 0 ]]; then
    print_info "No remotes were configured before cleanup"
fi

echo ""
print_success "========================================"
print_success "Cleanup completed successfully!"
print_success "========================================"
echo ""

# ============================================================================
# Step 12: Verify with gitleaks
# ============================================================================
# Gated on whether gitleaks is actually available, not on SKIP_GITLEAKS. That flag also
# gets set by --files and --files-from, which say nothing about wanting the result left
# unchecked -- so choosing the file list by hand used to silently skip the only step that
# confirms the cleanup did anything.
# In --redact mode the direct check runs FIRST and is the one that counts. It
# tests the actual values against every object in history, and it proves it can
# fail. gitleaks below is a second opinion with different rules, not the proof.
REDACT_VERIFY_RC=0
if [[ "$MODE" == "redact" ]]; then
    echo ""
    print_header "Step 12a: Verifying redaction directly..."
    set +e
    verify_redaction
    REDACT_VERIFY_RC=$?
    set -e
    echo ""
fi

if [[ -n "$GITLEAKS_PATH" ]]; then
    echo ""
    print_header "Step 12: Verifying cleanup with gitleaks..."
    print_info "Running gitleaks scan to verify secrets are removed..."
    echo ""

    GITLEAKS_CMD="$GITLEAKS_PATH"
    # Use same format as detection scan for consistency
    # Exit code 0 = no secrets, 1 = secrets found
    # Temporarily disable set -e to capture exit code properly
    set +e
    run_gitleaks_json "$GITLEAKS_CMD"
    VERIFY_EXIT=$?
    set -e
    VERIFY_OUTPUT="$GITLEAKS_JSON"

    # A scan that never ran is checked first and reported as unverified. It used to reach
    # the success branch through the empty-output test, announcing a clean repository on
    # the strength of a report gitleaks had refused to write.
    if [[ "$VERIFY_EXIT" -ne 0 && "$VERIFY_EXIT" -ne 1 ]]; then
        print_error "✗ Verification did NOT run -- this cleanup is unverified."
        print_info "Check the gitleaks error above, then re-run manually:"
        print_info "  gitleaks detect --source . --log-opts=\"--all --full-history\""
    elif [[ "$VERIFY_EXIT" -eq 0 ]] || [[ "$VERIFY_OUTPUT" == "[]" ]]; then
        print_success "✓ No secrets detected by gitleaks!"
    elif [[ "$MODE" == "redact" ]] && [[ "$(count_real_findings "$VERIFY_OUTPUT")" == "0" ]]; then
        # Every remaining finding is a REPLACE_WITH_SECRET_NN placeholder.
        # generic-api-key fires on `Password=<anything>` whatever the value is, so
        # a successful redaction leaves a repo that scans dirty forever. Calling
        # that "secrets still detected" trains the operator to ignore the scanner,
        # which is worse than the noise itself.
        print_success "✓ No secrets detected by gitleaks!"
        echo ""
        print_info "gitleaks matched only the REPLACE_WITH_SECRET_NN placeholders."
        print_info "Allowlist them so future scans stay meaningful -- in .gitleaks.toml:"
        echo ""
        echo -e "  ${GRAY}[[allowlists]]${NC}"
        echo -e "  ${GRAY}description = \"Redaction placeholders left by git-secret-scrubber\"${NC}"
        echo -e "  ${GRAY}regexes = ['''^REPLACE_WITH_SECRET_[0-9]+$''']${NC}"
        echo -e "  ${GRAY}regexTarget = \"secret\"${NC}"
    else
        print_warning "gitleaks still detected some secrets!"
        print_info "This might be expected if:"
        print_info "  - Secrets exist in other files not cleaned"
        print_info "  - gitleaks is detecting false positives"
        echo ""
        print_info "Run 'gitleaks detect --source . --log-opts=\"--all\"' to see what was detected."
    fi
    echo ""
fi

print_header "Next steps:"
print_info "1. Review the changes: git log --oneline -10"
print_info "2. Verify remote is configured: git remote -v"
echo ""

if [[ ${#REMOTE_INFO[@]} -gt 0 ]]; then
    PRIMARY_REMOTE="origin"
    if [[ -z "${REMOTE_INFO[$PRIMARY_REMOTE]:-}" ]]; then
        PRIMARY_REMOTE="${!REMOTE_INFO[@]}"
        PRIMARY_REMOTE="${PRIMARY_REMOTE%% *}"
    fi
    
    print_warning "⚠️  IMPORTANT: Protected Branch Notice"
    echo ""
    print_info "If your branch is protected in GitLab/GitHub, you have these options:"
    echo ""
    print_info "Option 1: Temporarily unprotect the branch (if you have admin access)"
    print_info "  1. Go to Repository > Settings > Protected Branches"
    print_info "  2. Temporarily unprotect '$CURRENT_BRANCH'"
    print_info "  3. Force push: git push $PRIMARY_REMOTE --force --all"
    print_info "  4. Re-protect the branch after push"
    echo ""
    print_info "Option 2: Use a new branch and merge (recommended for protected branches)"
    print_info "  1. Create a new branch: git checkout -b cleanup-secrets-history"
    print_info "  2. Push new branch: git push $PRIMARY_REMOTE cleanup-secrets-history"
    print_info "  3. Create a Merge Request to replace the protected branch"
    print_info "  4. After merge, delete old branch and rename new one"
    echo ""
    print_info "Option 3: Contact repository admin"
    print_info "  Ask an admin to temporarily allow force push or unprotect the branch"
    echo ""
    print_info "3. Coordinate with your team (they must re-clone after push)"
    print_info "4. Force push (if branch is not protected):"
    echo -e "   ${CYAN}git push $PRIMARY_REMOTE --force --all${NC}"
    echo -e "   ${CYAN}git push $PRIMARY_REMOTE --force --tags${NC}"
else
    print_warning "No remote was configured. You'll need to add one before pushing:"
    print_info "  git remote add origin <your-repo-url>"
    print_info "  git push origin --force --all"
fi

echo ""
print_info "Backup branch: $BACKUP_BRANCH"
echo ""

print_error "╔══════════════════════════════════════════════════════════════════╗"
print_error "║  ⚠️  REMINDER: After force-push, ALL teammates must RE-CLONE!     ║"
print_error "║  Their local copies will be incompatible with the new history.  ║"
print_error "╚══════════════════════════════════════════════════════════════════╝"
echo ""
if [[ "$MODE" == "redact" ]]; then
    print_info "Redacted values now read REPLACE_WITH_SECRET_NN. Allowlist that string"
    print_info "in your gitleaks config, or every historical commit fails future scans."
    echo ""
fi

# A scrub that could not prove itself must not exit 0 -- CI and shell callers
# read the status, not the log.
if [[ "$MODE" == "redact" && "$REDACT_VERIFY_RC" -ne 0 ]]; then
    print_error "Exiting non-zero: redaction could not be verified."
    exit 1
fi

