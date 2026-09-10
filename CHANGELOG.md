# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`--redact` / `-Redact`: replace secret VALUES in place instead of deleting the file.**
  Runs `git filter-repo --replace-text`, rewriting each credential to
  `REPLACE_WITH_SECRET_NN` everywhere in history while the files and their structure
  survive. The previous behaviour (whole-file removal) is unchanged and is still the
  default, now spelled `--delete-files`. Deleting a file that is still in use was the
  failure this addresses: a Helm `values.yaml` or an `appsettings.json` cannot be
  removed from history without removing the configuration with it.
- **Values are found by sweeping every blob in history, not by trusting the scanner.**
  gitleaks' report is merged in for its provider-specific rules, but the sweep is what
  finds ADO.NET connection-string fields (`Password=…;`) — unquoted and
  semicolon-delimited, so rules built around quoted secrets never match them. On a real
  452-commit repository that shape was **27 of 50** leaked values. Every pattern matches
  case-insensitively; a first pass that did not left a lowercase `password=` in history.
- **Identifier filtering, because `--replace-text` rewrites a string everywhere.**
  Excluded from redaction: kebab-case names (`redis-credentials`), segmented config keys
  (`ApiKeys_SendGridApiKeyName`, `Identity.Api.ClientSecret`), template expressions
  (`{{ … }}`, `${…}`) anywhere in the value, placeholders, and anything without at least
  two character classes. Redacting an identifier corrupts content permanently and hides
  nothing — the credential it names lives elsewhere.
- **The proposed list is shown masked and requires confirmation.** Length and a
  three-character prefix only, so a scrub does not end with every credential in a
  terminal scrollback. `--dry-run` prints it and stops.
- **Falsifiable verification.** After a redact run each value is checked against every
  object in the rewritten history, *and* the same search is required to find every value
  in the pre-rewrite history. If that control fails the search is broken, its silence
  proves nothing, and the run reports itself unverified and exits non-zero.
- **Refuses to rewrite while a linked worktree is checked out.** A worktree pins the
  commits it references, so `git gc --prune=now` cannot drop them and the old objects —
  with their secrets — survive the rewrite locally, ready to be pushed back.

### Fixed
- **Both: the run crashed after rewriting history in a repository with no remote.**
  `declare -A REMOTE_INFO` leaves the variable unset, and `${#REMOTE_INFO[@]}` under
  `set -u` is an "unbound variable" error — raised at Step 11, after the rewrite had
  already happened, which is the worst possible moment to abort.
- **PowerShell: the script could not start outside Windows.** `$env:TEMP` is a
  Windows-only variable; under PowerShell Core on macOS or Linux it is null and every
  `Join-Path $env:TEMP …` failed with "Cannot bind argument to parameter 'Path'".
- **PowerShell: `-match` is case-insensitive, and it dropped a live token.** In the
  kebab-case identifier filter, `[a-z]` therefore also matched `A-Z`, so
  `glpat-WSyTEST…` was classified as an identifier and silently excluded from
  redaction. Bash's `=~` is case-sensitive; this is the one place the two languages
  disagree by default, and it now uses `-cmatch`.
- **Bash: gitleaks detection silently reported every repository as clean on macOS.** The
  scan wrote its report to `/dev/stdout`, which on macOS is a symlink to `/dev/fd/1` and
  cannot be reopened for writing while stdout is a pipe. gitleaks pre-checks the path,
  fails with `Report path is not writable`, and exits without scanning; because its stderr
  was sent to `/dev/null` the empty report was read as "no secrets found". Reports now go
  to a temp file, and a gitleaks exit code other than 0 or 1 is surfaced instead of being
  treated as a clean result.
- **Bash: the script could not run on a stock macOS.** `declare -A` needs bash 4.0+, but
  the shebang pinned `/bin/bash`, which Apple ships as 3.2. The script aborted after the
  confirmation prompt. Now uses `#!/usr/bin/env bash`.
- **Bash: files were silently dropped from the cleanup.** The "is this path in history"
  check piped `git log` into `head -1` under `set -o pipefail`; `head` closing the pipe
  killed `git log` with SIGPIPE (exit 141), which read as "not in history". Being a race
  on how much git had written, it dropped files inconsistently — and dropped files with
  longer histories most often. Replaced with `git log -n 1`.
- **Both: cleanup was never verified when the file list was given explicitly.** The
  Step 12 verification was gated on `SkipGitleaks`, which `--files`/`--files-from` also
  set. It is now gated on whether gitleaks is available.
- **Both: `--files-from` could not take a relative path.** It was resolved after changing
  into the target repository, so the list was reported missing. Now resolved against the
  caller's directory first.
- `clean-secrets.sh` is committed with its executable bit set.

### Added
- CI regression test (`test-detection`, macOS + Ubuntu) that commits a secret, deletes it,
  and fails unless the scan finds it in history. Every previous job passed
  `--skip-gitleaks`, so no test had ever run a scan.
- ShellCheck now fails the build on `error` severity instead of being suppressed by
  `|| true` and an unconditional success message.

---

## [0.1.0] - 2026-01-04

### Added
- Initial public release
- Cross-platform support (Windows PowerShell, Linux/macOS Bash)
- Automatic secret detection using gitleaks with full git history scanning
- Interactive file selection menu
- Automatic Python virtual environment setup (in system temp directory)
- Auto-download of gitleaks if not installed (with SHA256 verification)
- User consent prompt before downloading gitleaks
- Backup branch creation before cleanup
- Remote configuration preservation and restoration
- Post-cleanup verification with gitleaks
- Dry-run mode for previewing changes (`-DryRun` / `--dry-run`)
- Force mode to skip confirmation prompts (`-Force` / `--force`)
- Skip-gitleaks mode for manual file specification (`-SkipGitleaks` / `--skip-gitleaks`)
- No-download mode to disable automatic gitleaks download (`-NoDownload` / `--no-download`)
- Repository path option (`-Path` / `--path`)
- Files list option (`-Files` / `--files`)
- Files from file option (`-FilesFrom` / `--files-from`)
- Help option (`-Help` / `--help`)
- Comprehensive documentation
- GitHub issue/PR templates
- CI workflow for linting

### Security
- Scripts validate git repository before proceeding
- Backup branches created before any destructive operations
- User confirmation required before rewriting history
- Warnings about uncommitted changes
- SHA256 checksum verification for downloaded binaries
- User consent required before downloading external binaries

---

## Version History Summary

| Version | Date | Description |
|---------|------|-------------|
| 0.1.0 | 2026-01-04 | Initial public release |

[0.1.0]: https://github.com/ZarinLab/Git-Secret-Scrubber/releases/tag/v0.1.0

