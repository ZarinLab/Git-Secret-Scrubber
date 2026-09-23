# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Fixes from the 2026-09-17 review of f27e18a, ahead of rewriting ~60 production
repositories. Every item has a fixture in `tests/regressions.sh` (bash) or the
regression block of `tests/api-conformance-ps.sh` (PowerShell) that fails
against f27e18a and passes now.

### Added
- **`--replacement TEXT` / `-Replacement TEXT`** (`--redact` only): every value
  becomes TEXT instead of a numbered `REPLACE_WITH_SECRET_NN`. TEXT must be
  non-empty, one line, free of `==>` (filter-repo's separator), and share nothing
  with the values being replaced — a TEXT containing a value would write it back
  into every commit. The placeholder check after the run and the printed
  `.gitleaks.toml` allowlist both use TEXT.
- **`--yes` / `-Yes`** answers the final confirmation for non-interactive runs.
  With `--files`/`--files-from` it also selects every listed file; files proposed
  by a scan are still chosen by a person, and no guard is answered by it.
- **Exit status 3**: `--redact` skipped value(s) that are live in HEAD, so the
  repository still holds them. It used to say "SKIPPED" and exit 0 — and a run
  whose only findings were live exited 0 with "No secret values found".
- **Every rejected candidate is listed**, masked, with the rule that rejected
  it. A run without `--secrets-from` prints a loud warning that it is relying on
  the patterns alone.
- **The commit-map is kept.** Every real run copies `.git/filter-repo/commit-map`
  to `<repo>.commit-map` beside the repository (the next filter-repo run
  overwrites the original) and prints the GitLab follow-up: read-only
  `refs/merge-requests/*`, `refs/keep-around/*`, and Repository cleanup with the
  commit-map after a 30-minute wait.
- **Stash guard.** A real run refuses while `git stash list` is non-empty; a dry
  run warns. The uncommitted-changes prompt no longer advises stashing.
- **`.gitleaksignore` warning.** Its fingerprints carry commit SHAs and are all
  dead after a rewrite; the run says so and shows the `.gitleaks.toml`
  allowlist shape to move them to.
- **CI runs the conformance and regression suites** on Ubuntu and macOS, for
  both scripts. They existed and nothing ran them. Each suite now exits non-zero
  on any failure.

### Changed
- **No backup branch.** It was created inside the repository just before the
  rewrite, and filter-repo rewrites every ref — so it came out redacted too and
  backed up nothing, while the README told people to restore from it. The run
  now tells you to take a `git clone --mirror` before confirming; README "How to
  Restore" rewritten around the mirror.
- **Guards run first.** The stash and worktree guards run before any prompt or
  scan; the worktree guard used to run after "Type YES".
- **Commit messages and tag annotations are rewritten** (`--replace-message`
  with the same expressions) **and verified**: the direct check now reads every
  object (`git cat-file --batch-all-objects`), not just blobs. A token in a
  commit message used to survive while the run reported it "gone from every
  object in history".
- **Connection-string passwords skip the identifier rules.** In
  `Server=…;User Id=…;Password=summerholiday;` the position says it is a
  password; `summerholiday`, `my-db-pass-word` and `my_db_pass_word2` were all
  dropped as identifiers and the dry run said "No secret values found". Only
  placeholders are dropped there (`${…}`, `FROM_VAULT`, `__TOKEN__`, `#{…}`,
  `%…%`). Values from gitleaks and `--secrets-from` already skipped them.
- **`--secrets-from` serves many repositories.** Lines are trimmed (a list saved
  on Windows ended every value in `\r`), and values that occur nowhere in the
  repository are counted and skipped. Either case used to fail the verification
  control after the history had already been rewritten.

### Fixed
- **Bash: Apple's `/bin/bash` 3.2 is refused before any work**, with
  `brew install bash` and the command to re-run. It used to die mid-run on
  `config_flag[@]: unbound variable`, naming neither cause nor fix.
- **Both: a missing `--secrets-from` or `--gitleaks-config` file is an error**,
  and relative paths resolve against the caller's directory. The list was
  silently skipped, and the config announced as "in use" while gitleaks ran on
  stock rules.
- **Both: "No secrets detected by gitleaks!" printed after a failed scan** at
  the detection step, directly under the failure.
- **Bash: the rejected-candidates list came out empty whenever nothing was
  accepted** — `awk 'NR == FNR'` with an empty first file (caught by its test).
- **PowerShell: the object dump and the HEAD snapshot were re-encoded.** Piping
  `git cat-file`/`git archive` through PowerShell decodes with the console code
  page and `Set-Content` re-encodes: under a non-UTF-8 code page a UTF-8
  password was harvested as mojibake, its replacement rule matched nothing, and
  the value survived. Both are now copied byte for byte from the process stream.
- **PowerShell: a gitleaks exit code other than 0/1 was read as a clean
  verification.** A scan that never ran is now reported as unverified.
- **PowerShell: the exit status leaked `$LASTEXITCODE`** from the last native
  command when the script was invoked from `-Command`; it now ends in `exit 0`.
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

