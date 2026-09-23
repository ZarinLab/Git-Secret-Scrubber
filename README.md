# Git Secret Scrubber

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platform">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License">
  <img src="https://img.shields.io/github/v/release/ZarinLab/Git-Secret-Scrubber?include_prereleases" alt="Release">
  <img src="https://img.shields.io/github/issues/ZarinLab/Git-Secret-Scrubber" alt="Issues">
  <img src="https://img.shields.io/github/stars/ZarinLab/Git-Secret-Scrubber?style=social" alt="Stars">
</p>

<p align="center">
  <strong>A cross-platform tool to remove secrets from Git history — delete the file, or redact the value and keep it</strong>
</p>

<p align="center">
  Automatically detects secrets using <a href="https://github.com/gitleaks/gitleaks">gitleaks</a>, provides an interactive interface to select files for complete removal from history, and verifies the cleanup afterward.
</p>

---

> ⚠️ **IMPORTANT: ROTATE YOUR SECRETS!**
> 
> **Removing secrets from git history does NOT revoke them.** If a secret was ever committed, assume it's compromised. You must rotate/invalidate any exposed API keys, passwords, tokens, or credentials immediately—even before running this tool.

---

## What This Tool Does

Two modes, both driven by `git filter-repo`. Pick the one that matches what the file *is*.

### `--delete-files` (default) — remove whole files

Removes entire files from every commit (`filter-repo --invert-paths`). For files that exist only to hold credentials.

### `--redact` — replace the values, keep the files

Finds credential-shaped **values** and replaces each with `REPLACE_WITH_SECRET_NN` — or with one fixed text of your choice, `--replacement TEXT` — everywhere in history: file contents (`filter-repo --replace-text`) and commit and tag messages (`--replace-message`), leaving the files and their structure intact.

*Designed for developers and teams who have accidentally committed secrets and need a safe remediation workflow.*

| Situation | Mode |
| --- | --- |
| `.env`, `secrets.json`, `*.pem` — the file is nothing but credentials | `--delete-files` |
| A Helm `values.yaml`, `appsettings.json`, `docker-compose.yml` still in use | `--redact` |
| Source code with an embedded password | `--redact` |
| A key file committed by accident | `--delete-files` |

**Deleting a file that is still in use is the mistake `--redact` exists to prevent.** `--delete-files` removes the configuration along with the credential, from every historical commit — so a `values.yaml` that held one password loses every setting beside it too.

### Finding the values

`--redact` does not trust the scanner's report alone. It sweeps **every object in the repository** — file contents, commit messages, tag annotations — for credential shapes and merges that with what gitleaks found, because gitleaks' rules miss whole categories:

- ADO.NET connection-string fields (`Password=…;`) are unquoted and semicolon-delimited, so rules written around quoted secrets never match them. In one real 452-commit repository this was **27 of 50** leaked values.
- Every pattern is matched case-insensitively — a lowercase `password=` is just as real as `Password=`.

It then filters out things that look like credentials but are not, because `--replace-text` rewrites a string *everywhere*: replacing an identifier corrupts content permanently. Excluded are kebab-case names (`redis-credentials`), segmented config keys (`ApiKeys_SendGridApiKeyName`, `Identity.Api.ClientSecret`), template expressions (`{{ … }}`, `${…}`), placeholders, and values without at least two character classes.

Three kinds of value skip those identifier rules, because something other than their shape says what they are:

- **the `Password=` field of a connection string** (`Server=…;User Id=…;Password=summerholiday;`) — the position makes it a password, however word-like. Only placeholders are dropped there (`${…}`, `FROM_VAULT`, `__TOKEN__`, `#{Token}`);
- **gitleaks findings**, which already passed the repository's own rules and allowlists;
- **values you name in `--secrets-from`** (one per line; trimmed, so a Windows-saved list works). Values in the list that do not occur in the repository are counted and skipped, so one list can serve many repositories.

**Every rejected candidate is listed**, masked, with the rule that rejected it. If one of them is a credential, put it in a `--secrets-from` file and re-run. Without `--secrets-from` the run prints a loud warning: it is then relying on the patterns alone.

The proposed list is shown **masked** — length and a three-character prefix — and you confirm before anything is rewritten. Use `--dry-run` to see it and stop.

### Verifying

After a `--redact` run the tool checks each value against **every object in the repository** (`git cat-file --batch-all-objects`: blobs, commits and tags), and it checks that the *same search finds every value in the pre-rewrite objects*. If that control fails, the search is broken and its silence afterwards proves nothing — the run reports itself unverified and exits non-zero.

A value still present in HEAD is **skipped** by default (rewriting it changes live configuration) and the run **exits 3**, because the repository still holds it. `--include-head-values` rewrites those too.

### Exit status

| Code | Meaning |
| --- | --- |
| 0 | Done (or nothing to do), and verified |
| 1 | Error, refused by a guard (stash, worktree, old bash, bad option), or the rewrite could not be verified |
| 3 | `--redact`: value(s) live in HEAD were skipped — the repository still holds them |

### Recommended command for a production repository

```bash
# 1. Backup: a mirror clone, OUTSIDE the working clone. The tool does not make one.
git clone --mirror git@gitlab.example.com:group/repo.git repo.mirror-backup.git

# 2. A fresh working clone (filter-repo turns its remote branches into local ones).
git clone git@gitlab.example.com:group/repo.git repo

# 3. Preview. Read the proposed AND the rejected lists; exit 3 means values are live in HEAD.
/opt/homebrew/bin/bash clean-secrets.sh repo --redact --dry-run \
    --secrets-from known-values.txt --replacement replacemetext

# 4. Rewrite, non-interactively.
/opt/homebrew/bin/bash clean-secrets.sh repo --redact \
    --secrets-from known-values.txt --replacement replacemetext --yes
```

Then push, and do the GitLab follow-up under [After Cleanup](#after-cleanup).

---

## Features

- 🔍 **Automatic Secret Detection** — Uses gitleaks to scan git history and detect secrets
- 🎯 **Interactive File Selection** — Choose which files to clean with an easy-to-use menu
- ✅ **Verification** — Automatically verifies cleanup with gitleaks after completion
- 🔄 **Remote Preservation** — Automatically saves and restores git remotes
- 🛡️ **Safety First** — Refuses to run with stash entries, linked worktrees or an old bash; tells you to take a mirror-clone backup first
- 🌍 **Cross-Platform** — Works on Windows (PowerShell), Linux, and macOS (Bash)
- 🐍 **Auto-Setup** — Automatically creates a temporary Python virtual environment and installs dependencies (nothing touches your system Python)
- 📦 **Auto-Download** — Automatically downloads gitleaks if not installed (with SHA256 verification)

> **🔒 Security Note:** By default, if gitleaks isn't installed, the script can download it automatically from GitHub with SHA256 checksum verification. Use `--no-download` (Bash) or `-NoDownload` (PowerShell) to disable automatic downloads if you prefer to install gitleaks manually.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Command Line Options](#command-line-options)
- [Example Workflow](#example-workflow)
- [Git History Rewrite Warnings](#git-history-rewrite-warnings)
- [After Cleanup](#after-cleanup)
- [Troubleshooting](#troubleshooting)
- [How to Restore from Backup](#how-to-restore-from-backup)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Git** 2.22+ | Required for git-filter-repo compatibility |
| **Python** 3.6+ | Used to run git-filter-repo (auto-installed in venv) |
| **Bash** 4.0+ | Linux/macOS only. macOS ships bash 3.2 as `/bin/bash` — run `brew install bash` |
| **gitleaks** | Optional — auto-downloaded if not installed |

> **macOS note:** the script resolves `bash` from `PATH`, so a Homebrew bash is picked up
> automatically once installed. Apple's `/bin/bash` is 3.2 and lacks associative arrays,
> which the script needs to preserve your git remotes across the rewrite. Run under 3.2
> (`/bin/bash clean-secrets.sh …`), it stops before doing anything and tells you to
> `brew install bash` and re-run with `/opt/homebrew/bin/bash`.

### Installing gitleaks (optional)

| Platform | Command |
|----------|---------|
| macOS | `brew install gitleaks` |
| Windows | `winget install gitleaks` |
| Linux | Download from [releases page](https://github.com/gitleaks/gitleaks/releases) |

> 💡 **Windows PowerShell Note:** If you get an execution policy error, run PowerShell as Administrator and execute:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

## Installation

### Option 1: Clone the Repository

```bash
git clone https://github.com/ZarinLab/Git-Secret-Scrubber.git
cd Git-Secret-Scrubber
```

### Option 2: Download Scripts Directly

Download the script for your platform:
- **Windows:** [clean-secrets.ps1](https://raw.githubusercontent.com/ZarinLab/Git-Secret-Scrubber/main/clean-secrets.ps1)
- **Linux/macOS:** [clean-secrets.sh](https://raw.githubusercontent.com/ZarinLab/Git-Secret-Scrubber/main/clean-secrets.sh)

### Make Scripts Executable (Linux/macOS)

The script is committed with the executable bit set, so a clone is ready to run. If you
downloaded it directly with `curl` or your browser, restore it:

```bash
chmod +x clean-secrets.sh
```

That's it! The scripts will automatically set up Python virtual environments when run.

## Quick Start

### Option A: Clone once, use anywhere (recommended)

```bash
# Clone Git Secret Scrubber (one-time setup)
git clone https://github.com/ZarinLab/Git-Secret-Scrubber.git
cd Git-Secret-Scrubber

# Clean any repository by passing the path as an argument
./clean-secrets.sh /path/to/your/repo                  # Linux/macOS
.\clean-secrets.ps1 "C:\path\to\your\repo"             # Windows PowerShell
```

### Option B: Run from inside the target repository

```bash
# Copy the script to your repository and run it there
cd /path/to/your/repo
./clean-secrets.sh           # Linux/macOS
.\clean-secrets.ps1          # Windows PowerShell
```

## Usage

### Windows (PowerShell)

```powershell
# Dry run to see what will be cleaned (recommended first step)
.\clean-secrets.ps1 -DryRun

# Run for real
.\clean-secrets.ps1

# Clean a specific repository (not the current directory)
.\clean-secrets.ps1 -Path "C:\repos\my-project"

# Skip gitleaks detection (manually specify files)
.\clean-secrets.ps1 -SkipGitleaks

# Specify files directly without detection
.\clean-secrets.ps1 -Files "secrets.txt,.env,config/api-keys.json"

# Read files from a text file
.\clean-secrets.ps1 -FilesFrom "files-to-clean.txt"

# Force run even with uncommitted changes
.\clean-secrets.ps1 -Force

# Disable automatic gitleaks download
.\clean-secrets.ps1 -NoDownload

# Combine flags: skip detection and disable downloads
.\clean-secrets.ps1 -SkipGitleaks -NoDownload
```

### Linux/macOS (Bash)

```bash
# Dry run to see what will be cleaned (recommended first step)
./clean-secrets.sh --dry-run

# Run for real
./clean-secrets.sh

# Clean a specific repository (not the current directory)
./clean-secrets.sh --path /home/user/repos/my-project

# Skip gitleaks detection (manually specify files)
./clean-secrets.sh --skip-gitleaks

# Specify files directly without detection
./clean-secrets.sh --files "secrets.txt,.env,config/api-keys.json"

# Read files from a text file
./clean-secrets.sh --files-from files-to-clean.txt

# Force run even with uncommitted changes
./clean-secrets.sh --force

# Disable automatic gitleaks download
./clean-secrets.sh --no-download

# Combine flags: skip detection and disable downloads
./clean-secrets.sh --skip-gitleaks --no-download
```

## How It Works

**Detect secrets → Select files → Remove from all commits → Verify cleanup.**

| Step | Action | Description |
|:----:|--------|-------------|
| 0 | **Guards** | Refuses stash entries and linked worktrees; warns about `.gitleaksignore` |
| 1 | **Setup** | Creates Python venv, installs git-filter-repo |
| 2 | **Detection** | Runs gitleaks to find secrets in history |
| 3 | **Selection** | Interactive menu to choose files (or the masked value list, in `--redact`) |
| 4 | **Confirm** | Reminds you to take a `git clone --mirror` backup; `Type YES` (or `--yes`) |
| 5 | **Cleanup** | Removes files / replaces values in the entire history |
| 6 | **Restore** | Restores git remotes (removed by filter-repo) |
| 7 | **Verify** | Direct check of every object (`--redact`), then gitleaks |
| 8 | **Commit-map** | Copies `.git/filter-repo/commit-map` beside the repository and prints the GitLab follow-up |

## Command Line Options

| Option           | PowerShell                  | Bash                          | Description                                          |
|------------------|-----------------------------|-------------------------------|------------------------------------------------------|
| Redact values    | `-Redact`                   | `--redact`                    | Replace secret VALUES in place, keeping the files    |
| Delete files     | `-DeleteFiles`              | `--delete-files`              | Remove whole files from history (default)            |
| Extra secrets    | `-SecretsFrom list.txt`     | `--secrets-from list.txt`     | Additional literal values to redact, one per line    |
| Min length       | `-MinSecretLength 12`       | `--min-secret-length 12`      | Shortest value to redact (redact mode, default 8)    |
| Replacement      | `-Replacement TEXT`         | `--replacement TEXT`          | Replace every value with TEXT instead of `REPLACE_WITH_SECRET_NN` (redact mode) |
| HEAD values      | `-IncludeHeadValues`        | `--include-head-values`       | Also rewrite values still present in HEAD (default: skipped, exit 3) |
| gitleaks config  | `-GitleaksConfig f.toml`    | `--gitleaks-config f.toml`    | Scan with this config (default: the repo's `.gitleaks.toml`) |
| Non-interactive  | `-Yes`                      | `--yes`                       | Answer the final confirmation; with `--files`/`--files-from` also select them all |
| Repository Path  | `"C:\path"` or `-Path`      | `/path` or `--path`           | Path to repository (positional or named argument)    |
| Dry Run          | `-DryRun`                   | `--dry-run`                   | Preview what will be cleaned without making changes  |
| Force            | `-Force`                    | `--force`                     | Proceed even with uncommitted changes                |
| Skip Detection   | `-SkipGitleaks`             | `--skip-gitleaks`             | Skip gitleaks detection, manually specify files      |
| No Download      | `-NoDownload`               | `--no-download`               | Disable automatic downloading of gitleaks            |
| Files List       | `-Files "a.txt, b.txt"`     | `--files "a.txt,b.txt"`       | Comma-separated list of files to clean               |
| Files from File  | `-FilesFrom list.txt`       | `--files-from list.txt`       | Read files from text file (one per line)             |
| Help             | `-Help`                     | `-h`, `--help`                | Show help message                                    |

### Input Methods

When you run the script, you'll be prompted to choose how to identify files:

1. **Automatic detection** (default) — Uses gitleaks to scan git history
2. **Comma-separated list** — Enter file paths directly
3. **Text file** — Load paths from a file (one per line, `#` for comments)

Uncommitted changes must be committed (or `--force`d past), not stashed: a run
refuses to start while `git stash list` is non-empty.

You can also skip the prompt by using command-line arguments:

```bash
# Use gitleaks (default)
./clean-secrets.sh

# Specify files directly
./clean-secrets.sh --files "secrets.txt, config/.env, old-credentials.json"

# Read from a text file
./clean-secrets.sh --files-from files-to-clean.txt
```

```powershell
# Use gitleaks (default)
.\clean-secrets.ps1

# Specify files directly
.\clean-secrets.ps1 -Files "secrets.txt, config/.env"

# Read from a text file
.\clean-secrets.ps1 -FilesFrom files-to-clean.txt
```

### Example files-to-clean.txt

```text
# Files containing secrets to remove from git history
# One file per line, comments start with #

config/secrets.yaml
.env.production
credentials/api-keys.json

# Old backup files
backup/.env.old
```

## Example Workflow

```
Step 1: Setting up virtual environment...
✓ Found Python: /usr/bin/python3
✓ Virtual environment created
✓ git-filter-repo installed

Step 2: Detecting secrets with gitleaks...
Running gitleaks scan...

Found secrets in the following files:

  [1] config/secrets.yaml
      Secrets: aws-access-key, api-token
  [2] .env.example
      Secrets: database-password

Step 3: Checking files in git history...
  ✓ Found in history: config/secrets.yaml
  ✓ Found in history: .env.example

Step 4: Select files to clean from history
  [1] config/secrets.yaml
  [2] .env.example
  [A] All files
  [N] None (cancel)

Enter file numbers (comma-separated) or 'A' for all, 'N' to cancel: A
✓ Selected all 2 files

⚠️  WARNING: This will rewrite git history!
Type 'YES' to continue: YES

Step 7: Saving remote configuration...
Step 8: Removing files from git history...
Step 9: Cleaning up git references...
Step 10: Restoring remote configuration...
Step 11: Verifying cleanup with gitleaks...
✓ No secrets detected by gitleaks!

Commit-map and GitLab follow-up
commit-map (old SHA -> new SHA) copied to:
   /path/to/repo.commit-map
```

## Git History Rewrite Warnings

> ⚠️ **This tool rewrites git history!**

Before running this tool, understand the implications:

- **All commit SHAs will change** — Every commit hash in your repository will be different
- **Team coordination required** — All team members must **re-clone** the repository
- **References will break** — Any links/references to old commit SHAs will be invalid
- **CI/CD updates may be needed** — Pipelines referencing specific commits need updating

### Protected Branches

If your branch is protected (e.g., `main`, `master`), you have options:

1. **Temporarily unprotect** the branch (if you have admin access)
2. **Use a new branch** and create a merge request
3. **Contact your repository admin**

See [docs/protected-branches.md](docs/protected-branches.md) for detailed instructions.

## After Cleanup

1. **Review changes:**
   ```bash
   git log --oneline -10
   ```

2. **Verify remote is configured:**
   ```bash
   git remote -v
   ```

3. **Force push** (if branch is not protected):
   ```bash
   git push origin --force --all
   git push origin --force --tags
   ```

4. **Keep the commit-map.** Every real run copies `.git/filter-repo/commit-map` (old SHA → new SHA) to `<repo>.commit-map` beside the repository, because the next filter-repo run overwrites the original.

5. **GitLab: the push does not remove the old commits from the server.**
   - `refs/merge-requests/*` are read-only: every merge request keeps its old head commit and its stored diff. An MR whose diff shows a secret must be *deleted* to lose it.
   - `refs/keep-around/*` pin commits referenced by pipelines, notes and MR diffs.
   - Wait 30 minutes after the push (cleanup ignores newer objects), then **Settings → Repository → Repository maintenance → Repository cleanup** (older GitLab: Settings → Repository → Repository cleanup) and upload the commit-map.

6. **`.gitleaksignore` is dead.** Its fingerprints contain commit SHAs, and every SHA changed. Move each entry to a `.gitleaks.toml` `[[allowlists]]` block with a `description` that says why it is allowed.

7. **Notify your team** — Everyone must re-clone the repository

8. **Rotate secrets** — Any exposed secrets should be rotated immediately

## Troubleshooting

### Python not found

Make sure Python 3.6+ is installed and in PATH:

| Platform | Installation Command |
|----------|---------------------|
| Windows | Download from [python.org](https://www.python.org/downloads/) or `winget install Python.Python.3.12` |
| Ubuntu/Debian | `sudo apt install python3 python3-venv` |
| macOS | `brew install python3` |
| Fedora | `sudo dnf install python3` |

### gitleaks not found

Install gitleaks or use the skip flag:
- Install: See [gitleaks releases](https://github.com/gitleaks/gitleaks/releases)
- Skip: Use `--skip-gitleaks` / `-SkipGitleaks` and manually specify files

### Virtual environment issues

Delete the `.venv` folder and run the script again:
```bash
rm -rf .venv
./clean-secrets.sh
```

### Protected branch errors

See [docs/protected-branches.md](docs/protected-branches.md) for solutions.

## How to Restore from Backup

**The tool does not make a backup.** Earlier versions created a
`backup-before-secret-cleanup-*` branch in the repository just before the
rewrite — and filter-repo rewrites every ref, so that branch was rewritten too
and backed up nothing. Take the backup yourself, before the run, outside the
working clone:

```bash
git clone --mirror /path/to/repo /path/to/repo.mirror-backup.git
```

If something goes wrong **before you push**, discard the working clone and
clone again from the mirror (or from the server, which still has the old
history). If something goes wrong **after you push**, push the mirror back:

```bash
cd /path/to/repo.mirror-backup.git
git push --mirror --force <remote-url>   # restores every branch and tag as it was
```

Pushing the mirror back restores the secrets too — rotate them either way.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for reporting instructions.

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

## Related Tools

- [gitleaks](https://github.com/gitleaks/gitleaks) — Secret detection
- [git-filter-repo](https://github.com/newren/git-filter-repo) — Git history rewriting
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) — Alternative history cleaner
- [truffleHog](https://github.com/trufflesecurity/trufflehog) — Another secret scanner

## Disclaimer

**This tool modifies git history.** Always:

- ✅ Test in a copy of your repository first
- ✅ Coordinate with your team before force pushing
- ✅ Rotate any exposed secrets immediately
- ✅ Understand the implications of rewriting git history

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/ZarinLab">ZarinLab</a>
</p>
