# Git Secret Scrubber

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platform">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License">
  <img src="https://img.shields.io/github/v/release/ZarinLab/Git-Secret-Scrubber?include_prereleases" alt="Release">
  <img src="https://img.shields.io/github/issues/ZarinLab/Git-Secret-Scrubber" alt="Issues">
  <img src="https://img.shields.io/github/stars/ZarinLab/Git-Secret-Scrubber?style=social" alt="Stars">
</p>

<p align="center">
  <strong>A cross-platform tool to safely remove secret-containing files from Git history</strong>
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

This tool **removes entire files** from Git history using `git filter-repo --invert-paths`. It does **not** edit file contents or surgically remove secret strings—it completely deletes selected files from all commits.

*Designed for developers and teams who have accidentally committed secrets and need a safe remediation workflow.*

| ✅ Great For | ❌ Not For |
| --- | --- |
| Removing entire files containing secrets from history | Editing secrets inside files (redacting specific strings) |
| `.env`, `secrets.json`, `*.pem`, API key files | Source code with embedded passwords |
| Configuration files with credentials | Partial file cleanup |
| Accidentally committed key files | Fine-grained secret replacement |

If you need to edit specific strings within files (e.g., replace a password with `REDACTED`), use `git filter-repo` with `--replace-text` directly.

---

## Features

- 🔍 **Automatic Secret Detection** — Uses gitleaks to scan git history and detect secrets
- 🎯 **Interactive File Selection** — Choose which files to clean with an easy-to-use menu
- ✅ **Verification** — Automatically verifies cleanup with gitleaks after completion
- 🔄 **Remote Preservation** — Automatically saves and restores git remotes
- 🛡️ **Safety First** — Creates backup branches before making changes
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
| **gitleaks** | Optional — auto-downloaded if not installed |

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
| 1 | **Setup** | Creates Python venv, installs git-filter-repo |
| 2 | **Detection** | Runs gitleaks to find secrets in history |
| 3 | **Selection** | Interactive menu to choose files |
| 4 | **Backup** | Creates backup branch |
| 5 | **Cleanup** | Removes files from entire git history |
| 6 | **Restore** | Restores git remotes (removed by filter-repo) |
| 7 | **Verify** | Runs gitleaks again to confirm cleanup |

## Command Line Options

| Option           | PowerShell                  | Bash                          | Description                                          |
|------------------|-----------------------------|-------------------------------|------------------------------------------------------|
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

Step 5: Saving remote configuration...
Step 6: Creating backup branch...
Step 7: Removing files from git history...
Step 8: Cleaning up git references...
Step 9: Restoring remote configuration...
Step 10: Verifying cleanup with gitleaks...
✓ No secrets detected by gitleaks!
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

4. **Notify your team** — Everyone must re-clone the repository

5. **Rotate secrets** — Any exposed secrets should be rotated immediately

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

If something goes wrong, restore from the backup branch:

```bash
# List backup branches
git branch | grep backup-before-secret-cleanup

# Restore from backup (replace with your backup branch name)
git reset --hard backup-before-secret-cleanup-YYYYMMDD-HHMMSS
```

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
