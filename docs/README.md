# Documentation

This directory contains detailed documentation for Git Secret Scrubber.

## Documentation Index

| Document | Description |
|----------|-------------|
| [protected-branches.md](protected-branches.md) | Handling protected branches when force pushing |

## Topics Covered

### Protected Branches

Solutions for handling protected branches when force pushing after history cleanup:

- Temporarily unprotecting branches
- Using new branches with merge requests
- Working with repository admins
- Platform-specific instructions (GitLab, GitHub, Bitbucket)

## Command Line Options

| Option | PowerShell | Bash | Description |
|--------|-----------|------|-------------|
| Dry Run | `-DryRun` | `--dry-run` | Preview what will be cleaned without making changes |
| Force | `-Force` | `--force` | Proceed even with uncommitted changes |
| Skip Detection | `-SkipGitleaks` | `--skip-gitleaks` | Skip gitleaks detection, manually specify files |
| No Download | `-NoDownload` | `--no-download` | Disable automatic downloading of gitleaks |
| Repository Path | `-Path C:\repos\myrepo` | `--path /path/to/repo` | Path to the git repository to clean |
| Files List | `-Files "a.txt, b.txt"` | `--files "a.txt,b.txt"` | Comma-separated list of files to clean |
| Files from File | `-FilesFrom list.txt` | `--files-from list.txt` | Read files from text file (one per line) |
| Help | `-Help` or `-h` | `-h, --help` | Show help message |

## Quick Links

| Resource | Description |
|----------|-------------|
| [Main README](../README.md) | Getting started and usage |
| [Contributing](../CONTRIBUTING.md) | How to contribute |
| [Security](../SECURITY.md) | Security policy |
| [Changelog](../CHANGELOG.md) | Version history |
| [License](../LICENSE) | Apache 2.0 License |

## Need Help?

- Check the [main README](../README.md) for usage instructions
- See [Troubleshooting](../README.md#troubleshooting) for common issues
- Open an [issue](https://github.com/ZarinLab/Git-Secret-Scrubber/issues) for bugs or feature requests

