# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

