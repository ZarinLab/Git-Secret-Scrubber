# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Git Secret Scrubber, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](https://github.com/ZarinLab/Git-Secret-Scrubber/security/advisories) of this repository
   - Click "Report a vulnerability"
   - Provide details about the vulnerability

2. **Email**
   - Send an email to the maintainers (check the repository for contact information)
   - Include `[SECURITY]` in the subject line

### What to Include

Please include the following information in your report:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** of the vulnerability
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up questions

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Updates**: We will keep you informed about our progress
- **Resolution**: We aim to resolve critical vulnerabilities within 7 days
- **Credit**: We will credit you in the release notes (unless you prefer anonymity)

## Scope

This security policy applies to:

- The PowerShell script (`clean-secrets.ps1`)
- The Bash script (`clean-secrets.sh`)
- Any official releases and distributions

### Out of Scope

- Vulnerabilities in third-party dependencies (gitleaks, git-filter-repo)
  - Please report these to the respective projects
- Issues that require physical access to the machine
- Social engineering attacks

## Security Best Practices

When using Git Secret Scrubber:

1. **Run in isolated environments** when testing
2. **Review the scripts** before running them on sensitive repositories
3. **Use the `--dry-run` flag** first to preview changes
4. **Rotate any exposed secrets** immediately after cleanup
5. **Keep the tool updated** to get the latest security fixes
6. **Use `--no-download`** if you prefer to install gitleaks manually rather than allowing automatic downloads
7. **Verify checksums** - the tool verifies SHA256 checksums of downloaded binaries, but you can also verify manually

## Automatic Downloads

By default, if gitleaks is not installed, the script can download it automatically from GitHub. This download:

- Only happens with user consent (you'll be prompted)
- Displays the download URL before proceeding
- Verifies the SHA256 checksum after download
- Can be disabled with `-NoDownload` (PowerShell) or `--no-download` (Bash)

If you prefer not to allow automatic downloads, install gitleaks manually:
- **Windows**: `winget install gitleaks` or `choco install gitleaks`
- **macOS**: `brew install gitleaks`
- **Linux**: Download from https://github.com/gitleaks/gitleaks/releases

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

We recommend always using the latest version.

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. Updates will be published:

- As a new release on GitHub
- With a security advisory if the vulnerability is significant

---

Thank you for helping keep Git Secret Scrubber secure!

