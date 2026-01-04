# Contributing to Git Secret Scrubber

First off, thank you for considering contributing to Git Secret Scrubber! It's people like you that make this tool better for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)
- [Testing](#testing)
- [Questions?](#questions)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. This code of conduct outlines our expectations for participants' behavior, as well as the consequences for unacceptable behavior.

**Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.**

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/Git-Secret-Scrubber.git
   cd Git-Secret-Scrubber
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs **actual behavior**
- **Environment details:**
  - OS and version (Windows 10, Ubuntu 22.04, macOS Ventura, etc.)
  - PowerShell/Bash version
  - Python version
  - gitleaks version (if applicable)
- **Error messages** and logs (redact any secrets!)
- **Screenshots** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title** describing the enhancement
- **Detailed description** of the proposed functionality
- **Use case** — Why is this enhancement useful?
- **Possible implementation** — How might this be implemented?

### Pull Requests

1. **Ensure your PR addresses an existing issue** or create one first for discussion
2. **Follow the style guidelines** below
3. **Test your changes** on at least one platform (Windows or Linux/macOS)
4. **Update documentation** if needed
5. **Add yourself to the contributors** section if you'd like

## Development Setup

### Prerequisites

- Git 2.22+
- Python 3.6+ (for testing git-filter-repo integration)
- PowerShell 5.1+ (for Windows script testing)
- Bash 4.0+ (for Linux/macOS script testing)
- gitleaks (optional, for secret detection testing)

### Testing Environment

Create a test repository with known "secrets" to test the scripts:

```bash
# Create test repo
mkdir test-repo && cd test-repo
git init

# Create a file with fake secrets (don't use real secrets!)
echo "aws_access_key_id=AKIAIOSFODNN7EXAMPLE" > secrets.txt
git add secrets.txt
git commit -m "Add config file with test secret"

# Now test the cleanup script
../clean-secrets.sh --dry-run
```

## Submitting Changes

1. **Commit your changes** with clear, descriptive commit messages:
   ```bash
   git commit -m "Add support for custom gitleaks config"
   ```

2. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create a Pull Request** from your fork to the main repository

### Commit Message Guidelines

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues when applicable: `Fix #123: Handle edge case`

Examples:
```
Add --verbose flag for detailed output
Fix #42: Handle spaces in file paths correctly
Update README with new command line options
Refactor remote preservation logic for clarity
```

## Style Guidelines

### PowerShell (`clean-secrets.ps1`)

- Use **PascalCase** for function names: `Write-Header`, `Test-PythonInstallation`
- Use **$PascalCase** for variables: `$CurrentBranch`, `$FilesInHistory`
- Use approved verbs: `Get-`, `Set-`, `Test-`, `Write-`, `Invoke-`
- Add comments for complex logic
- Use `[CmdletBinding()]` for advanced functions when appropriate

```powershell
# Good
function Get-FilesWithSecrets {
    param(
        [string]$Path,
        [switch]$Recurse
    )
    # Implementation
}

# Bad
function getFilesWithSecrets($path, $recurse) {
    # Implementation
}
```

### Bash (`clean-secrets.sh`)

- Use **snake_case** for function names: `print_header`, `test_python`
- Use **UPPER_CASE** for constants: `RED`, `GREEN`, `DRY_RUN`
- Use **lower_case** for local variables: `file_path`, `current_branch`
- Use `[[` for conditionals (Bash-specific, more robust)
- Quote variables: `"$variable"` not `$variable`
- Add comments for complex logic

```bash
# Good
print_header() {
    local message="$1"
    echo -e "${CYAN}$message${NC}"
}

# Bad
printHeader() {
    echo -e "${CYAN}$1${NC}"
}
```

### Documentation

- Use **Markdown** for documentation files
- Include code examples where helpful
- Keep lines under 120 characters
- Use proper heading hierarchy (h1 → h2 → h3)

## Testing

### Manual Testing Checklist

Before submitting, test:

- [ ] PowerShell script on Windows
- [ ] Bash script on Linux or macOS
- [ ] `--dry-run` / `-DryRun` mode works correctly
- [ ] `--force` / `-Force` flag works
- [ ] `--skip-gitleaks` / `-SkipGitleaks` works
- [ ] Virtual environment creation works
- [ ] Remote preservation and restoration works
- [ ] Backup branch is created correctly
- [ ] Error handling works (test with invalid inputs)

### Test Scenarios

1. **Clean repository** — No secrets detected
2. **Single secret file** — One file with secrets
3. **Multiple secret files** — Several files with secrets
4. **Uncommitted changes** — Warning should appear
5. **No git repository** — Error message should appear
6. **No Python installed** — Helpful error message

## Questions?

If you have questions, feel free to:

- Open a [GitHub Discussion](https://github.com/ZarinLab/Git-Secret-Scrubber/discussions)
- Open an issue with the `question` label
- Reach out to the maintainers

---

Thank you for contributing! 🎉

