<#
.SYNOPSIS
    Git Secret Scrubber - Remove secrets from Git history safely.

.DESCRIPTION
    This tool removes entire files from Git history using git filter-repo.
    It does NOT edit file contents - it completely removes selected files
    from all commits in your repository's history.
    
    Automatically detects secrets using gitleaks, provides an interactive
    interface to select files for cleanup, and verifies the cleanup afterward.

.PARAMETER DryRun
    Preview what will be cleaned without making any changes.

.PARAMETER Force
    Proceed even with uncommitted changes in non-cleanup files.

.PARAMETER SkipGitleaks
    Skip gitleaks detection. Useful if gitleaks is not installed
    or you want to manually specify files to clean.

.PARAMETER NoDownload
    Disable automatic downloading of gitleaks. Use this if you prefer
    to install gitleaks manually.

.PARAMETER Path
    Path to the git repository to clean. Defaults to current directory.
    Example: -Path "C:\repos\my-project"

.PARAMETER Files
    Comma-separated list of files to clean from git history.
    Example: -Files "secrets.txt, config/.env, credentials.json"

.PARAMETER FilesFrom
    Path to a text file containing file paths to clean (one per line).
    Lines starting with # are treated as comments.
    Example: -FilesFrom "files-to-clean.txt"

.PARAMETER Help
    Show help message with all available options.

.EXAMPLE
    .\clean-secrets.ps1 -DryRun
    Preview what files would be cleaned without making changes.

.EXAMPLE
    .\clean-secrets.ps1
    Run the full cleanup process interactively.

.EXAMPLE
    .\clean-secrets.ps1 -Path "C:\repos\my-project"
    Clean a specific repository.

.EXAMPLE
    .\clean-secrets.ps1 -Files "secrets.txt, .env"
    Clean specific files without gitleaks detection.

.EXAMPLE
    .\clean-secrets.ps1 -FilesFrom "cleanup-list.txt"
    Read files to clean from a text file.

.EXAMPLE
    .\clean-secrets.ps1 -SkipGitleaks -Force
    Skip secret detection and force run even with uncommitted changes.

.EXAMPLE
    .\clean-secrets.ps1 -NoDownload
    Run without allowing automatic gitleaks download.

.NOTES
    Author: ZarinLab
    License: Apache 2.0
    Repository: https://github.com/ZarinLab/Git-Secret-Scrubber
    Version: 0.1.0

.LINK
    https://github.com/ZarinLab/Git-Secret-Scrubber
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Path = "",
    [switch]$DryRun = $false,
    [switch]$Force = $false,
    [switch]$Redact = $false,
    [switch]$DeleteFiles = $false,
    [string]$SecretsFrom = "",
    # 8, not 16: a real 10-character database password turned up in a live scrub,
    # and a higher floor would have left it in history. Length alone is a poor
    # filter -- Test-LooksLikeSecret pairs it with character-class diversity.
    [int]$MinSecretLength = 8,
    [switch]$SkipGitleaks = $false,
    [switch]$NoDownload = $false,
    [string]$Files = "",
    [string]$FilesFrom = "",
    [Alias("h")]
    [switch]$Help = $false
)

# Show help if requested
if ($Help) {
    Write-Host ""
    Write-Host "Git Secret Scrubber - Remove secrets from Git history" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage: .\clean-secrets.ps1 [PATH] [OPTIONS]" -ForegroundColor White
    Write-Host ""
    Write-Host "Arguments:" -ForegroundColor Yellow
    Write-Host "  PATH              Path to the git repository to clean (optional, default: current directory)"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -DryRun           Preview what will be cleaned without making changes"
    Write-Host "  -Force            Proceed even with uncommitted changes"
    Write-Host "  -SkipGitleaks     Skip gitleaks detection (prompt for manual input)"
    Write-Host "  -NoDownload       Disable automatic downloading of gitleaks"
    Write-Host "  -Path FOLDER      Path to the git repository (alternative to positional argument)"
    Write-Host "  -Files LIST       Comma-separated list of files to clean"
    Write-Host "                    Example: -Files 'secrets.txt, config/.env'"
    Write-Host "  -FilesFrom FILE   Read files to clean from a text file (one per line)"
    Write-Host "                    Example: -FilesFrom 'files-to-clean.txt'"
    Write-Host "  -Help, -h         Show this help message"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\clean-secrets.ps1 C:\repos\myrepo             # Clean a specific repository"
    Write-Host "  .\clean-secrets.ps1 -DryRun                     # Preview with gitleaks detection"
    Write-Host "  .\clean-secrets.ps1 -Path C:\repos\myrepo       # Same as positional argument"
    Write-Host "  .\clean-secrets.ps1 -Files 'secrets.txt,.env'   # Clean specific files"
    Write-Host "  .\clean-secrets.ps1 -FilesFrom cleanup.txt      # Read files from cleanup.txt"
    Write-Host "  .\clean-secrets.ps1 -SkipGitleaks               # Skip detection, enter files manually"
    Write-Host "  .\clean-secrets.ps1 -NoDownload                 # Disable auto-download of gitleaks"
    Write-Host ""
    Write-Host "For full documentation, use: Get-Help .\clean-secrets.ps1 -Full" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

$ErrorActionPreference = "Stop"

# Colors for output
function Write-Header { param($text) Write-Host $text -ForegroundColor Cyan }
function Write-Success { param($text) Write-Host $text -ForegroundColor Green }
function Write-Warning { param($text) Write-Host $text -ForegroundColor Yellow }
function Write-Error { param($text) Write-Host $text -ForegroundColor Red }
function Write-Info { param($text) Write-Host $text -ForegroundColor Gray }

# $env:TEMP is a Windows-only variable: under PowerShell Core on macOS or Linux it
# is null, and every `Join-Path $env:TEMP ...` then fails with "Cannot bind
# argument to parameter 'Path' because it is null". Resolved once, here, so the
# three call sites cannot drift apart.
$script:TempRoot = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }

# ============================================================================
# Redaction mode (-Redact)
# ============================================================================

$script:GssTmpDir = $null
function Initialize-GssTmpDir {
    if ($script:GssTmpDir) { return }
    $script:GssTmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("gss-work-" + [System.Guid]::NewGuid().ToString("N").Substring(0,8))
    New-Item -ItemType Directory -Path $script:GssTmpDir -Force | Out-Null
}

# Concatenate every blob in history into one file.
#
# Used twice: to harvest candidate secrets, and afterwards to prove each one is
# gone. The gitleaks report alone is not enough for either job -- its rules miss
# whole categories of credential (see Get-SecretCandidates).
function Export-HistoryBlobs {
    param([string]$OutFile)
    Initialize-GssTmpDir
    $idx = Join-Path $script:GssTmpDir "blob-index"
    # One --batch pass rather than a cat-file per blob: on a repo with real
    # history the per-blob loop takes minutes where this takes a second. The
    # interleaved "<sha> blob <size>" headers are harmless -- the file is only
    # ever searched for literal secret values.
    git rev-list --objects --all 2>$null |
        ForEach-Object { ($_ -split ' ')[0] } |
        git cat-file --batch-check='%(objectname) %(objecttype)' 2>$null |
        Where-Object { $_ -match '\sblob$' } |
        ForEach-Object { ($_ -split ' ')[0] } |
        Sort-Object -Unique | Set-Content -Path $idx -Encoding ascii
    Get-Content $idx | git cat-file --batch --buffer 2>$null | Set-Content -Path $OutFile -Encoding utf8
    Remove-Item $idx -ErrorAction SilentlyContinue
}

# Decide whether a captured string is a credential or an identifier.
#
# Erring permissive is not cosmetic: --replace-text rewrites the string
# EVERYWHERE, so redacting an identifier corrupts that content permanently.
function Test-LooksLikeSecret {
    param([string]$Value)
    if ($Value.Length -lt $script:MinSecretLen) { return $false }

    # Placeholders and template expressions hold no credential.
    # -cmatch, not -match: PowerShell's -match is case-INSENSITIVE by default,
    # which is the opposite of bash's =~ and would reject any value merely
    # starting with the letters "change" or "sample" in any casing.
    if ($Value -cmatch '^(REPLACE|CHANGE|PLACEHOLDER|TODO|EXAMPLE|DUMMY|SAMPLE|CHANGEME|YOUR_|xxx|XXX)') { return $false }
    if ($Value.StartsWith('$') -or $Value.StartsWith('<') -or $Value.StartsWith('lookup(') -or $Value.StartsWith('process.env.')) { return $false }

    # A template expression ANYWHERE in the value, not only at the start: a Helm
    # value like `amir-{{ include (print ...) }}` was captured whole by the
    # quoted-value pattern and passed a start-anchored check.
    if ($Value.Contains('{{') -or $Value.Contains('}}') -or $Value.Contains('${')) { return $false }

    # Segmented identifier paths with no digits: ApiKeys_SendGridApiKeyName,
    # Identity.Api.ClientSecret, Recaptcha:SiteKey. These are configuration KEY
    # names -- including token names that REFERENCE a vault secret rather than
    # containing one. Redacting them rewrites the reference and breaks config
    # while hiding nothing. The no-digit condition keeps real segmented tokens
    # safe: a SendGrid key is segmented too, but its segments carry digits.
    if ($Value -match '^[A-Za-z][A-Za-z0-9]*([._:]+[A-Za-z][A-Za-z0-9]*)+$' -and $Value -notmatch '[0-9]') { return $false }

    # kebab-case is how Kubernetes Secret names and DNS labels are written. The
    # identifier belongs in git; the credential it names lives elsewhere.
    #
    # ⚠️ -cmatch is load-bearing. With the default case-INSENSITIVE -match, [a-z]
    # also matches A-Z, so this rule swallowed `glpat-WSyTESTtoken123456789` as
    # "kebab-case" and silently dropped a live GitLab token from the redaction
    # list. The bash implementation uses =~, which is case-sensitive; this is the
    # single place the two languages disagree by default.
    if ($Value -cmatch '^[a-z][a-z0-9]*(-[a-z0-9]+)+$') { return $false }

    # Character-class diversity rather than entropy: cheap, and it is what keeps
    # a short lowercase word out of a global search-and-replace.
    $classes = 0
    if ($Value -cmatch '[a-z]') { $classes++ }
    if ($Value -cmatch '[A-Z]') { $classes++ }
    if ($Value -match '[0-9]') { $classes++ }
    if ($Value -match '[^a-zA-Z0-9]') { $classes++ }
    return ($classes -ge 2)
}

# Harvest candidate secret values from the blob dump and the gitleaks report.
#
# Every pattern is case-insensitive: a lowercase `password=` is as real as
# `Password=`, and matching only the capitalised form leaves secrets behind.
function Get-SecretCandidates {
    param([string]$BlobFile, [string]$GitleaksJson)
    $found = New-Object System.Collections.Generic.HashSet[string]

    # gitleaks first: its rules carry provider-specific knowledge a generic
    # sweep does not have.
    if ($GitleaksJson -and $GitleaksJson -ne "[]" -and $GitleaksJson -ne "null") {
        try {
            foreach ($f in ($GitleaksJson | ConvertFrom-Json)) {
                if ($f.Secret) { [void]$found.Add([string]$f.Secret) }
            }
        } catch { }
    }

    $patterns = @(
        # Connection-string credentials. THIS is the shape gitleaks misses most
        # often -- unquoted and semicolon-delimited, so rules built around quoted
        # secrets never see it. In one real repo it was 27 of 50 leaked values.
        @{ Rx = '(?i)password\s*=\s*([^;"''\s]+)';                                     Group = 1 },
        @{ Rx = '(?i)(?:secretkey|accesskeyid|access_key_id|apikey|api_key|clientsecret|client_secret)\s*[:=]\s*"?([^",;\s}]+)'; Group = 1 },
        # Credentials in a URL userinfo component (amqp://, mongodb://, postgres://).
        @{ Rx = '://[^/\s:@"]{2,}:([^@\s"'']{4,})@';                                    Group = 1 },
        # Provider tokens with a fixed, unmistakable prefix.
        @{ Rx = '(AKIA[0-9A-Z]{16})';                                                  Group = 1 },
        @{ Rx = '(glpat-[A-Za-z0-9_-]{15,})';                                          Group = 1 },
        @{ Rx = '(gh[pousr]_[A-Za-z0-9]{20,})';                                        Group = 1 },
        @{ Rx = '(SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})';                        Group = 1 },
        @{ Rx = '(xox[baprs]-[A-Za-z0-9-]{10,})';                                      Group = 1 },
        # Quoted values under a credential-ish key.
        @{ Rx = '(?i)"?(?:password|passwd|pwd|secret|token|apikey)"?\s*:\s*"([^"]{8,})"'; Group = 1 }
    )

    # Streamed, not Get-Content -Raw: a large repository's blob dump does not
    # need to be held in memory in one string.
    foreach ($line in [System.IO.File]::ReadLines($BlobFile)) {
        foreach ($p in $patterns) {
            foreach ($m in [regex]::Matches($line, $p.Rx)) {
                $v = $m.Groups[$p.Group].Value
                if ($v) { [void]$found.Add($v) }
            }
        }
    }

    if ($SecretsFrom -and (Test-Path $SecretsFrom)) {
        foreach ($l in Get-Content $SecretsFrom) {
            if ($l.Trim()) { [void]$found.Add($l.Trim()) }
        }
    }

    # Longest first. --replace-text applies rules in file order, so a secret that
    # is a prefix of a longer one must be replaced second or it truncates the
    # longer match and leaves its tail in history.
    return @($found | Where-Object { Test-LooksLikeSecret $_ } | Sort-Object -Property Length -Descending)
}

# Show a secret without printing it. Length and a three-character prefix let an
# operator recognise a value they know; the rest stays hidden so a scrub does not
# end with the whole credential set in a terminal scrollback.
function Format-MaskedSecret {
    param([string]$Value)
    $prefix = if ($Value.Length -ge 3) { $Value.Substring(0,3) } else { $Value }
    return ("len={0,-4} {1}..." -f $Value.Length, $prefix)
}

# Refuse to rewrite while a linked worktree is checked out.
#
# A worktree pins the commits it references. `git gc --prune=now` cannot drop
# them, so the old objects -- and every secret in them -- survive the rewrite in
# the local repository, ready to be pushed back.
function Test-StaleWorktrees {
    $lines = @(git worktree list --porcelain 2>$null | Where-Object { $_ -like 'worktree *' })
    if ($lines.Count -le 1) { return }
    Write-Host ""
    Write-Error "This repository has $($lines.Count - 1) linked worktree(s):"
    git worktree list 2>$null | Select-Object -Skip 1 | ForEach-Object { Write-Host "    $_" }
    Write-Host ""
    Write-Warning "A worktree pins the commits it has checked out. They survive the"
    Write-Warning "rewrite and 'git gc --prune=now' cannot remove them, so the old"
    Write-Warning "history -- and its secrets -- stays in this repository."
    Write-Host ""
    Write-Info "Remove them first:  git worktree remove <path>"
    Write-Info "Or prune abandoned ones:  git worktree prune"
    Write-Host ""
    if (-not $Force) {
        $wt = Read-Host "Type 'IGNORE' to rewrite anyway (not recommended)"
        if ($wt -ne "IGNORE") {
            Write-Info "Aborted. Remove the worktrees and re-run."
            exit 1
        }
    }
}

# Count gitleaks findings that are NOT the placeholders this tool introduced.
function Get-RealFindingCount {
    param([string]$Json)
    try {
        $data = $Json | ConvertFrom-Json
    } catch {
        # Unparseable output is not evidence of a clean repo.
        return -1
    }
    if (-not $data) { return 0 }
    return @($data | Where-Object { [string]$_.Secret -notmatch '^REPLACE_WITH_SECRET_[0-9]+$' }).Count
}

# Prove the rewrite worked -- and prove the proof can fail.
#
# "gitleaks found nothing" is a weak claim: it is also what a scan that never ran
# says. This checks each value directly, and checks that the same search FINDS
# every value in the pre-rewrite dump. If it does not, the search is broken and
# its silence afterwards means nothing.
function Test-Redaction {
    param([string[]]$Secrets, [string]$PreBlobs)
    Initialize-GssTmpDir
    $post = Join-Path $script:GssTmpDir "blobs-after"
    Export-HistoryBlobs -OutFile $post

    $preText  = [System.IO.File]::ReadAllText($PreBlobs)
    $postText = [System.IO.File]::ReadAllText($post)

    $survivors = 0; $foundBefore = 0
    foreach ($sec in $Secrets) {
        if ($preText.Contains($sec))  { $foundBefore++ }
        if ($postText.Contains($sec)) {
            $survivors++
            Write-Error "  STILL PRESENT: $(Format-MaskedSecret $sec)"
        }
    }

    Write-Host ""
    if ($foundBefore -ne $Secrets.Count) {
        Write-Error "✗ Verification is NOT trustworthy."
        Write-Info "  Only $foundBefore of $($Secrets.Count) values were found in the pre-rewrite"
        Write-Info "  history, so this search cannot detect a failure. Do not treat a"
        Write-Info "  clean result as proof."
        return $false
    }
    Write-Info "Control: all $($Secrets.Count) value(s) were present before the rewrite,"
    Write-Info "so this check is able to fail."

    if ($survivors -gt 0) {
        Write-Error "✗ $survivors of $($Secrets.Count) value(s) SURVIVED the rewrite."
        Write-Info "  Restore from the backup branch and re-run."
        return $false
    }
    Write-Success "✓ All $($Secrets.Count) value(s) are gone from every object in history."
    return $true
}

# Resolve -FilesFrom against the caller's directory BEFORE changing into the repo,
# otherwise a relative path stops resolving the moment we Set-Location and the list
# reads as missing.
if ($FilesFrom -and -not [System.IO.Path]::IsPathRooted($FilesFrom)) {
    $FilesFrom = Join-Path (Get-Location).Path $FilesFrom
}

# Change to specified path if provided
if ($Path) {
    if (Test-Path $Path) {
        Set-Location $Path
        Write-Info "Working in: $Path"
    } else {
        Write-Host "Error: Path not found: $Path" -ForegroundColor Red
        exit 1
    }
}

Write-Header "========================================"
Write-Header "Git History Secret Cleanup Script"
Write-Header "========================================"
Write-Host ""

# Display important security reminder
Write-Host ""
Write-Error "╔══════════════════════════════════════════════════════════════════╗"
Write-Error "║  ⚠️  IMPORTANT: ROTATE YOUR SECRETS IMMEDIATELY!                  ║"
Write-Error "║                                                                  ║"
Write-Error "║  Removing secrets from git history does NOT revoke them.        ║"
Write-Error "║  Any secrets that were exposed should be rotated/invalidated.   ║"
Write-Error "╚══════════════════════════════════════════════════════════════════╝"
Write-Host ""

# Check if we're in a git repository
if (-not (Test-Path ".git")) {
    Write-Error "ERROR: Not in a git repository!"
    exit 1
}

# Get current branch
$currentBranch = git branch --show-current
Write-Info "Current branch: $currentBranch"
Write-Host ""

# ============================================================================
# Detection Method Selection (if not specified via command line)
# ============================================================================
$detectionMethod = ""
$manualFiles = $Files
$filesFromPath = $FilesFrom

# Mode. -Redact and -DeleteFiles are mutually exclusive; default is delete, which
# is what this tool did before redaction existed.
if ($Redact -and $DeleteFiles) {
    Write-Error "Choose one of -Redact or -DeleteFiles, not both."
    exit 1
}
$script:Mode = if ($Redact) { "redact" } else { "delete" }
$script:MinSecretLen = $MinSecretLength
$script:SecretValues = @()
$script:PreBlobs = $null
$script:ReplacementsFile = $null
$script:RedactVerifyOk = $true
$script:GitleaksRawJson = $null

# Check if user already specified files via command line
if ($manualFiles) {
    $detectionMethod = "files"
    Write-Info "Using files from -Files argument"
} elseif ($filesFromPath) {
    $detectionMethod = "file"
    Write-Info "Using files from: $filesFromPath"
    if (-not (Test-Path $filesFromPath)) {
        Write-Error "File not found: $filesFromPath"
        exit 1
    }
} elseif ($SkipGitleaks) {
    # User wants to skip gitleaks but didn't provide files - will prompt later
    $detectionMethod = "manual"
} elseif ($script:Mode -eq "redact") {
    # -Redact does not work from a file list at all: it finds credential-shaped
    # VALUES by sweeping every blob, then replaces them wherever they appear. The
    # "which files?" question has no meaning here.
    $detectionMethod = "gitleaks"
    Write-Info "Mode -Redact: scanning history for secret values"
} else {
    # Ask user how they want to detect secrets
    Write-Host ""
    Write-Header "How would you like to identify files with secrets?"
    Write-Host ""
    Write-Host "  [1] Automatic detection using gitleaks (recommended)" -ForegroundColor Cyan
    Write-Host "      Scans git history for secrets automatically" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] Enter a comma-separated list of files" -ForegroundColor Cyan
    Write-Host "      Example: secrets.txt, config/.env, credentials.json" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [3] Load files from a text file" -ForegroundColor Cyan
    Write-Host "      One file path per line, supports # comments" -ForegroundColor Gray
    Write-Host ""
    
    $detectionChoice = Read-Host "Select option [1/2/3] (default: 1)"
    
    switch ($detectionChoice) {
        "2" {
            $detectionMethod = "files"
            $SkipGitleaks = $true
            Write-Host ""
            Write-Info "Enter the file paths to clean from git history."
            Write-Info "Separate multiple files with commas."
            Write-Host ""
            $manualFiles = Read-Host "File paths"
            if ([string]::IsNullOrWhiteSpace($manualFiles)) {
                Write-Error "No files specified. Exiting."
                exit 1
            }
        }
        "3" {
            $detectionMethod = "file"
            $SkipGitleaks = $true
            Write-Host ""
            Write-Info "Enter the path to a text file containing file paths to clean."
            Write-Info "The file should have one path per line. Lines starting with # are ignored."
            Write-Host ""
            $filesFromPath = Read-Host "Text file path"
            if ([string]::IsNullOrWhiteSpace($filesFromPath)) {
                Write-Error "No file specified. Exiting."
                exit 1
            }
            if (-not (Test-Path $filesFromPath)) {
                Write-Error "File not found: $filesFromPath"
                exit 1
            }
        }
        default {
            $detectionMethod = "gitleaks"
            Write-Info "Using automatic detection with gitleaks"
        }
    }
}

Write-Host ""

# Check for uncommitted changes
$status = git status --porcelain
if ($status) {
    # List of cleanup-related files that are safe to have uncommitted
    $cleanupFiles = @(
        "clean-secrets.ps1",
        "clean-secrets.sh",
        "docs/protected-branches.md",
        "docs/README.md",
        ".gitignore",
        "README.md"
    )
    
    # Check if uncommitted changes are only cleanup files
    $statusLines = $status -split "`n" | Where-Object { $_.Trim() -ne "" }
    $nonCleanupFiles = @()
    
    foreach ($line in $statusLines) {
        $file = ($line -replace '^\S+\s+', '').Trim()
        # Remove quotes if present
        $file = $file -replace '^"|"$', ''
        
        # Handle rename lines: "old -> new" - extract just the new filename
        if ($file -match ' -> ') {
            $file = ($file -split ' -> ')[-1]
            # Also remove quotes from the new name if present
            $file = $file -replace '^"|"$', ''
        }
        
        $isCleanupFile = $false
        foreach ($cleanupFile in $cleanupFiles) {
            if ($file -eq $cleanupFile -or $file -like "*\$cleanupFile") {
                $isCleanupFile = $true
                break
            }
        }
        
        if (-not $isCleanupFile) {
            $nonCleanupFiles += $file
        }
    }
    
    if ($nonCleanupFiles.Count -gt 0) {
        Write-Warning "WARNING: You have uncommitted changes in files that are NOT part of this cleanup tool!"
        Write-Warning "Modified files:"
        foreach ($file in $nonCleanupFiles) {
            Write-Host "  - $file" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Info "It's recommended to commit or stash these changes before cleaning git history."
        Write-Host ""
        
        if (-not $Force) {
            $proceed = Read-Host "Do you want to proceed anyway? (yes/no) [default: no]"
            if ([string]::IsNullOrWhiteSpace($proceed) -or ($proceed -ne "yes" -and $proceed -ne "y")) {
                Write-Info "Aborted. Please commit or stash your changes first, or use -Force flag to skip this prompt."
                exit 0
            } else {
                Write-Warning "Proceeding with uncommitted changes in other files..."
                Write-Host ""
            }
        } else {
            Write-Warning "Proceeding with -Force flag (you have uncommitted changes in other files)..."
            Write-Host ""
        }
    } else {
        Write-Info "Uncommitted changes are only in cleanup script files - this is OK."
        Write-Host ""
    }
}

# ============================================================================
# Step 1: Setup git-filter-repo (prefer system binary, fallback to venv)
# ============================================================================
Write-Header "Step 1: Setting up git-filter-repo..."

# Create unique temp paths based on repo name and PID to avoid collisions
$repoName = (Split-Path -Leaf (Get-Location)) -replace ' ', '_'
# $env:TEMP is a Windows-only variable: under PowerShell Core on macOS or Linux
# it is null, and Join-Path then fails with "Cannot bind argument to parameter
# 'Path' because it is null" before the script does any work at all.
$tempBase = Join-Path $script:TempRoot "git-secret-scrubber-${repoName}-$PID"
$venvPath = Join-Path $tempBase "venv"
$binDir = Join-Path $tempBase "bin"

$pythonExe = $null
$useSystemFilterRepo = $false
$filterRepoCmd = $null

# Check if git-filter-repo is already installed system-wide
$filterRepoExe = Get-Command git-filter-repo -ErrorAction SilentlyContinue
if ($filterRepoExe) {
    $filterRepoCmd = $filterRepoExe.Source
    $useSystemFilterRepo = $true
    Write-Success "Found system git-filter-repo: $filterRepoCmd"
}

# Function to test if Python is actually working (not a Windows Store stub)
function Test-PythonInstallation {
    param([string]$pythonPath)
    
    try {
        # Try to get Python version - this will fail if it's a Windows Store stub
        $versionOutput = & $pythonPath --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $versionOutput -match "Python \d+\.\d+") {
            # Also check if it's not in WindowsApps (which is usually a stub)
            if ($pythonPath -notlike "*WindowsApps*") {
                return $true
            }
            # Even if in WindowsApps, if it works, use it
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

# Check for Python in PATH first
$pythonCommands = @("python3", "python")
foreach ($cmd in $pythonCommands) {
    try {
        $cmdInfo = Get-Command $cmd -ErrorAction Stop
        if (Test-PythonInstallation -pythonPath $cmdInfo.Source) {
            $pythonExe = $cmdInfo
            Write-Success "Found Python: $($pythonExe.Source)"
            break
        } else {
            Write-Info "Found $cmd but it doesn't work (likely Windows Store stub), trying alternatives..."
        }
    } catch {
        continue
    }
}

# If not found in PATH, try common installation locations
if (-not $pythonExe) {
    Write-Info "Python not found in PATH, checking common installation locations..."
    
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe",
        "$env:ProgramFiles\Python*\python.exe",
        "$env:ProgramFiles(x86)\Python*\python.exe",
        "$env:USERPROFILE\AppData\Local\Programs\Python\Python*\python.exe"
    )
    
    foreach ($pathPattern in $commonPaths) {
        $pythonPaths = Get-ChildItem -Path $pathPattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        foreach ($pythonPath in $pythonPaths) {
            if (Test-PythonInstallation -pythonPath $pythonPath.FullName) {
                $pythonExe = @{ Source = $pythonPath.FullName }
                Write-Success "Found Python: $($pythonExe.Source)"
                break
            }
        }
        if ($pythonExe) { break }
    }
}

if (-not $pythonExe) {
    Write-Error "ERROR: Python is not installed or not working!"
    Write-Host ""
    Write-Info "Please install Python from one of these sources:"
    Write-Info "  1. Official Python: https://www.python.org/downloads/"
    Write-Info "  2. Microsoft Store: Search for 'Python' in Microsoft Store"
    Write-Info "  3. Chocolatey: choco install python"
    Write-Info "  4. Winget: winget install Python.Python.3.12"
    Write-Host ""
    Write-Warning "Note: If Python is installed but not found, make sure it's added to PATH"
    exit 1
}

# Set up venv paths (used later even if system git-filter-repo is available)
$pipPath = Join-Path $venvPath "Scripts\pip.exe"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

# Only create venv and install git-filter-repo if system version not available
if (-not $useSystemFilterRepo) {
    Write-Info "git-filter-repo not found in PATH, setting up via Python venv..."
    
    # Create virtual environment if it doesn't exist
    if (-not (Test-Path $venvPath)) {
        Write-Info "Creating virtual environment at $venvPath..."
        
        # Test Python before using it
        $testResult = & $pythonExe.Source --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Python executable is not working: $($pythonExe.Source)"
            Write-Info "Output: $testResult"
            exit 1
        }
        
        # Create venv
        $venvOutput = & $pythonExe.Source -m venv $venvPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to create virtual environment!"
            Write-Info "Error output: $venvOutput"
            Write-Host ""
            Write-Info "Try running manually: $($pythonExe.Source) -m venv $venvPath"
            exit 1
        }
        Write-Success "Virtual environment created"
    } else {
        Write-Info "Virtual environment already exists"
    }

    # Verify pip exists
    if (-not (Test-Path $pipPath)) {
        Write-Error "pip not found in virtual environment: $pipPath"
        Write-Info "The virtual environment may be corrupted. Try deleting $venvPath and running again."
        exit 1
    }

    # Install git-filter-repo if not already installed
    Write-Info "Installing git-filter-repo..."
    $pipOutput = & $pipPath install git-filter-repo --quiet --disable-pip-version-check 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install git-filter-repo!"
        Write-Info "Error output: $pipOutput"
        Write-Host ""
        Write-Info "Try running manually: $pipPath install git-filter-repo"
        exit 1
    }
    Write-Success "git-filter-repo installed via pip"
} else {
    # Use system Python for venvPython path (for consistency in later usage)
    $venvPython = $pythonExe.Source
}

Write-Host ""

# ============================================================================
# Step 2: Check for gitleaks (optional - may skip if not needed)
# ============================================================================
Write-Header "Step 2: Checking for gitleaks..."

$gitleaksExe = Get-Command gitleaks -ErrorAction SilentlyContinue
$gitleaksPath = $null

if ($gitleaksExe) {
    $gitleaksPath = $gitleaksExe.Source
    Write-Success "Found gitleaks: $gitleaksPath"
} elseif (-not $SkipGitleaks -and $NoDownload) {
    Write-Warning "gitleaks not found and -NoDownload specified."
    Write-Info "Please install gitleaks manually or use -SkipGitleaks"
    Write-Info "  winget install gitleaks"
    Write-Info "  choco install gitleaks"
    $SkipGitleaks = $true
} elseif (-not $SkipGitleaks -and -not $NoDownload) {
    Write-Info "gitleaks not found in PATH. Attempting to download..."
    
    # Create bin directory for gitleaks in temp location
    if (-not (Test-Path $binDir)) {
        New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    }
    
    # Determine OS and architecture
    $arch = if ([Environment]::Is64BitOperatingSystem) { "64bit" } else { "32bit" }
    $os = "windows"
    $ext = ".exe"
    
    # Temporarily allow errors for API call
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    
    # Get latest version from GitHub API
    try {
        Write-Info "Fetching latest gitleaks version..."
        $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" -ErrorAction Stop
        $version = $latestRelease.tag_name -replace '^v', ''
        $gitleaksVersion = $latestRelease.tag_name
        
        Write-Info "Latest version: $gitleaksVersion"
        
        # Determine download URL - gitleaks Windows binaries are direct .exe files
        # Try multiple naming patterns as gitleaks naming has changed over versions
        $assetPatterns = @(
            "gitleaks_${version}_windows_x64.exe",
            "gitleaks_${version}_windows_amd64.exe",
            "gitleaks_${version}_windows_x86_64.exe"
        )
        
        $downloadUrl = $null
        foreach ($pattern in $assetPatterns) {
            $asset = $latestRelease.assets | Where-Object { $_.name -eq $pattern } | Select-Object -First 1
            if ($asset) {
                $downloadUrl = $asset.browser_download_url
                $assetName = $pattern
                break
            }
        }
        
        # If no direct exe, try zip (some versions distribute as zip)
        if (-not $downloadUrl) {
            $zipPatterns = @(
                "gitleaks_${version}_windows_x64.zip",
                "gitleaks_${version}_windows_amd64.zip"
            )
            foreach ($pattern in $zipPatterns) {
                $asset = $latestRelease.assets | Where-Object { $_.name -eq $pattern } | Select-Object -First 1
                if ($asset) {
                    $downloadUrl = $asset.browser_download_url
                    $assetName = $pattern
                    break
                }
            }
        }
        
        # Get checksums URL
        $checksumAsset = $latestRelease.assets | Where-Object { $_.name -eq "gitleaks_${version}_checksums.txt" } | Select-Object -First 1
        $checksumUrl = if ($checksumAsset) { $checksumAsset.browser_download_url } else { $null }
        
        if ($downloadUrl) {
            # Ask user for permission to download
            Write-Host ""
            Write-Warning "gitleaks is required for automatic secret detection."
            Write-Warning "We can download it for you, or you can install it manually."
            Write-Host ""
            Write-Info "Version: $gitleaksVersion"
            Write-Info "Download URL: $downloadUrl"
            if ($checksumUrl) {
                Write-Info "Checksums: $checksumUrl"
            }
            Write-Host ""
            Write-Info "Manual installation options:"
            Write-Info "  winget install gitleaks"
            Write-Info "  choco install gitleaks"
            Write-Info "  Download from: https://github.com/gitleaks/gitleaks/releases"
            Write-Host ""
            
            $downloadChoice = Read-Host "Download gitleaks automatically? (yes/no) [default: yes]"
            if ([string]::IsNullOrWhiteSpace($downloadChoice) -or $downloadChoice -eq "yes" -or $downloadChoice -eq "y") {
                Write-Info "Downloading gitleaks $gitleaksVersion..."
                
                # Download with progress
                $ProgressPreference = 'SilentlyContinue'
                $downloadPath = Join-Path $binDir $assetName
                
                try {
                    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
                    
                    # Verify checksum if available
                    if ($checksumUrl -and (Test-Path $downloadPath)) {
                        Write-Info "Verifying checksum..."
                        try {
                            $checksumContent = Invoke-WebRequest -Uri $checksumUrl -ErrorAction Stop | Select-Object -ExpandProperty Content
                            $expectedHash = ($checksumContent -split "`n" | Where-Object { $_ -like "*$assetName*" } | Select-Object -First 1) -replace '\s+.*$', ''
                            
                            if ($expectedHash) {
                                $actualHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash.ToLower()
                                $expectedHash = $expectedHash.ToLower()
                                
                                if ($actualHash -eq $expectedHash) {
                                    Write-Success "Checksum verified: $actualHash"
                                } else {
                                    Write-Error "Checksum mismatch!"
                                    Write-Error "Expected: $expectedHash"
                                    Write-Error "Actual:   $actualHash"
                                    Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
                                    $SkipGitleaks = $true
                                }
                            } else {
                                $actualHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash.ToLower()
                                Write-Warning "Could not find checksum for $assetName"
                                Write-Info "SHA256: $actualHash"
                            }
                        } catch {
                            Write-Warning "Could not verify checksum: $($_.Exception.Message)"
                        }
                    }
                    
                    if (-not $SkipGitleaks) {
                        if ($assetName -like "*.zip") {
                            # Extract zip
                            Write-Info "Extracting gitleaks from archive..."
                            Expand-Archive -Path $downloadPath -DestinationPath $binDir -Force
                            Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
                            $gitleaksPath = Join-Path $binDir "gitleaks.exe"
                        } else {
                            # Direct exe - rename to standard name
                            $gitleaksPath = Join-Path $binDir "gitleaks.exe"
                            if ($downloadPath -ne $gitleaksPath) {
                                Move-Item -Path $downloadPath -Destination $gitleaksPath -Force
                            }
                        }
                        
                        if (Test-Path $gitleaksPath) {
                            $gitleaksPath = (Resolve-Path $gitleaksPath).Path
                            
                            # Show version info
                            $installedVersion = & $gitleaksPath version 2>$null
                            Write-Success "gitleaks installed successfully"
                            Write-Info "Version: $installedVersion"
                        } else {
                            Write-Warning "gitleaks binary not found after download"
                            $SkipGitleaks = $true
                        }
                    }
                } catch {
                    Write-Warning "Download failed: $($_.Exception.Message)"
                    $SkipGitleaks = $true
                }
            } else {
                # User declined download
                Write-Info "Skipping gitleaks download."
                Write-Info "You can install it manually and run this script again."
                $SkipGitleaks = $true
            }
        } else {
            Write-Warning "Could not find Windows binary in release assets"
            Write-Info "Please install gitleaks manually:"
            Write-Info "  winget install gitleaks"
            Write-Info "  Or download from: https://github.com/gitleaks/gitleaks/releases"
            $SkipGitleaks = $true
        }
    } catch {
        Write-Warning "Failed to download gitleaks automatically: $($_.Exception.Message)"
        Write-Info "Please install gitleaks manually:"
        Write-Info "  winget install gitleaks"
        Write-Info "  Or download from: https://github.com/gitleaks/gitleaks/releases"
        $SkipGitleaks = $true
    } finally {
        # Restore error action preference
        $ErrorActionPreference = $oldErrorAction
    }
}

# Final check: if we don't have gitleaks at this point, skip it
if (-not $SkipGitleaks -and -not $gitleaksPath -and -not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Warning "gitleaks is not available. Skipping automatic detection."
    Write-Info "You can manually specify files to clean."
    $SkipGitleaks = $true
}

if ($SkipGitleaks) {
    Write-Info "Skipping gitleaks (not installed or download failed)"
} else {
    Write-Header "Step 3: Detecting secrets with gitleaks..."
}

$detectedFiles = @()

if (-not $SkipGitleaks) {
    Write-Info "Running gitleaks scan..."
    
    # Use downloaded gitleaks if available, otherwise use system one
    $gitleaksCmd = if ($gitleaksPath) { $gitleaksPath } else { "gitleaks" }
    
    # Run gitleaks with JSON format (gitleaks native format)
    # IMPORTANT: Use --log-opts to scan ENTIRE git history, not just working tree
    # Use report-format and report-path for reliable JSON output
    $tempReport = Join-Path $script:TempRoot "gitleaks-report-$(Get-Random).json"
    Write-Info "Scanning entire git history (this may take a while for large repos)..."
    $null = & $gitleaksCmd detect --source . --log-opts="--all --full-history" --no-banner --report-format json --report-path $tempReport 2>&1
    $gitleaksExitCode = $LASTEXITCODE
    
    # Exit code 1 means secrets found, 0 means no secrets
    if ((Test-Path $tempReport) -and (Get-Item $tempReport).Length -gt 0) {
        try {
            # Parse gitleaks native JSON format (array of findings)
            # Keep the RAW text too: -Redact feeds it to Get-SecretCandidates so
            # the sweep inherits gitleaks' provider-specific rules (token
            # prefixes, checksums) that generic patterns cannot reproduce.
            $script:GitleaksRawJson = Get-Content $tempReport -Raw
            $gitleaksResults = $script:GitleaksRawJson | ConvertFrom-Json -ErrorAction Stop
            
            # gitleaks JSON format: array of objects with File, RuleID, etc.
            if ($gitleaksResults -and $gitleaksResults.Count -gt 0) {
                Write-Host ""
                Write-Warning "Found secrets in the following files:"
                Write-Host ""
                
                # Group findings by file
                $fileMap = @{}
                foreach ($finding in $gitleaksResults) {
                    $filePath = $finding.File
                    $ruleId = $finding.RuleID
                    $line = $finding.StartLine
                    
                    if ($filePath -and -not $fileMap.ContainsKey($filePath)) {
                        $fileMap[$filePath] = @()
                    }
                    if ($filePath) {
                        $fileMap[$filePath] += @{
                            Rule = $ruleId
                            Line = $line
                        }
                    }
                }
                
                $index = 1
                foreach ($file in $fileMap.Keys | Sort-Object) {
                    $rules = $fileMap[$file] | ForEach-Object { "$($_.Rule):L$($_.Line)" } | Select-Object -Unique
                    Write-Host "  [$index] $file" -ForegroundColor Yellow
                    Write-Host "      Secrets: $($rules -join ', ')" -ForegroundColor Gray
                    $detectedFiles += @{
                        Index = $index
                        Path = $file
                        Rules = $rules
                    }
                    $index++
                }
                
                Write-Host ""
                Write-Warning "Total files with secrets: $($detectedFiles.Count)"
            }
        } catch {
            Write-Warning "Could not parse gitleaks output: $($_.Exception.Message)"
        } finally {
            Remove-Item $tempReport -Force -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item $tempReport -Force -ErrorAction SilentlyContinue
    }
    
    if ($detectedFiles.Count -eq 0) {
        Write-Success "No secrets detected by gitleaks!"
        Write-Host ""
        Write-Info "This could mean:"
        Write-Info "  1. No secrets are present in git history"
        Write-Info "  2. gitleaks didn't detect them (check manually)"
        Write-Host ""
        Write-Info "You can manually specify files to clean in the next step."
    }
}

# Check which files actually exist in git history
Write-Host ""
Write-Header "Step 4: Checking files in git history..."

$filesInHistory = @()

# Process files from command line arguments or manual input first
if ($manualFiles) {
    Write-Info "Processing files from input..."
    $manualFileArray = $manualFiles -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    foreach ($file in $manualFileArray) {
        $exists = git log --all --full-history --oneline -- "$file" 2>$null | Select-Object -First 1
        if ($exists) {
            $filesInHistory += @{
                Index = $filesInHistory.Count + 1
                Path = $file
                Rules = @("manual")
            }
            Write-Success "  ✓ Found in history: $file"
        } else {
            Write-Warning "  ✗ Not in history: $file"
        }
    }
} elseif ($filesFromPath -and (Test-Path $filesFromPath)) {
    Write-Info "Reading files from: $filesFromPath"
    $fileLines = Get-Content $filesFromPath | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and -not $_.StartsWith("#") }
    foreach ($file in $fileLines) {
        $exists = git log --all --full-history --oneline -- "$file" 2>$null | Select-Object -First 1
        if ($exists) {
            $filesInHistory += @{
                Index = $filesInHistory.Count + 1
                Path = $file
                Rules = @("manual")
            }
            Write-Success "  ✓ Found in history: $file"
        } else {
            Write-Warning "  ✗ Not in history: $file"
        }
    }
} elseif ($detectedFiles.Count -gt 0) {
    # Use files detected by gitleaks
    foreach ($file in $detectedFiles) {
        $exists = git log --all --full-history --oneline -- "$($file.Path)" 2>$null | Select-Object -First 1
        if ($exists) {
            $filesInHistory += $file
            Write-Success "  ✓ Found in history: $($file.Path)"
        } else {
            Write-Info "  ✗ Not in history: $($file.Path)"
        }
    }
}

# If still no files, prompt for manual input
if ($filesInHistory.Count -eq 0) {
    Write-Host ""
    if ($SkipGitleaks) {
        Write-Info "No files specified. Please enter files to clean."
    } else {
        Write-Success "No files found in git history from detection."
        Write-Info "If you know files with secrets, you can manually specify them."
    }
    Write-Host ""
    Write-Info "You can enter:"
    Write-Info "  - Comma-separated file paths: secrets.txt, config/.env"
    Write-Info "  - Path to a text file with @ prefix: @files-to-clean.txt"
    Write-Host ""
    $userInput = Read-Host "Enter file paths (or @filename for file list, or press Enter to exit)"
    
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        exit 0
    }
    
    # Check if user provided a file reference
    if ($userInput.StartsWith("@")) {
        $inputFile = $userInput.Substring(1)
        if (Test-Path $inputFile) {
            Write-Info "Reading files from: $inputFile"
            $fileLines = Get-Content $inputFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and -not $_.StartsWith("#") }
            foreach ($file in $fileLines) {
                $exists = git log --all --full-history --oneline -- "$file" 2>$null | Select-Object -First 1
                if ($exists) {
                    $filesInHistory += @{
                        Index = $filesInHistory.Count + 1
                        Path = $file
                        Rules = @("manual")
                    }
                    Write-Success "  ✓ Found in history: $file"
                } else {
                    Write-Warning "  ✗ Not in history: $file"
                }
            }
        } else {
            Write-Error "File not found: $inputFile"
            exit 1
        }
    } else {
        # Comma-separated list
        $manualFileArray = $userInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        foreach ($file in $manualFileArray) {
            $exists = git log --all --full-history --oneline -- "$file" 2>$null | Select-Object -First 1
            if ($exists) {
                $filesInHistory += @{
                    Index = $filesInHistory.Count + 1
                    Path = $file
                    Rules = @("manual")
                }
                Write-Success "  ✓ Found in history: $file"
            } else {
                Write-Warning "  ✗ Not in history: $file"
            }
        }
    }
}

if ($filesInHistory.Count -eq 0) {
    Write-Error "No valid files to clean! None of the specified files exist in git history."
    exit 1
}

Write-Host ""

# ============================================================================
# Step 5: Let user select which files to clean
# ============================================================================
if ($script:Mode -eq "redact") {

Write-Header "Step 5: Collecting secret values to redact"

Initialize-GssTmpDir
$script:PreBlobs         = Join-Path $script:GssTmpDir "blobs-before"
$script:ReplacementsFile = Join-Path $script:GssTmpDir "replacements.txt"

Write-Info "Reading every blob in history..."
Export-HistoryBlobs -OutFile $script:PreBlobs
Write-Info "Scanned $((Get-Item $script:PreBlobs).Length) bytes of history"

$script:SecretValues = @(Get-SecretCandidates -BlobFile $script:PreBlobs -GitleaksJson $script:GitleaksRawJson)

if ($script:SecretValues.Count -eq 0) {
    Write-Success "No secret values found to redact."
    exit 0
}

Write-Host ""
Write-Warning "$($script:SecretValues.Count) distinct value(s) will be replaced everywhere in history:"
Write-Host ""
$i = 0
foreach ($sec in $script:SecretValues) {
    $i++
    Write-Host ("  [{0}] {1}" -f $i, (Format-MaskedSecret $sec)) -ForegroundColor Gray
}
Write-Host ""
Write-Info "Values are masked on purpose -- a scrub should not end with every"
Write-Info "credential in your terminal history."
Write-Host ""
Write-Warning "Review this list. Anything here that is NOT a credential will be"
Write-Warning "replaced in every commit, which corrupts that content permanently."
Write-Info "Narrow it with -MinSecretLength, or add known values with -SecretsFrom."

# literal: prefixes the match so filter-repo does not treat it as a regex -- a
# password containing . * + ? [ ] would otherwise match far more than itself.
$lines = New-Object System.Collections.Generic.List[string]
$i = 0
foreach ($sec in $script:SecretValues) {
    $i++
    $lines.Add(("literal:{0}==>REPLACE_WITH_SECRET_{1:D2}" -f $sec, $i))
}
# UTF8 without BOM: filter-repo reads this file byte-for-byte, and a BOM would
# corrupt the first replacement rule.
[System.IO.File]::WriteAllLines($script:ReplacementsFile, $lines, (New-Object System.Text.UTF8Encoding($false)))

if ($DryRun) {
    Write-Host ""
    Write-Success "DRY RUN MODE - No changes will be made"
    Write-Info "Would replace the $($script:SecretValues.Count) value(s) above with REPLACE_WITH_SECRET_NN."
    exit 0
}

} else {

Write-Header "Step 5: Select files to clean from history"

Write-Host ""
Write-Host "Files found in git history:" -ForegroundColor Yellow
Write-Host ""
for ($i = 0; $i -lt $filesInHistory.Count; $i++) {
    $file = $filesInHistory[$i]
    Write-Host "  [$($i + 1)] $($file.Path)" -ForegroundColor Cyan
    Write-Host "      Secrets: $($file.Rules -join ', ')" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  [A] All files" -ForegroundColor Green
Write-Host "  [N] None (cancel)" -ForegroundColor Red
Write-Host ""

$selection = Read-Host "Enter file numbers (comma-separated) or 'A' for all, 'N' to cancel"

if ($selection -eq "N" -or $selection -eq "n") {
    Write-Info "Cancelled by user."
    exit 0
}

$selectedFiles = @()
if ($selection -eq "A" -or $selection -eq "a") {
    $selectedFiles = $filesInHistory
    Write-Success "Selected all $($selectedFiles.Count) files"
} else {
    $indices = $selection -split "," | ForEach-Object { [int]::Parse($_.Trim()) }
    foreach ($idx in $indices) {
        if ($idx -ge 1 -and $idx -le $filesInHistory.Count) {
            $selectedFiles += $filesInHistory[$idx - 1]
        } else {
            Write-Warning "Invalid index: $idx (skipping)"
        }
    }
    
    if ($selectedFiles.Count -eq 0) {
        Write-Error "No valid files selected!"
        exit 1
    }
    
    Write-Success "Selected $($selectedFiles.Count) file(s)"
}

Write-Host ""
Write-Host "Files that will be removed from history:" -ForegroundColor Yellow
foreach ($file in $selectedFiles) {
    Write-Host "  - $($file.Path)" -ForegroundColor Gray
}
Write-Host ""

if ($DryRun) {
    Write-Success "DRY RUN MODE - No changes will be made"
    Write-Host ""
    Write-Info "Would remove these files from history:"
    foreach ($file in $selectedFiles) {
        Write-Host "  ✓ $($file.Path)" -ForegroundColor Green
    }
    exit 0
}

}  # end of -DeleteFiles file selection

# ============================================================================
# Step 6: Confirm and proceed with cleanup
# ============================================================================
if ($script:Mode -eq "redact") {
    Write-Warning "Mode: -Redact -- secret VALUES are replaced, files are kept."
} else {
    Write-Warning "Mode: -DeleteFiles -- entire FILES are removed from history."
    Write-Warning "If any selected file is still in use, its configuration goes with it."
}
Write-Host ""
Write-Error "⚠️  WARNING: This will rewrite git history!"
Write-Error "⚠️  All commit SHAs will change!"
Write-Error "⚠️  You will need to force push!"
Write-Error "⚠️  All team members must re-clone the repository!"
Write-Host ""
$confirm = Read-Host "Type 'YES' to continue"
if ($confirm -ne "YES") {
    Write-Info "Aborted."
    exit 0
}

# Save remote information (git-filter-repo removes remotes)
Write-Host ""
Write-Header "Step 7: Saving remote configuration..."
$remoteInfo = @{}
$remotes = git remote
foreach ($remote in $remotes) {
    $remoteUrl = git remote get-url $remote 2>$null
    if ($remoteUrl) {
        $remoteInfo[$remote] = $remoteUrl
        Write-Info "Saved remote '$remote': $remoteUrl"
    }
}

# A linked worktree keeps pre-rewrite objects reachable; check before rewriting
# rather than discovering it in verification.
Test-StaleWorktrees

# Create backup branch
Write-Host ""
Write-Header "Step 8: Creating backup branch..."
$backupBranch = "backup-before-secret-cleanup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
git branch $backupBranch
Write-Success "Backup branch created: $backupBranch"

# Rewrite history
Write-Host ""
if ($script:Mode -eq "redact") {
    Write-Header "Step 9: Redacting secret values in git history..."
} else {
    Write-Header "Step 9: Removing files from git history..."
}
Write-Info "This may take a while..."

if ($script:Mode -eq "redact") {
    $filterRepoArgs = @("--replace-text", $script:ReplacementsFile, "--force")
    # Deliberately not echoed with its argument expanded: the replacements file
    # is a plaintext list of every credential in the repository.
    Write-Info "Running: git filter-repo --replace-text <replacements> --force"
} else {
    # Build git-filter-repo command with multiple --path arguments
    $filterRepoArgs = @("--invert-paths", "--force")
    foreach ($file in $selectedFiles) {
        $filterRepoArgs += "--path"
        $filterRepoArgs += $file.Path
    }
    Write-Info "Running: git filter-repo $($filterRepoArgs -join ' ')"
}

# Use system git-filter-repo if available, otherwise use python module
if ($useSystemFilterRepo) {
    & $filterRepoCmd $filterRepoArgs
} else {
    & $venvPython -m git_filter_repo $filterRepoArgs
}

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Error "ERROR: git-filter-repo failed!"
    Write-Warning "You can restore from backup branch: $backupBranch"
    exit 1
}

# Clean up
Write-Host ""
Write-Header "Step 10: Cleaning up git references..."
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Restore remotes (git-filter-repo removes them)
Write-Host ""
Write-Header "Step 11: Restoring remote configuration..."
if ($remoteInfo.Count -gt 0) {
    foreach ($remote in $remoteInfo.Keys) {
        $remoteUrl = $remoteInfo[$remote]
        git remote add $remote $remoteUrl 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Restored remote '$remote': $remoteUrl"
        } else {
            # Remote might already exist, try to set URL
            git remote set-url $remote $remoteUrl 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Updated remote '$remote': $remoteUrl"
            } else {
                Write-Warning "Could not restore remote '$remote' - you may need to add it manually"
            }
        }
    }
} else {
    Write-Info "No remotes were configured before cleanup"
}

Write-Host ""
Write-Success "========================================"
Write-Success "Cleanup completed successfully!"
Write-Success "========================================"
Write-Host ""

# ============================================================================
# Step 12: Verify with gitleaks
# ============================================================================
# Gated on whether gitleaks is actually available, not on $SkipGitleaks. That flag also
# gets set by -Files and -FilesFrom, which say nothing about wanting the result left
# unchecked -- so choosing the file list by hand used to silently skip the only step that
# confirms the cleanup did anything.
# In -Redact mode the direct check runs FIRST and is the one that counts. It
# tests the actual values against every object in history, and proves it can
# fail. gitleaks below is a second opinion with different rules, not the proof.
$script:RedactVerifyOk = $true
if ($script:Mode -eq "redact") {
    Write-Host ""
    Write-Header "Step 12a: Verifying redaction directly..."
    $script:RedactVerifyOk = Test-Redaction -Secrets $script:SecretValues -PreBlobs $script:PreBlobs
    Write-Host ""
}

if ($gitleaksPath) {
    Write-Host ""
    Write-Header "Step 12: Verifying cleanup with gitleaks..."
    Write-Info "Running gitleaks scan to verify secrets are removed..."
    Write-Host ""

    $gitleaksCmd = $gitleaksPath
    # Use same format as detection scan for consistency
    # Exit code 0 = no secrets, 1 = secrets found
    $verifyReport = Join-Path $script:TempRoot "gitleaks-verify-$(Get-Random).json"
    $null = & $gitleaksCmd detect --source . --log-opts="--all --full-history" --no-banner --report-format json --report-path $verifyReport 2>&1
    $verifyExitCode = $LASTEXITCODE
    
    # Check if report has any findings
    $hasFindings = $false
    if ((Test-Path $verifyReport) -and (Get-Item $verifyReport).Length -gt 2) {
        $verifyContent = Get-Content $verifyReport -Raw
        if ($verifyContent -and $verifyContent -ne "[]" -and $verifyContent -ne "null") {
            $hasFindings = $true
        }
    }
    Remove-Item $verifyReport -Force -ErrorAction SilentlyContinue
    
    if ($verifyExitCode -eq 0 -or -not $hasFindings) {
        Write-Success "✓ No secrets detected by gitleaks!"
    } elseif ($script:Mode -eq "redact" -and (Get-RealFindingCount $verifyContent) -eq 0) {
        # Every remaining finding is a REPLACE_WITH_SECRET_NN placeholder.
        # generic-api-key fires on `Password=<anything>` whatever the value is, so
        # a successful redaction leaves a repo that scans dirty forever. Calling
        # that "secrets still detected" trains the operator to ignore the scanner.
        Write-Success "✓ No secrets detected by gitleaks!"
        Write-Host ""
        Write-Info "gitleaks matched only the REPLACE_WITH_SECRET_NN placeholders."
        Write-Info "Allowlist them so future scans stay meaningful -- in .gitleaks.toml:"
        Write-Host ""
        Write-Host "  [[allowlists]]" -ForegroundColor Gray
        Write-Host "  description = ""Redaction placeholders left by git-secret-scrubber""" -ForegroundColor Gray
        Write-Host "  regexes = ['''^REPLACE_WITH_SECRET_[0-9]+$''']" -ForegroundColor Gray
        Write-Host "  regexTarget = ""secret""" -ForegroundColor Gray
    } elseif ($verifyExitCode -eq 1) {
        # Exit code 1 means secrets were found
        Write-Warning "gitleaks still detected some secrets!"
        Write-Info "This might be expected if:"
        Write-Info "  - Secrets exist in other files not cleaned"
        Write-Info "  - gitleaks is detecting false positives"
        Write-Host ""
        Write-Info "Run 'gitleaks detect --source . --log-opts=`"--all`"' to see what was detected."
    } else {
        Write-Warning "gitleaks verification encountered an error (exit code: $verifyExitCode)"
    }
    Write-Host ""
}

Write-Header "Next steps:"
Write-Info "1. Review the changes: git log --oneline -10"
Write-Info "2. Verify remote is configured: git remote -v"
Write-Host ""

if ($remoteInfo.Count -gt 0) {
    $primaryRemote = if ($remoteInfo.ContainsKey("origin")) { "origin" } else { ($remoteInfo.Keys | Select-Object -First 1) }
    
    Write-Warning "⚠️  IMPORTANT: Protected Branch Notice"
    Write-Host ""
    Write-Info "If your branch is protected in GitLab/GitHub, you have these options:"
    Write-Host ""
    Write-Info "Option 1: Temporarily unprotect the branch (if you have admin access)"
    Write-Info "  1. Go to Repository > Settings > Protected Branches"
    Write-Info "  2. Temporarily unprotect '$currentBranch'"
    Write-Info "  3. Force push: git push $primaryRemote --force --all"
    Write-Info "  4. Re-protect the branch after push"
    Write-Host ""
    Write-Info "Option 2: Use a new branch and merge (recommended for protected branches)"
    Write-Info "  1. Create a new branch: git checkout -b cleanup-secrets-history"
    Write-Info "  2. Push new branch: git push $primaryRemote cleanup-secrets-history"
    Write-Info "  3. Create a Merge Request to replace the protected branch"
    Write-Info "  4. After merge, delete old branch and rename new one"
    Write-Host ""
    Write-Info "Option 3: Contact repository admin"
    Write-Info "  Ask an admin to temporarily allow force push or unprotect the branch"
    Write-Host ""
    Write-Info "3. Coordinate with your team (they must re-clone after push)"
    Write-Info "4. Force push (if branch is not protected):"
    Write-Host "   git push $primaryRemote --force --all" -ForegroundColor Cyan
    Write-Host "   git push $primaryRemote --force --tags" -ForegroundColor Cyan
} else {
    Write-Warning "No remote was configured. You'll need to add one before pushing:"
    Write-Info "  git remote add origin <your-repo-url>"
    Write-Info "  git push origin --force --all"
}
Write-Host ""
Write-Info "Backup branch: $backupBranch"
Write-Host ""

Write-Error "╔══════════════════════════════════════════════════════════════════╗"
Write-Error "║  ⚠️  REMINDER: After force-push, ALL teammates must RE-CLONE!     ║"
Write-Error "║  Their local copies will be incompatible with the new history.  ║"
Write-Error "╚══════════════════════════════════════════════════════════════════╝"

if ($script:Mode -eq "redact") {
    Write-Info "Redacted values now read REPLACE_WITH_SECRET_NN. Allowlist that string"
    Write-Info "in your gitleaks config, or every historical commit fails future scans."
    Write-Host ""
}

# A scrub that could not prove itself must not exit 0 -- CI and shell callers
# read the status, not the log.
if ($script:Mode -eq "redact" -and -not $script:RedactVerifyOk) {
    Write-Error "Exiting non-zero: redaction could not be verified."
    exit 1
}
Write-Host ""
