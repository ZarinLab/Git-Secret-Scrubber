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

.PARAMETER Yes
    Answer the final "Type YES" confirmation, for non-interactive runs. With
    -Files/-FilesFrom it also selects every listed file. Guards still refuse.

.PARAMETER Replacement
    -Redact only: replace every value with this literal text instead of the
    numbered REPLACE_WITH_SECRET_NN placeholders.

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
    # Exact values NEVER to redact, one per line (words and expressions a person
    # vetted), and a file to receive the exact values that will be replaced.
    [string]$ExcludeFrom = "",
    [string]$CandidatesOut = "",
    [string]$GitleaksConfig = "",
    [switch]$IncludeHeadValues = $false,
    [switch]$Yes = $false,
    # Empty = the numbered REPLACE_WITH_SECRET_NN placeholders. Whether it was
    # GIVEN is read from $PSBoundParameters, because an explicit empty string
    # is refused rather than treated as "not given".
    [string]$Replacement = "",
    # 8, not 16: a real 10-character database password turned up in a live scrub,
    # and a higher floor would have left it in history. Length alone is a poor
    # filter -- Get-HeuristicRejectReason pairs it with character-class diversity.
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
    Write-Host "Modes:" -ForegroundColor Yellow
    Write-Host "  -DeleteFiles      Remove whole FILES from history (default)"
    Write-Host "                    For .env, *.pem -- files that exist only to hold credentials."
    Write-Host "  -Redact           Replace secret VALUES in place, keeping the files"
    Write-Host "                    For files still in use, where deleting the file would"
    Write-Host "                    delete the configuration with it."
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -SecretsFrom FILE      Extra literal secret values to redact, one per line"
    Write-Host "  -ExcludeFrom FILE      Literal values NEVER to redact, one per line (vetted words, code)"
    Write-Host "  -CandidatesOut FILE    Write the exact values that will be replaced (owner-only) for vetting"
    Write-Host "                    (-Redact only; bypasses the identifier heuristics)"
    Write-Host "  -MinSecretLength N     Shortest value to redact (-Redact only, default 8)"
    Write-Host "  -GitleaksConfig FILE   gitleaks config to scan with"
    Write-Host "                    (default: .gitleaks.toml in the repo, if present)"
    Write-Host "  -IncludeHeadValues     Also redact values still present in HEAD"
    Write-Host "                    (default: they are reported and SKIPPED)"
    Write-Host "  -Replacement TEXT      Replace every value with TEXT (-Redact only)"
    Write-Host "                    (default: REPLACE_WITH_SECRET_NN, numbered per value)"
    Write-Host "  -Yes              Answer the final 'Type YES' confirmation, for"
    Write-Host "                    non-interactive runs. With -Files/-FilesFrom it also"
    Write-Host "                    selects every listed file. Guards still refuse."
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
    Write-Host "Exit status:" -ForegroundColor Yellow
    Write-Host "  0  done (or nothing to do), and verified"
    Write-Host "  1  error, refused by a guard, or the rewrite could not be verified"
    Write-Host "  3  -Redact: value(s) live in HEAD were SKIPPED, so the repository"
    Write-Host "     still holds them (see -IncludeHeadValues)"
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

# Run a native command and write its stdout to a file BYTE FOR BYTE.
#
# Not `git ... | Set-Content`. PowerShell decodes a native command's output
# into strings -- with [Console]::OutputEncoding, on Windows usually an OEM code
# page -- splits it into lines, and Set-Content re-encodes what is left. A dump
# that went through that is no longer the repository's bytes: a UTF-8 password
# came out as mojibake, was harvested as mojibake, and the replacement rule
# built from it matched nothing -- so the real value survived the rewrite.
#
# WorkingDirectory is set explicitly because Set-Location does not move the
# process's own current directory, which is what a child process inherits.
function Invoke-NativeToFile {
    param([string]$FilePath, [string[]]$ArgumentList, [string]$OutFile)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    # Arguments, not ArgumentList: ArgumentList does not exist on Windows
    # PowerShell 5.1's .NET Framework.
    $psi.Arguments = ($ArgumentList | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = (Get-Location).Path
    $proc = [System.Diagnostics.Process]::Start($psi)
    # stderr drained concurrently, or a chatty child blocks on a full pipe.
    $errTask = $proc.StandardError.ReadToEndAsync()
    $fs = [System.IO.File]::Create($OutFile)
    try { $proc.StandardOutput.BaseStream.CopyTo($fs) } finally { $fs.Dispose() }
    $proc.WaitForExit()
    [void]$errTask.Result
    return $proc.ExitCode
}

# Concatenate every object in the repository into one file -- blobs, and also
# commits and annotated tags.
#
# Used twice: to harvest candidate secrets, and afterwards to prove each one is
# gone. The gitleaks report alone is not enough for either job -- its rules miss
# whole categories of credential (see Get-SecretCandidates).
#
# Blobs alone are not enough either: a commit message or a tag annotation is
# an object too, and pushes like any other. A token pasted into a commit
# message survived the rewrite while a blob-only check reported it gone.
# --batch-all-objects also reads UNREACHABLE objects; the rewrite's gc prunes
# them, so for verification that only makes the check stricter.
#
# A failure must not read as an empty repository: an empty dump harvests
# nothing, and "nothing found" is the answer that ends a scrub.
function Export-HistoryObjects {
    param([string]$OutFile)
    Initialize-GssTmpDir
    $rc = Invoke-NativeToFile -FilePath "git" -ArgumentList @("cat-file", "--batch-all-objects", "--batch", "--unordered") -OutFile $OutFile
    if ($rc -ne 0 -or -not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -eq 0) {
        Write-Error "Could not read the repository's objects (git cat-file --batch-all-objects)."
        return $false
    }
    return $true
}

# Decide whether a captured string is a credential or an identifier.
#
# Erring permissive is not cosmetic: --replace-text rewrites the string
# EVERYWHERE, so redacting an identifier corrupts that content permanently.
#
# Erring the other way is worse because it is SILENT: a rejected value stays
# in history and nothing says so. So this returns the RULE that rejected the
# value ("" = accepted), and every rejection is listed for the operator.
# `Password=summerholiday;` was dropped by the alphabetic rule while the dry
# run reported "No secret values found".
function Get-HeuristicRejectReason {
    param([string]$Value)
    # Prose, not a credential: a translation file's "Forgot Password" has a
    # space; a generated credential does not. Sweep findings only.
    if ($Value.Contains(' ')) { return "contains a space (text, not a credential)" }
    if ($Value.Length -lt $script:MinSecretLen) { return "shorter than -MinSecretLength ($($script:MinSecretLen))" }

    # Placeholders and template expressions hold no credential.
    # -cmatch, not -match: PowerShell's -match is case-INSENSITIVE by default,
    # which is the opposite of bash's =~ and would reject any value merely
    # starting with the letters "change" or "sample" in any casing.
    if ($Value -cmatch '^(REPLACE|CHANGE|PLACEHOLDER|TODO|EXAMPLE|DUMMY|SAMPLE|CHANGEME|YOUR_|xxx|XXX)') { return "placeholder" }
    if ($Value.StartsWith('$') -or $Value.StartsWith('<') -or $Value.StartsWith('lookup(') -or $Value.StartsWith('process.env.')) { return "variable or lookup reference" }

    # A template expression ANYWHERE in the value, not only at the start: a Helm
    # value like `amir-{{ include (print ...) }}` was captured whole by the
    # quoted-value pattern and passed a start-anchored check.
    if ($Value.Contains('{{') -or $Value.Contains('}}') -or $Value.Contains('${')) { return "template expression" }

    # A code expression: an identifier or member path, then a call --
    # `DateTime.Now.AddDays(setting.PasswordExpiryDays)` arrives from the
    # `password... =` sweep, and replacing it changes code in every commit.
    if ($Value -cmatch '^[A-Za-z_][A-Za-z0-9_.]{3,}\(') { return "code expression (identifier then a call)" }

    # Provider tokens are segmented too, so exempt them BEFORE the identifier
    # rules below or glpat-/SG./ghp_ values get thrown away as names.
    if ($Value -cmatch '^(AKIA|glpat-|gh[pousr]_|SG\.|xox[baprs]-)') { return "" }

    # Bracketed markers -- [REDACTED], [MASKED]. Output of a redaction stage,
    # not input to one.
    if ($Value.StartsWith('[')) { return "bracketed marker" }

    # Purely alphabetic values: accessKey, secretKey, hawkUsername. Field names,
    # not credentials -- a generated credential essentially always carries a
    # digit or a symbol. Redacting `secretKey` rewrites the KEY of every mapping
    # that uses it.
    if ($Value -cmatch '^[A-Za-z]+$') { return "alphabetic only (field-name shape)" }

    # snake_case and SCREAMING_SNAKE_CASE identifiers: LOKI_S3_ACCESS_KEY_ID,
    # s3_access_key, appfile_s3_bucket_key.
    #
    # THE RULE THAT MATTERS MOST IN A KUBERNETES REPOSITORY. Env var names and
    # ExternalSecret remoteRef.key values are written this way. A dry run
    # against a 5069-commit GitOps repo proposed 17 values live in HEAD, almost
    # all of this shape. Redacting them renames the field that fetches a
    # credential, in every commit.
    if ($Value -cmatch '^[A-Za-z][A-Za-z0-9]*(_[A-Za-z0-9]+)+$') { return "snake_case identifier" }

    # Segmented identifier paths with no digits: ApiKeys_SendGridApiKeyName,
    # Identity.Api.ClientSecret, Recaptcha:SiteKey. These are configuration KEY
    # names -- including token names that REFERENCE a vault secret rather than
    # containing one. Redacting them rewrites the reference and breaks config
    # while hiding nothing. The no-digit condition keeps real segmented tokens
    # safe: a SendGrid key is segmented too, but its segments carry digits.
    if ($Value -match '^[A-Za-z][A-Za-z0-9]*([._:]+[A-Za-z][A-Za-z0-9]*)+$' -and $Value -notmatch '[0-9]') { return "segmented identifier (a.b / a_b / a:b, no digits)" }

    # kebab-case is how Kubernetes Secret names and DNS labels are written. The
    # identifier belongs in git; the credential it names lives elsewhere.
    #
    # ⚠️ -cmatch is load-bearing. With the default case-INSENSITIVE -match, [a-z]
    # also matches A-Z, so this rule swallowed `glpat-WSyTESTtoken123456789` as
    # "kebab-case" and silently dropped a live GitLab token from the redaction
    # list. The bash implementation uses =~, which is case-sensitive; this is the
    # single place the two languages disagree by default.
    if ($Value -cmatch '^[a-z][a-z0-9]*(-[a-z0-9]+)+$') { return "kebab-case identifier" }

    # Character-class diversity rather than entropy: cheap, and it is what keeps
    # a short lowercase word out of a global search-and-replace.
    $classes = 0
    if ($Value -cmatch '[a-z]') { $classes++ }
    if ($Value -cmatch '[A-Z]') { $classes++ }
    if ($Value -match '[0-9]') { $classes++ }
    if ($Value -match '[^a-zA-Z0-9]') { $classes++ }
    if ($classes -lt 2) { return "fewer than 2 character classes" }
    return ""
}

# The gate for values gitleaks itself reported.
#
# Deliberately weaker than Get-HeuristicRejectReason. A finding from gitleaks running
# under the repository's OWN config has already been through a human decision:
# the rules say what counts, the allowlists say what does not. Re-running the
# identifier heuristics over that verdict second-guesses it with less
# information and silently loses real credentials -- a Check Point agent token
# (cp-<hex>) is lowercase alphanumerics and hyphens, so the kebab-case rule
# threw it away. That miss left 21 live credentials in a repository the tool had
# just reported as cleaned.
function Get-MinimalRejectReason {
    param([string]$Value)
    if ($Value.Length -lt $script:MinSecretLen) { return "shorter than -MinSecretLength ($($script:MinSecretLen))" }
    if ($Value -cmatch '^(REPLACE|CHANGE|PLACEHOLDER|TODO|EXAMPLE|DUMMY|SAMPLE|CHANGEME|YOUR_)') { return "placeholder" }
    if ($Value.Contains('{{') -or $Value.Contains('}}') -or $Value.Contains('${')) { return "template expression or variable reference" }
    if ($Value.StartsWith('$') -or $Value.StartsWith('<')) { return "template expression or variable reference" }
    return ""
}

# The gate for the Password= field of a connection string.
#
# The POSITION says what the value is. After `Server=..;User Id=..;` the thing
# in `Password=` is the password, whatever it looks like -- and people choose
# passwords that look exactly like identifiers: `summerholiday`,
# `my-db-pass-word`, `my_db_pass_word2`. The identifier rules exist for the
# opposite case, a NAME sitting where a value could be, and they threw every
# one of those away.
#
# So: the minimal gate plus the placeholder shapes config templating puts in
# exactly this position -- SCREAMING_SNAKE (`FROM_VAULT`), `__TOKEN__` (Azure
# DevOps replace-tokens), `#{Token}` (Octopus), `%VAR%`. Rejected, and listed.
function Get-ConnStringRejectReason {
    param([string]$Value)
    $r = Get-MinimalRejectReason $Value
    if ($r) { return $r }
    if ($Value -cmatch '^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$') { return "SCREAMING_SNAKE placeholder" }
    if (($Value.StartsWith('__') -and $Value.EndsWith('__')) -or $Value.StartsWith('#{') -or ($Value.StartsWith('%') -and $Value.EndsWith('%'))) { return "replace-token placeholder" }
    return ""
}

# Harvest candidate secret values from the blob dump and the gitleaks report.
#
# Every pattern is case-insensitive: a lowercase `password=` is as real as
# `Password=`, and matching only the capitalised form leaves secrets behind.
$script:RejectedCandidates = @()
$script:SecretsFromAbsent = 0
function Get-SecretCandidates {
    param([string]$BlobFile, [string]$GitleaksJson)
    $found = New-Object System.Collections.Generic.HashSet[string]
    $trusted = New-Object System.Collections.Generic.HashSet[string]
    $connStr = New-Object System.Collections.Generic.HashSet[string]

    # gitleaks first: its rules carry provider-specific knowledge a generic
    # sweep does not have.
    if ($GitleaksJson -and $GitleaksJson -ne "[]" -and $GitleaksJson -ne "null") {
        try {
            foreach ($f in ($GitleaksJson | ConvertFrom-Json)) {
                if ($f.Secret) { [void]$trusted.Add([string]$f.Secret) }
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

    # The Password= field of a CONNECTION STRING: a `;`-delimited run of
    # key=value pairs that also names a server, a user or a database. Judged by
    # Get-ConnStringRejectReason, not the identifier rules. The neighbouring
    # key is what licenses that: a bare `password=x` is as often code
    # (`password=password`) as configuration. No whitespace around `=`, which
    # is how connection strings are written and assignments mostly are not.
    $ck = '(?:server|data source|datasource|host|hostname|address|addr|network address|user id|userid|uid|user|username|database|initial catalog)'
    $nq = '[^;"''<>=]'
    $connPatterns = @(
        # Password after a server/user/database key.
        "(?i)(?:^|[^A-Za-z0-9_])$ck=$nq*;(?:$nq*=[^;`"'<>]*;)*\s*(?:password|pwd)=([^;`"'\s]+)",
        # Password first, a server/user/database key after it.
        "(?i)(?:^|[^A-Za-z0-9_])(?:password|pwd)=([^;`"'\s]+);(?:$nq*=[^;`"'<>]*;)*\s*$ck="
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
        foreach ($rx in $connPatterns) {
            foreach ($m in [regex]::Matches($line, $rx)) {
                $v = $m.Groups[1].Value
                if ($v) { [void]$connStr.Add($v) }
            }
        }
    }

    # Operator-named values go in the TRUSTED set, not the sweep. Someone
    # listing a value by hand has already decided; running the guessing rules
    # over that decision only overrides it.
    #
    # A value that occurs nowhere in the repository is dropped with a count.
    # One shared list is meant to serve many repositories; a value absent from
    # this one has nothing to redact here, and keeping it would fail the
    # verification control, which requires every value present beforehand.
    $script:SecretsFromAbsent = 0
    if ($SecretsFrom) {
        $dumpText = [System.IO.File]::ReadAllText($BlobFile)
        foreach ($l in Get-Content $SecretsFrom) {
            $t = $l.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            if ($dumpText.Contains($t)) { [void]$trusted.Add($t) } else { $script:SecretsFromAbsent++ }
        }
        $dumpText = $null
    }

    # Longest first. --replace-text applies rules in file order, so a secret that
    # is a prefix of a longer one must be replaced second or it truncates the
    # longer match and leaves its tail in history.
    # Scanner findings get the minimal gate; sweep findings get the full
    # heuristics, because nothing has vetted those.
    # Connection-string passwords get the minimal gate plus template
    # placeholders. Every rejection is recorded with its rule.
    $keep = New-Object System.Collections.Generic.HashSet[string]
    $rejected = [ordered]@{}
    foreach ($v in $trusted) { $r = Get-MinimalRejectReason $v;    if ($r) { if (-not $rejected.Contains($v)) { $rejected[$v] = $r } } else { [void]$keep.Add($v) } }
    foreach ($v in $connStr) { $r = Get-ConnStringRejectReason $v; if ($r) { if (-not $rejected.Contains($v)) { $rejected[$v] = $r } } else { [void]$keep.Add($v) } }
    foreach ($v in $found)   { $r = Get-HeuristicRejectReason $v;  if ($r) { if (-not $rejected.Contains($v)) { $rejected[$v] = $r } } else { [void]$keep.Add($v) } }

    # A value one gate rejected and another accepted IS being redacted, so it
    # is not a rejection. The rest were dropped by every gate that saw them.
    $script:RejectedCandidates = @($rejected.Keys | Where-Object { -not $keep.Contains($_) } |
        ForEach-Object { [pscustomobject]@{ Reason = $rejected[$_]; Value = $_ } } | Sort-Object -Property Reason)
    # -ExcludeFrom wins over every source, -SecretsFrom included, and each
    # exclusion is listed as a rejection with its reason.
    if ($ExcludeFrom) {
        foreach ($l in Get-Content $ExcludeFrom) {
            $t = $l.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            if ($keep.Remove($t)) {
                $script:RejectedCandidates += [pscustomobject]@{ Reason = "excluded by -ExcludeFrom"; Value = $t }
            }
        }
    }
    $sorted = @($keep | Sort-Object -Property Length -Descending)
    if ($CandidatesOut) {
        # Owner-only before a single value is written.
        New-Item -ItemType File -Path $CandidatesOut -Force | Out-Null
        if ($IsWindows -or $env:OS -eq 'Windows_NT') {
            & icacls $CandidatesOut /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
        } else {
            & chmod 600 $CandidatesOut
        }
        [System.IO.File]::WriteAllLines($CandidatesOut, [string[]]$sorted)
    }
    return $sorted
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
    if ($DryRun) { return }
    # -Yes does not answer this: it confirms the rewrite, not the override of
    # a guard.
    if (-not $Force) {
        $wt = Read-Host "Type 'IGNORE' to rewrite anyway (not recommended)"
        if ($wt -ne "IGNORE") {
            Write-Info "Aborted. Remove the worktrees and re-run."
            exit 1
        }
    }
}

# What the values become, for messages.
function Get-PlaceholderLabel {
    if ($script:ReplacementSet) { return $Replacement }
    return "REPLACE_WITH_SECRET_NN"
}

# The gitleaks allowlist regex for the placeholder. Escaped by hand, not with
# [regex]::Escape: that also escapes spaces and '#', and gitleaks' RE2 rejects
# `\ ` as an invalid escape -- the advice would produce a broken config.
function Get-PlaceholderRegex {
    if (-not $script:ReplacementSet) { return '^REPLACE_WITH_SECRET_[0-9]+$' }
    return '^' + ([regex]::Replace($Replacement, '[\\.+*?()|\[\]{}^$]', { param($m) '\' + $m.Value })) + '$'
}

# Refuse to rewrite while the repository has stash entries.
#
# A stash is a pair of commits hanging off refs/stash, and its older entries
# exist ONLY in that ref's reflog. Whether they survive a rewrite depends on
# the filter-repo version: recent ones rewrite the stash, older ones leave it
# pointing at pre-rewrite commits -- which keeps every secret in them alive in
# this repository after a run that reports success. And a stash is uncommitted
# work: a history rewrite is no place to find out what happens to it.
function Test-StashList {
    $entries = @(git stash list 2>$null)
    if ($entries.Count -eq 0) { return }
    Write-Host ""
    if ($DryRun) {
        Write-Warning "This repository has $($entries.Count) stash entr(y/ies). A real run will refuse"
        Write-Warning "until they are gone."
        Write-Host ""
        return
    }
    Write-Error "This repository has $($entries.Count) stash entr(y/ies):"
    $entries | ForEach-Object { Write-Host "    $_" }
    Write-Host ""
    Write-Warning "Stash entries are commits kept outside every branch. A history"
    Write-Warning "rewrite may leave them holding the pre-rewrite content -- and the"
    Write-Warning "secrets in it -- and it is no place to keep work in progress."
    Write-Host ""
    Write-Info "Save each one somewhere safe, then clear them:"
    Write-Info "  git stash show -p stash@{0} > stash-0.patch   (one per entry)"
    Write-Info "  git stash clear"
    Write-Info "Nothing was changed."
    exit 1
}

# Warn about .gitleaksignore: its entries do not survive a rewrite. Each line is
# a fingerprint `<commit>:<file>:<rule>:<line>`, and the rewrite replaces every
# commit SHA -- so after the run every entry suppresses nothing.
function Test-GitleaksIgnore {
    if (-not (Test-Path ".gitleaksignore")) { return }
    $n = @(Get-Content ".gitleaksignore" | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }).Count
    Write-Host ""
    Write-Warning "This repository has a .gitleaksignore ($n fingerprint(s))."
    Write-Warning "Each fingerprint contains a commit SHA, and this rewrite changes every"
    Write-Warning "SHA: all of them stop matching after the run."
    Write-Info "Move each one to a .gitleaks.toml allowlist that says WHY it is allowed:"
    Write-Host "  [[allowlists]]" -ForegroundColor Gray
    Write-Host "  description = ""<reason this value is not a secret>""" -ForegroundColor Gray
    Write-Host "  regexTarget = ""secret""" -ForegroundColor Gray
    Write-Host "  regexes = ['''^<the value>$''']" -ForegroundColor Gray
    Write-Host ""
}

# Count gitleaks findings that are NOT the placeholders this tool introduced --
# REPLACE_WITH_SECRET_NN, or exactly the -Replacement TEXT when one was given.
function Get-RealFindingCount {
    param([string]$Json)
    try {
        $data = $Json | ConvertFrom-Json
    } catch {
        # Unparseable output is not evidence of a clean repo.
        return -1
    }
    if (-not $data) { return 0 }
    if ($script:ReplacementSet) {
        return @($data | Where-Object { ([string]$_.Secret).Trim() -cne $Replacement }).Count
    }
    return @($data | Where-Object { ([string]$_.Secret).Trim() -cnotmatch '^REPLACE_WITH_SECRET_[0-9]+$' }).Count
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
    $post = Join-Path $script:GssTmpDir "objects-after"
    if (-not (Export-HistoryObjects -OutFile $post)) { return $false }

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
        Write-Info "  Do not push. Restore from the mirror clone you took before the run,"
        Write-Info "  find out what holds them, and re-run."
        return $false
    }
    Write-Success "✓ All $($Secrets.Count) value(s) are gone from every object -- blobs, commits and tags."
    return $true
}

# Resolve -FilesFrom against the caller's directory BEFORE changing into the repo,
# otherwise a relative path stops resolving the moment we Set-Location and the list
# reads as missing. -SecretsFrom and -GitleaksConfig had the same bug, and both
# failed SILENTLY: a missing secrets list was skipped by a Test-Path, and a
# missing config fell back to stock rules.
if ($FilesFrom -and -not [System.IO.Path]::IsPathRooted($FilesFrom)) {
    $FilesFrom = Join-Path (Get-Location).Path $FilesFrom
}
if ($SecretsFrom -and -not [System.IO.Path]::IsPathRooted($SecretsFrom)) {
    $SecretsFrom = Join-Path (Get-Location).Path $SecretsFrom
}
if ($GitleaksConfig -and -not [System.IO.Path]::IsPathRooted($GitleaksConfig)) {
    $GitleaksConfig = Join-Path (Get-Location).Path $GitleaksConfig
}
foreach ($n in "ExcludeFrom","CandidatesOut") {
    $v = Get-Variable -Name $n -ValueOnly
    if ($v -and -not [System.IO.Path]::IsPathRooted($v)) { Set-Variable -Name $n -Value (Join-Path (Get-Location).Path $v) }
}
if ($ExcludeFrom -and -not (Test-Path $ExcludeFrom -PathType Leaf)) {
    Write-Host "Error: -ExcludeFrom file not found: $ExcludeFrom" -ForegroundColor Red
    exit 1
}
if ($SecretsFrom -and -not (Test-Path $SecretsFrom -PathType Leaf)) {
    Write-Host "Error: -SecretsFrom file not found: $SecretsFrom" -ForegroundColor Red
    exit 1
}
if ($GitleaksConfig -and -not (Test-Path $GitleaksConfig -PathType Leaf)) {
    Write-Host "Error: -GitleaksConfig file not found: $GitleaksConfig" -ForegroundColor Red
    exit 1
}

# -Replacement TEXT goes, verbatim, on the right of a filter-repo expression
# line: `literal:<value>==><TEXT>`. filter-repo splits each line on its LAST
# `==>`, so a TEXT containing one would split in the wrong place; a newline
# would end the expression. Checked against the values themselves once they
# are known. Messages name the bash spelling too: the two CLIs are one API.
$script:ReplacementSet = $PSBoundParameters.ContainsKey('Replacement')
if ($script:ReplacementSet) {
    if (-not $Redact) {
        Write-Host "Error: -Replacement (--replacement) only applies to -Redact." -ForegroundColor Red
        exit 1
    }
    if ([string]::IsNullOrEmpty($Replacement)) {
        Write-Host "Error: -Replacement (--replacement) TEXT must not be empty." -ForegroundColor Red
        exit 1
    }
    if ($Replacement.Contains("`n") -or $Replacement.Contains("`r")) {
        Write-Host "Error: -Replacement (--replacement) TEXT must be a single line." -ForegroundColor Red
        exit 1
    }
    if ($Replacement.Contains('==>')) {
        Write-Host "Error: -Replacement (--replacement) TEXT must not contain '==>' (the filter-repo expression separator)." -ForegroundColor Red
        exit 1
    }
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

# Guards run FIRST, before any prompt or scan. The worktree guard used to run
# after the "Type YES" confirmation: an operator confirmed a rewrite and was
# only then told it could not be done safely.
Test-StashList
Test-StaleWorktrees
Test-GitleaksIgnore

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
# Values left out because they are live in HEAD; non-zero makes the run exit 3.
$script:HeadSkipped = 0
# Honour the repository's own gitleaks config. Without it the scan runs stock
# rules, which is wrong in BOTH directions against a tuned repo: it misses the
# shapes the repo added rules for, and it reports the values the repo
# deliberately ALLOWLISTED. Feeding an allowlisted value to --replace-text
# rewrites live configuration to hide something that was never secret.
$script:GitleaksConfigFile = $GitleaksConfig
if (-not $script:GitleaksConfigFile -and (Test-Path ".gitleaks.toml")) {
    $script:GitleaksConfigFile = ".gitleaks.toml"
}

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
        # Not "or stash": a stash is refused outright (Test-StashList), so
        # that advice sent people straight into the next guard.
        Write-Info "Commit these changes, or move them out of the repository, before rewriting history."
        Write-Host ""
        
        if (-not $Force) {
            $proceed = Read-Host "Do you want to proceed anyway? (yes/no) [default: no]"
            if ([string]::IsNullOrWhiteSpace($proceed) -or ($proceed -ne "yes" -and $proceed -ne "y")) {
                Write-Info "Aborted. Commit your changes first, or use -Force to skip this prompt."
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
    $null = $cfgArgs = @(); if ($script:GitleaksConfigFile -and (Test-Path $script:GitleaksConfigFile)) { $cfgArgs = @("--config", $script:GitleaksConfigFile); Write-Info "Using gitleaks config: $($script:GitleaksConfigFile)" } else { Write-Warning "No gitleaks config -- stock rules only." }
        & $gitleaksCmd detect --source . --log-opts="--all --full-history" --no-banner @cfgArgs --report-format json --report-path $tempReport 2>&1
    $gitleaksExitCode = $LASTEXITCODE
    # Only 0 and 1 are scan results. Anything else means gitleaks never
    # completed, and its missing report must not read as a clean repository.
    if ($gitleaksExitCode -ne 0 -and $gitleaksExitCode -ne 1) {
        Write-Error "gitleaks did not complete (exit code $gitleaksExitCode) -- its findings are NOT included."
    }
    
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
    
    # "No secrets detected" is a claim about a scan that RAN. After a failed
    # one it used to print anyway, directly under the failure.
    if ($gitleaksExitCode -ne 0 -and $gitleaksExitCode -ne 1) {
        Write-Warning "gitleaks produced no usable result -- nothing is known from it."
    } elseif ($detectedFiles.Count -eq 0) {
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

# If still no files, prompt for manual input.
#
# Skipped in -Redact mode: that mode never uses a file list. It sweeps every
# blob for credential-shaped values, so "gitleaks named no files" is not a
# reason to stop -- and prompting here consumed the confirmation input as a
# filename, which broke every redact run where the scanner found nothing.
if ($filesInHistory.Count -eq 0 -and $script:Mode -ne "redact") {
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

if ($filesInHistory.Count -eq 0 -and $script:Mode -ne "redact") {
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
$script:PreBlobs         = Join-Path $script:GssTmpDir "objects-before"
$script:ReplacementsFile = Join-Path $script:GssTmpDir "replacements.txt"

# The patterns and gitleaks find credential SHAPES. A value that does not have
# one -- or has the shape of an identifier -- is found only if you name it.
# Not mandatory, because a quick scrub of one obvious token should not need a
# file; but a production scrub without it relies on guesswork, and says so.
if (-not $SecretsFrom) {
    Write-Error "╔══════════════════════════════════════════════════════════════════╗"
    Write-Error "║  No -SecretsFrom list: only values that the patterns and         ║"
    Write-Error "║  gitleaks recognise will be redacted. A password shaped like a   ║"
    Write-Error "║  word or an identifier can be rejected -- check the REJECTED     ║"
    Write-Error "║  list below, and name known values in a -SecretsFrom file.       ║"
    Write-Error "╚══════════════════════════════════════════════════════════════════╝"
    Write-Host ""
}

Write-Info "Reading every object in the repository (blobs, commits, tags)..."
if (-not (Export-HistoryObjects -OutFile $script:PreBlobs)) { exit 1 }
Write-Info "Scanned $((Get-Item $script:PreBlobs).Length) bytes of history"

$script:SecretValues = @(Get-SecretCandidates -BlobFile $script:PreBlobs -GitleaksJson $script:GitleaksRawJson)

if ($script:SecretsFromAbsent -gt 0) {
    Write-Info "$($script:SecretsFromAbsent) value(s) from -SecretsFrom occur nowhere in this"
    Write-Info "repository -- nothing to redact for them here."
}

# Every candidate a gate dropped, with the gate. This list is the only thing
# standing between an identifier-shaped password and a report that says the
# repository is clean.
if ($script:RejectedCandidates.Count -gt 0) {
    Write-Host ""
    Write-Warning "$($script:RejectedCandidates.Count) candidate value(s) were REJECTED and will NOT be redacted:"
    Write-Host ""
    foreach ($rc in $script:RejectedCandidates) {
        Write-Host ("  " + (Format-MaskedSecret $rc.Value) + "  rejected: " + $rc.Reason) -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Info "If any of these IS a credential, put it in a -SecretsFrom file (one"
    Write-Info "value per line) and re-run: named values skip the identifier rules."
}

# Split off anything still present in the CURRENT checkout.
#
# --replace-text rewrites HEAD like any other commit. A value live in the
# working tree is live CONFIGURATION; rewriting it does not hide a credential,
# it changes what the file means, everywhere, including the commit the deploy
# tooling reads. Against a GitOps repository that is a change to the running
# system, made by a tool nobody thought was allowed to make one.
#
# It is also where the remaining false positives live, because a value in HEAD
# is usually there on purpose: fixtures in a redaction test, an example key in
# a scanner config, a field name.
$headFile = Join-Path $script:GssTmpDir "head-content"
# Byte for byte, like the object dump (see Invoke-NativeToFile).
$null = Invoke-NativeToFile -FilePath "git" -ArgumentList @("archive", "HEAD") -OutFile $headFile
$headText = if (Test-Path $headFile) { [System.IO.File]::ReadAllText($headFile) } else { "" }

$liveVals = @($script:SecretValues | Where-Object { $headText -and $headText.Contains($_) })
if ($liveVals.Count -gt 0) {
    Write-Host ""
    Write-Warning "$($liveVals.Count) value(s) are STILL PRESENT in the current checkout:"
    Write-Host ""
    foreach ($lv in $liveVals) { Write-Host ("  " + (Format-MaskedSecret $lv)) -ForegroundColor Gray }
    Write-Host ""
    if ($IncludeHeadValues) {
        Write-Error "-IncludeHeadValues given: these WILL be rewritten in HEAD too."
        Write-Warning "That changes live configuration. Be sure each one is a credential."
    } else {
        Write-Info "SKIPPED -- rewriting these would change live configuration, and a"
        Write-Info "credential that is still live needs rotating and moving out of the"
        Write-Info "file, which a history rewrite does not do."
        Write-Info "Deal with them, then re-run. Use -IncludeHeadValues to override."
        Write-Error "This run will exit 3: the repository still holds these values."
        $script:SecretValues = @($script:SecretValues | Where-Object { -not ($headText -and $headText.Contains($_)) })
        $script:HeadSkipped = $liveVals.Count
    }
}

if ($script:SecretValues.Count -eq 0) {
    # "Nothing to rewrite" and "clean" are different answers: values skipped
    # because they are live in HEAD are still in the repository.
    if ($script:HeadSkipped -gt 0) {
        Write-Error "Nothing left to rewrite, but $($script:HeadSkipped) value(s) live in HEAD were skipped."
        exit 3
    }
    Write-Success "No secret values found to redact."
    exit 0
}

# The replacement must not reproduce what it replaces. If TEXT contains a
# value, that value is written straight back into every commit; if a value
# contains TEXT, the two are too alike to tell apart afterwards.
if ($script:ReplacementSet) {
    foreach ($sec in $script:SecretValues) {
        if ($Replacement.Contains($sec) -or $sec.Contains($Replacement)) {
            Write-Error "-Replacement (--replacement) TEXT contains a value being replaced, or is contained in one:"
            Write-Host ("  " + (Format-MaskedSecret $sec)) -ForegroundColor Gray
            Write-Info "Choose a TEXT that shares nothing with the values. Nothing was changed."
            exit 1
        }
    }
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
    if ($script:ReplacementSet) {
        $lines.Add(("literal:{0}==>{1}" -f $sec, $Replacement))
    } else {
        $lines.Add(("literal:{0}==>REPLACE_WITH_SECRET_{1:D2}" -f $sec, $i))
    }
}
# UTF8 without BOM: filter-repo reads this file byte-for-byte, and a BOM would
# corrupt the first replacement rule.
[System.IO.File]::WriteAllLines($script:ReplacementsFile, $lines, (New-Object System.Text.UTF8Encoding($false)))

if ($DryRun) {
    Write-Host ""
    Write-Success "DRY RUN MODE - No changes will be made"
    Write-Info "Would replace the $($script:SecretValues.Count) value(s) above with $(Get-PlaceholderLabel)."
    if ($script:HeadSkipped -gt 0) {
        Write-Error "Exiting 3: $($script:HeadSkipped) value(s) live in HEAD would be skipped."
        exit 3
    }
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

# -Yes selects every file only when the operator LISTED them (-Files,
# -FilesFrom): that list is already a decision. Files a scan proposed are
# still chosen by a person.
if ($Yes -and ($manualFiles -or $filesFromPath)) {
    $selection = "A"
    Write-Info "-Yes: selecting every listed file"
} else {
    $selection = Read-Host "Enter file numbers (comma-separated) or 'A' for all, 'N' to cancel"
}

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
# There is no backup branch. There used to be one, created in this repository
# just before the rewrite -- and filter-repo rewrites EVERY ref, so the
# "backup" came out redacted along with everything else. It backed up nothing.
$repoFull = (Get-Location).Path
Write-Warning "BACKUP: this tool does not make one. Take it BEFORE confirming, outside"
Write-Warning "this repository -- a mirror clone keeps every ref:"
Write-Info "  git clone --mirror ""$repoFull"" ""$repoFull.mirror-backup.git"""
Write-Host ""
if ($Yes) {
    Write-Warning "-Yes given: proceeding without the confirmation prompt."
} else {
    $confirm = Read-Host "Type 'YES' to continue"
    if ($confirm -ne "YES") {
        Write-Info "Aborted."
        exit 0
    }
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

# Rewrite history
Write-Host ""
if ($script:Mode -eq "redact") {
    Write-Header "Step 8: Redacting secret values in git history..."
} else {
    Write-Header "Step 8: Removing files from git history..."
}
Write-Info "This may take a while..."

if ($script:Mode -eq "redact") {
    # --replace-message with the SAME expressions: --replace-text reaches file
    # contents only, and a value pasted into a commit message or a tag
    # annotation is pushed like any other object.
    $filterRepoArgs = @("--replace-text", $script:ReplacementsFile, "--replace-message", $script:ReplacementsFile, "--force")
    # Deliberately not echoed with its argument expanded: the replacements file
    # is a plaintext list of every credential in the repository.
    Write-Info "Running: git filter-repo --replace-text <replacements> --replace-message <replacements> --force"
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
    Write-Warning "Do not push. Restore from the mirror clone you took before the run."
    exit 1
}

# Keep the commit-map where it survives. .git/filter-repo/commit-map is the
# old-SHA -> new-SHA table GitLab's Repository cleanup asks for; the next
# filter-repo run overwrites it and deleting the clone deletes it. A copy
# beside the repository outlives both.
$commitMapSrc = Join-Path (git rev-parse --git-dir) (Join-Path "filter-repo" "commit-map")
if (-not [System.IO.Path]::IsPathRooted($commitMapSrc)) { $commitMapSrc = Join-Path (Get-Location).Path $commitMapSrc }
$commitMapCopy = $null
if ((Test-Path $commitMapSrc) -and (Get-Item $commitMapSrc).Length -gt 0) {
    $repoDir = (Get-Location).Path
    $parentDir = Split-Path -Parent $repoDir
    $leaf = Split-Path -Leaf $repoDir
    $commitMapCopy = Join-Path $parentDir "$leaf.commit-map"
    if (Test-Path $commitMapCopy) {
        $commitMapCopy = Join-Path $parentDir "$leaf.$(Get-Date -Format 'yyyyMMdd-HHmmss').commit-map"
    }
    try {
        Copy-Item -Path $commitMapSrc -Destination $commitMapCopy -ErrorAction Stop
    } catch {
        Write-Warning "Could not copy the commit-map to $commitMapCopy -- keep $commitMapSrc yourself."
        $commitMapCopy = $null
    }
}

# Clean up
Write-Host ""
Write-Header "Step 9: Cleaning up git references..."
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Restore remotes (git-filter-repo removes them)
Write-Host ""
Write-Header "Step 10: Restoring remote configuration..."
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
# Step 11: Verify with gitleaks
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
    Write-Header "Step 11a: Verifying redaction directly..."
    $script:RedactVerifyOk = Test-Redaction -Secrets $script:SecretValues -PreBlobs $script:PreBlobs
    Write-Host ""
}

if ($gitleaksPath) {
    Write-Host ""
    Write-Header "Step 11: Verifying cleanup with gitleaks..."
    Write-Info "Running gitleaks scan to verify secrets are removed..."
    Write-Host ""

    $gitleaksCmd = $gitleaksPath
    # Use same format as detection scan for consistency
    # Exit code 0 = no secrets, 1 = secrets found
    $verifyReport = Join-Path $script:TempRoot "gitleaks-verify-$(Get-Random).json"
    $vcfg = @(); if ($script:GitleaksConfigFile -and (Test-Path $script:GitleaksConfigFile)) { $vcfg = @("--config", $script:GitleaksConfigFile) }
    $null = & $gitleaksCmd detect --source . --log-opts="--all --full-history" --no-banner @vcfg --report-format json --report-path $verifyReport 2>&1
    $verifyExitCode = $LASTEXITCODE
    
    # Check if report has any findings
    $hasFindings = $false
    $verifyContent = $null
    if ((Test-Path $verifyReport) -and (Get-Item $verifyReport).Length -gt 2) {
        $verifyContent = Get-Content $verifyReport -Raw
        if ($verifyContent -and $verifyContent -ne "[]" -and $verifyContent -ne "null") {
            $hasFindings = $true
        }
    }
    Remove-Item $verifyReport -Force -ErrorAction SilentlyContinue

    # A scan that never ran is checked FIRST. Only 0 and 1 are scan results; any
    # other code means gitleaks aborted without writing a report, and "no
    # findings" in a report that does not exist used to take the success branch.
    if ($verifyExitCode -ne 0 -and $verifyExitCode -ne 1) {
        Write-Error "✗ Verification did NOT run (gitleaks exit code $verifyExitCode) -- this cleanup is unverified."
        Write-Info "Re-run manually: gitleaks detect --source . --log-opts=`"--all --full-history`""
    } elseif ($verifyExitCode -eq 0 -or -not $hasFindings) {
        Write-Success "✓ No secrets detected by gitleaks!"
    } elseif ($script:Mode -eq "redact" -and (Get-RealFindingCount $verifyContent) -eq 0) {
        # Every remaining finding is a placeholder: REPLACE_WITH_SECRET_NN, or
        # the -Replacement TEXT. generic-api-key fires on `Password=<anything>`
        # whatever the value is, so a successful redaction leaves a repo that
        # scans dirty forever. Calling that "secrets still detected" trains the
        # operator to ignore the scanner.
        Write-Success "✓ No secrets detected by gitleaks!"
        Write-Host ""
        Write-Info "gitleaks matched only the $(Get-PlaceholderLabel) placeholders."
        Write-Info "Allowlist them so future scans stay meaningful -- in .gitleaks.toml:"
        Write-Host ""
        Write-Host "  [[allowlists]]" -ForegroundColor Gray
        Write-Host "  description = ""Redaction placeholders left by git-secret-scrubber""" -ForegroundColor Gray
        Write-Host "  regexes = ['''$(Get-PlaceholderRegex)''']" -ForegroundColor Gray
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

# GitLab keeps the old commits after the force-push. None of this is done by
# the push, and none of it can be done from here.
Write-Header "Commit-map and GitLab follow-up"
if ($commitMapCopy) {
    Write-Success "commit-map (old SHA -> new SHA) copied to:"
    Write-Host "   $commitMapCopy" -ForegroundColor Cyan
    Write-Info "  (original: $commitMapSrc -- overwritten by the next filter-repo run)"
} else {
    Write-Warning "No commit-map found at $commitMapSrc."
}
Write-Host ""
Write-Info "On GitLab the force-push does NOT remove the old commits:"
Write-Info "  - refs/merge-requests/* are read-only. Every merge request keeps its old"
Write-Info "    head commit and its stored diff, whatever you push. An MR whose diff"
Write-Info "    shows a secret must be deleted (not just closed) to lose it."
Write-Info "  - refs/keep-around/* pin commits that pipelines, notes and MR diffs"
Write-Info "    point at. Only Repository cleanup removes them."
Write-Info "  - After the push, wait 30 minutes (cleanup skips newer objects), then:"
Write-Info "    Settings → Repository → Repository maintenance → Repository cleanup"
Write-Info "    (older GitLab: Settings → Repository → Repository cleanup)"
Write-Info "    and upload the commit-map above."
Write-Host ""
if (Test-Path ".gitleaksignore") {
    Write-Warning "Reminder: every .gitleaksignore fingerprint is now dead (they carry old SHAs)."
    Write-Host ""
}

Write-Error "╔══════════════════════════════════════════════════════════════════╗"
Write-Error "║  ⚠️  REMINDER: After force-push, ALL teammates must RE-CLONE!     ║"
Write-Error "║  Their local copies will be incompatible with the new history.  ║"
Write-Error "╚══════════════════════════════════════════════════════════════════╝"

if ($script:Mode -eq "redact") {
    Write-Info "Redacted values now read $(Get-PlaceholderLabel). Allowlist that string"
    Write-Info "in your gitleaks config, or every historical commit fails future scans."
    Write-Host ""
}

# A scrub that could not prove itself must not exit 0 -- CI and shell callers
# read the status, not the log.
if ($script:Mode -eq "redact" -and -not $script:RedactVerifyOk) {
    Write-Error "Exiting non-zero: redaction could not be verified."
    exit 1
}
# Nor may a scrub that knowingly left values behind: the ones live in HEAD
# were skipped by design and are still in every commit that has them.
if ($script:Mode -eq "redact" -and $script:HeadSkipped -gt 0) {
    Write-Error "Exiting 3: $($script:HeadSkipped) value(s) live in HEAD were skipped and are still in history."
    exit 3
}
Write-Host ""
# Explicit, or the status is whatever the last native command left in
# $LASTEXITCODE -- gitleaks' 1 for "placeholders found" -- when this script is
# invoked from -Command or another script rather than with -File.
exit 0
