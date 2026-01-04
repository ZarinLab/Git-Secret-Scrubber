#!/bin/bash
#
# Git Secret Scrubber - Remove secrets from Git history safely.
#
# This tool removes entire files from Git history using git filter-repo.
# It does NOT edit file contents - it completely removes selected files
# from all commits in your repository's history.
#
# Usage:
#   ./clean-secrets.sh [PATH] [OPTIONS]
#
# Run with --help to see all available options.
#
# Arguments:
#   PATH             Path to the git repository to clean (optional)
#
# Common Options:
#   --dry-run        Preview what will be cleaned without making changes
#   --force          Proceed even with uncommitted changes
#   --skip-gitleaks  Skip gitleaks detection (manually specify files)
#   --no-download    Disable automatic downloading of gitleaks
#   --path FOLDER    Path to the git repository (alternative to positional arg)
#   --files LIST     Comma-separated list of files to clean
#   --files-from FILE  Read files to clean from a text file
#   -h, --help       Show full help message
#
# Examples:
#   ./clean-secrets.sh /path/to/repo          # Clean a specific repository
#   ./clean-secrets.sh --dry-run              # Preview changes
#   ./clean-secrets.sh                        # Full cleanup with gitleaks
#   ./clean-secrets.sh --skip-gitleaks        # Skip detection, enter manually
#   ./clean-secrets.sh --files ".env,secrets.json"  # Clean specific files
#
# Author: ZarinLab
# License: Apache 2.0
# Repository: https://github.com/ZarinLab/Git-Secret-Scrubber
# Version: 0.1.0
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Parse arguments
DRY_RUN=false
FORCE=false
SKIP_GITLEAKS=false
NO_DOWNLOAD=false
REPO_PATH=""
MANUAL_FILES=""
FILES_FROM=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --skip-gitleaks)
            SKIP_GITLEAKS=true
            shift
            ;;
        --no-download)
            NO_DOWNLOAD=true
            shift
            ;;
        --path)
            REPO_PATH="$2"
            shift 2
            ;;
        --files)
            # Comma-separated list of files
            MANUAL_FILES="$2"
            SKIP_GITLEAKS=true
            shift 2
            ;;
        --files-from)
            # Read files from a text file (one per line)
            FILES_FROM="$2"
            SKIP_GITLEAKS=true
            shift 2
            ;;
        -h|--help)
            echo "Git Secret Scrubber - Remove secrets from Git history"
            echo ""
            echo "Usage: $0 [OPTIONS] [PATH]"
            echo ""
            echo "Arguments:"
            echo "  PATH             Path to the git repository to clean (optional, default: current directory)"
            echo ""
            echo "Options:"
            echo "  --dry-run        Preview what will be cleaned without making changes"
            echo "  --force          Proceed even with uncommitted changes"
            echo "  --skip-gitleaks  Skip gitleaks detection (prompt for manual input)"
            echo "  --no-download    Disable automatic downloading of gitleaks"
            echo "  --path FOLDER    Path to the git repository to clean (alternative to positional arg)"
            echo "  --files LIST     Comma-separated list of files to clean"
            echo "                   Example: --files 'secrets.txt,config/.env'"
            echo "  --files-from FILE  Read files to clean from a text file (one per line)"
            echo "                   Example: --files-from files-to-clean.txt"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 /path/to/repo                # Clean a specific repository"
            echo "  $0 --dry-run                    # Preview with gitleaks detection"
            echo "  $0 --path /path/to/repo         # Same as positional argument"
            echo "  $0 --files 'secrets.txt,.env'   # Clean specific files"
            echo "  $0 --files-from cleanup.txt     # Read files from cleanup.txt"
            echo "  $0 --skip-gitleaks              # Skip detection, enter files manually"
            exit 0
            ;;
        *)
            # If it's not an option (doesn't start with -), treat as path
            if [[ "$1" != -* && -z "$REPO_PATH" ]]; then
                REPO_PATH="$1"
                shift
            else
                echo "Unknown option: $1"
                echo "Usage: $0 [OPTIONS] [PATH]"
                echo "Use --help for more information."
                exit 1
            fi
            ;;
    esac
done

# Change to specified path if provided
if [[ -n "$REPO_PATH" ]]; then
    if [[ -d "$REPO_PATH" ]]; then
        cd "$REPO_PATH" || { echo "Error: Cannot change to directory: $REPO_PATH"; exit 1; }
        echo "Working in: $REPO_PATH"
    else
        echo "Error: Path not found: $REPO_PATH"
        exit 1
    fi
fi

# Helper functions
print_header() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_info() {
    echo -e "${GRAY}$1${NC}"
}

# Display important security reminder
echo ""
print_error "╔══════════════════════════════════════════════════════════════════╗"
print_error "║  ⚠️  IMPORTANT: ROTATE YOUR SECRETS IMMEDIATELY!                  ║"
print_error "║                                                                  ║"
print_error "║  Removing secrets from git history does NOT revoke them.        ║"
print_error "║  Any secrets that were exposed should be rotated/invalidated.   ║"
print_error "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in a git repository
if [[ ! -d ".git" ]]; then
    print_error "ERROR: Not in a git repository!"
    exit 1
fi

# Get current branch
CURRENT_BRANCH=$(git branch --show-current)
print_info "Current branch: $CURRENT_BRANCH"
echo ""

# ============================================================================
# Detection Method Selection (if not specified via command line)
# ============================================================================
DETECTION_METHOD=""

# Check if user already specified files via command line
if [[ -n "$MANUAL_FILES" ]]; then
    DETECTION_METHOD="files"
    print_info "Using files from --files argument"
elif [[ -n "$FILES_FROM" ]]; then
    DETECTION_METHOD="file"
    print_info "Using files from: $FILES_FROM"
elif [[ "$SKIP_GITLEAKS" == true ]]; then
    # User wants to skip gitleaks but didn't provide files - will prompt later
    DETECTION_METHOD="manual"
else
    # Ask user how they want to detect secrets
    echo ""
    print_header "How would you like to identify files with secrets?"
    echo ""
    echo -e "  ${CYAN}[1]${NC} Automatic detection using gitleaks (recommended)"
    echo -e "      Scans git history for secrets automatically"
    echo ""
    echo -e "  ${CYAN}[2]${NC} Enter a comma-separated list of files"
    echo -e "      Example: secrets.txt, config/.env, credentials.json"
    echo ""
    echo -e "  ${CYAN}[3]${NC} Load files from a text file"
    echo -e "      One file path per line, supports # comments"
    echo ""
    
    read -p "Select option [1/2/3] (default: 1): " DETECTION_CHOICE
    
    case "$DETECTION_CHOICE" in
        2)
            DETECTION_METHOD="files"
            SKIP_GITLEAKS=true
            echo ""
            print_info "Enter the file paths to clean from git history."
            print_info "Separate multiple files with commas."
            echo ""
            read -p "File paths: " MANUAL_FILES
            if [[ -z "$MANUAL_FILES" ]]; then
                print_error "No files specified. Exiting."
                exit 1
            fi
            ;;
        3)
            DETECTION_METHOD="file"
            SKIP_GITLEAKS=true
            echo ""
            print_info "Enter the path to a text file containing file paths to clean."
            print_info "The file should have one path per line. Lines starting with # are ignored."
            echo ""
            read -p "Text file path: " FILES_FROM
            if [[ -z "$FILES_FROM" ]]; then
                print_error "No file specified. Exiting."
                exit 1
            fi
            if [[ ! -f "$FILES_FROM" ]]; then
                print_error "File not found: $FILES_FROM"
                exit 1
            fi
            ;;
        1|"")
            DETECTION_METHOD="gitleaks"
            print_info "Using automatic detection with gitleaks"
            ;;
        *)
            print_warning "Invalid choice. Using automatic detection."
            DETECTION_METHOD="gitleaks"
            ;;
    esac
fi

echo ""

# Check for uncommitted changes
if [[ -n "$(git status --porcelain)" ]]; then
    # List of cleanup-related files that are safe to have uncommitted
    CLEANUP_FILES=("clean-secrets.sh" "clean-secrets.ps1" "docs/protected-branches.md" "docs/README.md" ".gitignore" "README.md")
    
    STATUS=$(git status --porcelain)
    NON_CLEANUP_FILES=()
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        
        # Extract file path from porcelain output
        # Format: XY filename  OR  XY old -> new (for renames)
        FILE=$(echo "$line" | sed 's/^[^ ]* *//' | sed 's/^"//;s/"$//')
        
        # Handle rename lines: "old -> new" - extract just the new filename
        if [[ "$FILE" == *" -> "* ]]; then
            FILE="${FILE##* -> }"
            # Also remove quotes from the new name if present
            FILE=$(echo "$FILE" | sed 's/^"//;s/"$//')
        fi
        
        IS_CLEANUP=false
        for CLEANUP_FILE in "${CLEANUP_FILES[@]}"; do
            if [[ "$FILE" == "$CLEANUP_FILE" ]] || [[ "$FILE" == *"/$CLEANUP_FILE" ]]; then
                IS_CLEANUP=true
                break
            fi
        done
        
        if [[ "$IS_CLEANUP" == false ]]; then
            NON_CLEANUP_FILES+=("$FILE")
        fi
    done <<< "$STATUS"
    
    if [[ ${#NON_CLEANUP_FILES[@]} -gt 0 ]]; then
        print_warning "WARNING: You have uncommitted changes in files that are NOT part of this cleanup tool!"
        print_warning "Modified files:"
        for FILE in "${NON_CLEANUP_FILES[@]}"; do
            echo -e "  ${YELLOW}- $FILE${NC}"
        done
        echo ""
        print_info "It's recommended to commit or stash these changes before cleaning git history."
        echo ""
        
        if [[ "$FORCE" == false ]]; then
            read -p "Do you want to proceed anyway? (yes/no) [default: no]: " PROCEED
            if [[ -z "$PROCEED" ]] || ([[ "$PROCEED" != "yes" ]] && [[ "$PROCEED" != "y" ]]); then
                print_info "Aborted. Please commit or stash your changes first, or use --force flag to skip this prompt."
                exit 0
            else
                print_warning "Proceeding with uncommitted changes in other files..."
                echo ""
            fi
        else
            print_warning "Proceeding with --force flag (you have uncommitted changes in other files)..."
            echo ""
        fi
    else
        print_info "Uncommitted changes are only in cleanup script files - this is OK."
        echo ""
    fi
fi

# ============================================================================
# Step 1: Setup git-filter-repo (prefer system binary, fallback to venv)
# ============================================================================
print_header "Step 1: Setting up git-filter-repo..."

# Create unique temp paths based on repo name to avoid collisions
REPO_NAME=$(basename "$(pwd)" | tr ' ' '_')
TEMP_BASE="${TMPDIR:-/tmp}/git-secret-scrubber-${REPO_NAME}-$$"
VENV_PATH="${TEMP_BASE}/venv"
BIN_DIR="${TEMP_BASE}/bin"

PYTHON_CMD=""
USE_SYSTEM_FILTER_REPO=false
FILTER_REPO_CMD=""

# Function to test if Python is actually working
test_python() {
    local python_path="$1"
    if "$python_path" --version &>/dev/null; then
        return 0
    fi
    return 1
}

# Check if git-filter-repo is already installed system-wide
if command -v git-filter-repo &> /dev/null; then
    FILTER_REPO_CMD="git-filter-repo"
    USE_SYSTEM_FILTER_REPO=true
    print_success "Found system git-filter-repo: $(command -v git-filter-repo)"
fi

# Check for Python in PATH (needed for gitleaks download parsing and fallback filter-repo)
for cmd in python3 python; do
    if command -v "$cmd" &> /dev/null; then
        PYTHON_PATH=$(command -v "$cmd")
        if test_python "$PYTHON_PATH"; then
            PYTHON_CMD="$PYTHON_PATH"
            print_success "Found Python: $PYTHON_CMD"
            break
        fi
    fi
done

# If not found in PATH, try common locations
if [[ -z "$PYTHON_CMD" ]]; then
    print_info "Python not found in PATH, checking common installation locations..."
    
    COMMON_PATHS=(
        "$HOME/.local/bin/python3"
        "/usr/bin/python3"
        "/usr/local/bin/python3"
        "/opt/homebrew/bin/python3"
    )
    
    for path in "${COMMON_PATHS[@]}"; do
        if [[ -f "$path" ]] && test_python "$path"; then
            PYTHON_CMD="$path"
            print_success "Found Python: $PYTHON_CMD"
            break
        fi
    done
fi

if [[ -z "$PYTHON_CMD" ]]; then
    print_error "ERROR: Python is not installed or not working!"
    echo ""
    print_info "Please install Python from one of these sources:"
    print_info "  1. Official Python: https://www.python.org/downloads/"
    print_info "  2. Package manager:"
    print_info "     - Ubuntu/Debian: sudo apt install python3 python3-venv"
    print_info "     - macOS: brew install python3"
    print_info "     - Fedora: sudo dnf install python3"
    echo ""
    print_warning "Note: If Python is installed but not found, make sure it's added to PATH"
    exit 1
fi

# If no system git-filter-repo, set up virtual environment
if [[ "$USE_SYSTEM_FILTER_REPO" == false ]]; then
    print_info "git-filter-repo not found in PATH, setting up via Python venv..."
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "$VENV_PATH" ]]; then
        print_info "Creating virtual environment at $VENV_PATH..."
        
        if ! "$PYTHON_CMD" -m venv "$VENV_PATH" 2>&1; then
            print_error "Failed to create virtual environment!"
            exit 1
        fi
        print_success "Virtual environment created"
    else
        print_info "Virtual environment already exists"
    fi

    # Get paths
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        PIP_PATH="$VENV_PATH/Scripts/pip"
        VENV_PYTHON="$VENV_PATH/Scripts/python"
    else
        PIP_PATH="$VENV_PATH/bin/pip"
        VENV_PYTHON="$VENV_PATH/bin/python"
    fi

    # Verify pip exists
    if [[ ! -f "$PIP_PATH" ]]; then
        print_error "pip not found in virtual environment: $PIP_PATH"
        print_info "The virtual environment may be corrupted. Try deleting $VENV_PATH and running again."
        exit 1
    fi

    # Install git-filter-repo
    print_info "Installing git-filter-repo..."
    if ! "$PIP_PATH" install git-filter-repo --quiet --disable-pip-version-check 2>&1; then
        print_error "Failed to install git-filter-repo!"
        exit 1
    fi
    print_success "git-filter-repo installed via pip"
else
    # Set VENV_PYTHON for consistency (used later in gitleaks parsing)
    VENV_PYTHON="$PYTHON_CMD"
fi

echo ""

# ============================================================================
# Step 2: Check for gitleaks (optional - may skip if not needed)
# ============================================================================
print_header "Step 2: Checking for gitleaks..."

GITLEAKS_PATH=""
if command -v gitleaks &> /dev/null; then
    GITLEAKS_PATH=$(command -v gitleaks)
    print_success "Found gitleaks: $GITLEAKS_PATH"
elif [[ "$SKIP_GITLEAKS" == false ]] && [[ "$NO_DOWNLOAD" == false ]]; then
    print_info "gitleaks not found in PATH. Attempting to download..."
    
    # Create bin directory for gitleaks in temp location
    mkdir -p "$BIN_DIR"
elif [[ "$SKIP_GITLEAKS" == false ]] && [[ "$NO_DOWNLOAD" == true ]]; then
    print_warning "gitleaks not found and --no-download specified."
    print_info "Please install gitleaks manually or use --skip-gitleaks"
    print_info "  macOS: brew install gitleaks"
    print_info "  Linux: Download from https://github.com/gitleaks/gitleaks/releases"
    SKIP_GITLEAKS=true
fi

if [[ "$SKIP_GITLEAKS" == false ]] && [[ -z "$GITLEAKS_PATH" ]] && [[ "$NO_DOWNLOAD" == false ]]; then
    
    # Determine OS and architecture
    OS=""
    ARCH=""
    EXT=""
    
    case "$(uname -s)" in
        Linux*)
            OS="linux"
            EXT=""
            ;;
        Darwin*)
            OS="darwin"
            EXT=""
            ;;
        *)
            print_warning "Unsupported OS. Please install gitleaks manually."
            SKIP_GITLEAKS=true
            ;;
    esac
    
    if [[ "$SKIP_GITLEAKS" == false ]]; then
        case "$(uname -m)" in
            x86_64|amd64)
                ARCH="amd64"
                ;;
            arm64|aarch64)
                ARCH="arm64"
                ;;
            *)
                print_warning "Unsupported architecture. Please install gitleaks manually."
                SKIP_GITLEAKS=true
                ;;
        esac
    fi
    
    if [[ "$SKIP_GITLEAKS" == false ]]; then
        # Get latest version from GitHub API
        print_info "Fetching latest gitleaks version..."
        if command -v curl &> /dev/null; then
            LATEST_RELEASE=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest)
        elif command -v wget &> /dev/null; then
            LATEST_RELEASE=$(wget -qO- https://api.github.com/repos/gitleaks/gitleaks/releases/latest)
        else
            print_warning "curl or wget not found. Cannot download gitleaks."
            SKIP_GITLEAKS=true
        fi
        
        if [[ "$SKIP_GITLEAKS" == false ]]; then
            # Extract version and download URL using Python (portable across all platforms)
            # We already verified Python is available earlier in the script
            ASSET_NAME_PATTERN="gitleaks_.*_${OS}_${ARCH}"
            
            read -r GITLEAKS_VERSION DOWNLOAD_URL CHECKSUM_URL <<< $(echo "$LATEST_RELEASE" | "$PYTHON_CMD" -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tag = data.get('tag_name', '')
    version = tag.lstrip('v')
    os_name = '${OS}'
    arch = '${ARCH}'
    asset_name = f'gitleaks_{version}_{os_name}_{arch}'
    url = ''
    checksum_url = ''
    for asset in data.get('assets', []):
        name = asset.get('name', '')
        if name.startswith(asset_name) and not name.endswith('.sig'):
            url = asset.get('browser_download_url', '')
        if name == 'gitleaks_' + version + '_checksums.txt':
            checksum_url = asset.get('browser_download_url', '')
    print(f'{tag} {url} {checksum_url}')
except Exception as e:
    print('')
" 2>/dev/null || echo "")
            
            VERSION=$(echo "$GITLEAKS_VERSION" | sed 's/^v//')
            
            if [[ -n "$DOWNLOAD_URL" ]]; then
                # Ask user for permission to download
                echo ""
                print_warning "gitleaks is required for automatic secret detection."
                print_warning "We can download it for you, or you can install it manually."
                echo ""
                print_info "Version: $GITLEAKS_VERSION"
                print_info "Download URL: $DOWNLOAD_URL"
                if [[ -n "$CHECKSUM_URL" ]]; then
                    print_info "Checksums: $CHECKSUM_URL"
                fi
                echo ""
                print_info "Manual installation options:"
                if [[ "$OS" == "darwin" ]]; then
                    print_info "  brew install gitleaks"
                elif [[ "$OS" == "linux" ]]; then
                    print_info "  apt install gitleaks  (or your package manager)"
                fi
                print_info "  Download from: https://github.com/gitleaks/gitleaks/releases"
                echo ""
                
                read -p "Download gitleaks automatically? (yes/no) [default: yes]: " DOWNLOAD_CHOICE
                if [[ -z "$DOWNLOAD_CHOICE" ]] || [[ "$DOWNLOAD_CHOICE" == "yes" ]] || [[ "$DOWNLOAD_CHOICE" == "y" ]]; then
                    print_info "Downloading gitleaks $GITLEAKS_VERSION..."
                    
                    # Determine the archive filename from URL
                    ARCHIVE_NAME=$(basename "$DOWNLOAD_URL")
                    ARCHIVE_PATH="$BIN_DIR/$ARCHIVE_NAME"
                    
                    # Download the archive
                    if command -v curl &> /dev/null; then
                        curl -L -o "$ARCHIVE_PATH" "$DOWNLOAD_URL" || {
                            print_warning "Download failed"
                            SKIP_GITLEAKS=true
                        }
                    elif command -v wget &> /dev/null; then
                        wget -O "$ARCHIVE_PATH" "$DOWNLOAD_URL" || {
                            print_warning "Download failed"
                            SKIP_GITLEAKS=true
                        }
                    fi
                    
                    # Verify checksum if available
                    if [[ -f "$ARCHIVE_PATH" ]] && [[ -n "$CHECKSUM_URL" ]] && [[ "$SKIP_GITLEAKS" == false ]]; then
                        print_info "Verifying checksum..."
                        
                        # Download checksums file
                        CHECKSUMS_FILE="$BIN_DIR/checksums.txt"
                        if command -v curl &> /dev/null; then
                            curl -sL -o "$CHECKSUMS_FILE" "$CHECKSUM_URL" 2>/dev/null
                        elif command -v wget &> /dev/null; then
                            wget -qO "$CHECKSUMS_FILE" "$CHECKSUM_URL" 2>/dev/null
                        fi
                        
                        if [[ -f "$CHECKSUMS_FILE" ]]; then
                            # Calculate SHA256 of downloaded file
                            if command -v sha256sum &> /dev/null; then
                                ACTUAL_HASH=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
                            elif command -v shasum &> /dev/null; then
                                ACTUAL_HASH=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')
                            else
                                ACTUAL_HASH=""
                                print_warning "Cannot verify checksum (sha256sum/shasum not found)"
                            fi
                            
                            if [[ -n "$ACTUAL_HASH" ]]; then
                                EXPECTED_HASH=$(grep "$ARCHIVE_NAME" "$CHECKSUMS_FILE" | awk '{print $1}')
                                if [[ -n "$EXPECTED_HASH" ]]; then
                                    if [[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
                                        print_success "Checksum verified: $ACTUAL_HASH"
                                    else
                                        print_error "Checksum mismatch!"
                                        print_error "Expected: $EXPECTED_HASH"
                                        print_error "Actual:   $ACTUAL_HASH"
                                        rm -f "$ARCHIVE_PATH" "$CHECKSUMS_FILE" 2>/dev/null
                                        SKIP_GITLEAKS=true
                                    fi
                                else
                                    print_warning "Could not find checksum for $ARCHIVE_NAME"
                                    print_info "SHA256: $ACTUAL_HASH"
                                fi
                            fi
                            rm -f "$CHECKSUMS_FILE" 2>/dev/null
                        else
                            print_warning "Could not download checksums file"
                        fi
                    fi
                    
                    # Extract the binary from the archive
                    if [[ -f "$ARCHIVE_PATH" ]] && [[ "$SKIP_GITLEAKS" == false ]]; then
                        print_info "Extracting gitleaks from archive..."
                        
                        if [[ "$ARCHIVE_NAME" == *.tar.gz ]] || [[ "$ARCHIVE_NAME" == *.tgz ]]; then
                            # Extract tar.gz archive
                            tar -xzf "$ARCHIVE_PATH" -C "$BIN_DIR" gitleaks 2>/dev/null || \
                            tar -xzf "$ARCHIVE_PATH" -C "$BIN_DIR" --strip-components=1 2>/dev/null || {
                                print_warning "Failed to extract gitleaks from tar.gz"
                                SKIP_GITLEAKS=true
                            }
                        elif [[ "$ARCHIVE_NAME" == *.zip ]]; then
                            # Extract zip archive
                            if command -v unzip &> /dev/null; then
                                unzip -o -j "$ARCHIVE_PATH" "gitleaks" -d "$BIN_DIR" 2>/dev/null || \
                                unzip -o "$ARCHIVE_PATH" -d "$BIN_DIR" 2>/dev/null || {
                                    print_warning "Failed to extract gitleaks from zip"
                                    SKIP_GITLEAKS=true
                                }
                            else
                                print_warning "unzip not found, cannot extract archive"
                                SKIP_GITLEAKS=true
                            fi
                        else
                            # Assume it's a raw binary (Windows .exe case)
                            mv "$ARCHIVE_PATH" "$BIN_DIR/gitleaks"
                        fi
                        
                        # Clean up archive
                        rm -f "$ARCHIVE_PATH" 2>/dev/null
                        
                        # Set path and permissions
                        GITLEAKS_PATH="$BIN_DIR/gitleaks"
                        if [[ -f "$GITLEAKS_PATH" ]]; then
                            chmod +x "$GITLEAKS_PATH"
                            # Try to canonicalize path with realpath if available (best-effort)
                            GITLEAKS_PATH=$(realpath "$GITLEAKS_PATH" 2>/dev/null || echo "$GITLEAKS_PATH")
                            
                            # Show version info
                            INSTALLED_VERSION=$("$GITLEAKS_PATH" version 2>/dev/null || echo "unknown")
                            print_success "gitleaks installed successfully"
                            print_info "Version: $INSTALLED_VERSION"
                        else
                            print_warning "gitleaks binary not found after extraction"
                            SKIP_GITLEAKS=true
                        fi
                    fi
                else
                    # User declined download
                    print_info "Skipping gitleaks download."
                    print_info "You can install it manually and run this script again."
                    SKIP_GITLEAKS=true
                fi
            else
                print_warning "Could not find binary for $OS/$ARCH in release assets"
                print_info "Please install gitleaks manually:"
                if [[ "$OS" == "darwin" ]]; then
                    print_info "  brew install gitleaks"
                fi
                print_info "  Or download from: https://github.com/gitleaks/gitleaks/releases"
                SKIP_GITLEAKS=true
            fi
        fi
    fi
fi

DETECTED_FILES=()

if [[ "$SKIP_GITLEAKS" == true ]]; then
    print_info "Skipping gitleaks (not installed or download failed)"
else
    print_header "Step 3: Detecting secrets with gitleaks..."
fi

if [[ "$SKIP_GITLEAKS" == false ]]; then
    print_info "Running gitleaks scan..."
    
    # Use downloaded gitleaks if available, otherwise use system one
    GITLEAKS_CMD="${GITLEAKS_PATH:-gitleaks}"
    
    # Run gitleaks with JSON format (gitleaks native format, not SARIF)
    # Exit code: 0 = no secrets, 1 = secrets found, other = error
    # Run gitleaks with --log-opts to scan ENTIRE git history, not just working tree
    # IMPORTANT: Without this, gitleaks only scans current files, missing historical secrets
    print_info "Scanning entire git history (this may take a while for large repos)..."
    
    # Temporarily disable set -e to capture exit code properly
    set +e
    GITLEAKS_OUTPUT=$("$GITLEAKS_CMD" detect --source . --log-opts="--all --full-history" --no-banner --report-format json --report-path /dev/stdout 2>/dev/null)
    GITLEAKS_EXIT=$?
    set -e
    
    # Log exit code for debugging
    if [[ "$GITLEAKS_EXIT" -eq 0 ]]; then
        print_info "gitleaks scan complete: no secrets detected"
    elif [[ "$GITLEAKS_EXIT" -eq 1 ]]; then
        print_info "gitleaks scan complete: secrets detected"
    else
        print_warning "gitleaks scan returned exit code: $GITLEAKS_EXIT"
    fi
    
    if [[ -n "$GITLEAKS_OUTPUT" ]] && [[ "$GITLEAKS_OUTPUT" != "null" ]] && [[ "$GITLEAKS_OUTPUT" != "[]" ]]; then
        # Parse gitleaks native JSON format using Python (portable)
        # gitleaks JSON format: array of findings with File, RuleID, etc.
        PARSE_RESULT=$(echo "$GITLEAKS_OUTPUT" | "$PYTHON_CMD" -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if not data or not isinstance(data, list):
        print('')
        sys.exit(0)
    
    # Group findings by file
    files = {}
    for finding in data:
        file_path = finding.get('File', '')
        rule_id = finding.get('RuleID', 'unknown')
        if file_path:
            if file_path not in files:
                files[file_path] = set()
            files[file_path].add(rule_id)
    
    # Output in format: file|rules|index (one per line)
    for idx, (path, rules) in enumerate(sorted(files.items()), 1):
        rules_str = ','.join(sorted(rules))
        print(f'{path}|{rules_str}|{idx}')
except Exception as e:
    print('')
" 2>/dev/null)
        
        if [[ -n "$PARSE_RESULT" ]]; then
            echo ""
            print_warning "Found secrets in the following files:"
            echo ""
            
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                IFS='|' read -r file_path rules index_num <<< "$line"
                echo -e "  ${YELLOW}[$index_num] $file_path${NC}"
                echo -e "      ${GRAY}Secrets: $rules${NC}"
                DETECTED_FILES+=("$line")
            done <<< "$PARSE_RESULT"
            
            echo ""
            print_warning "Total files with secrets: ${#DETECTED_FILES[@]}"
        fi
    fi
    
    if [[ ${#DETECTED_FILES[@]} -eq 0 ]]; then
        print_success "No secrets detected by gitleaks!"
        echo ""
        print_info "This could mean:"
        print_info "  1. No secrets are present in git history"
        print_info "  2. gitleaks didn't detect them (check manually)"
        echo ""
        print_info "You can manually specify files to clean in the next step."
    fi
fi

# Check which files actually exist in git history
echo ""
print_header "Step 4: Checking files in git history..."

FILES_IN_HISTORY=()

# Process files from command line arguments first
if [[ -n "$MANUAL_FILES" ]]; then
    print_info "Using files from --files argument..."
    IFS=',' read -ra FILES_ARRAY <<< "$MANUAL_FILES"
    for file in "${FILES_ARRAY[@]}"; do
        file=$(echo "$file" | xargs) # trim whitespace
        [[ -z "$file" ]] && continue
        if git log --all --full-history --oneline -- "$file" 2>/dev/null | head -1 | grep -q .; then
            FILES_IN_HISTORY+=("$file|manual")
            print_success "  ✓ Found in history: $file"
        else
            print_warning "  ✗ Not in history: $file"
        fi
    done
elif [[ -n "$FILES_FROM" ]]; then
    if [[ -f "$FILES_FROM" ]]; then
        print_info "Reading files from: $FILES_FROM"
        while IFS= read -r file || [[ -n "$file" ]]; do
            file=$(echo "$file" | xargs) # trim whitespace
            # Skip empty lines and comments
            [[ -z "$file" ]] && continue
            [[ "$file" == \#* ]] && continue
            
            if git log --all --full-history --oneline -- "$file" 2>/dev/null | head -1 | grep -q .; then
                FILES_IN_HISTORY+=("$file|manual")
                print_success "  ✓ Found in history: $file"
            else
                print_warning "  ✗ Not in history: $file"
            fi
        done < "$FILES_FROM"
    else
        print_error "File not found: $FILES_FROM"
        exit 1
    fi
elif [[ ${#DETECTED_FILES[@]} -gt 0 ]]; then
    # Use files detected by gitleaks
    for file_entry in "${DETECTED_FILES[@]}"; do
        IFS='|' read -r file_path rules _index <<< "$file_entry"
        if git log --all --full-history --oneline -- "$file_path" 2>/dev/null | head -1 | grep -q .; then
            FILES_IN_HISTORY+=("$file_path|$rules")
            print_success "  ✓ Found in history: $file_path"
        else
            print_info "  ✗ Not in history: $file_path"
        fi
    done
fi

# If still no files, prompt for manual input
if [[ ${#FILES_IN_HISTORY[@]} -eq 0 ]]; then
    echo ""
    if [[ "$SKIP_GITLEAKS" == true ]]; then
        print_info "No files specified. Please enter files to clean."
    else
        print_success "No files found in git history from gitleaks scan."
        print_info "If you know files with secrets, you can manually specify them."
    fi
    echo ""
    print_info "You can enter:"
    print_info "  - Comma-separated file paths: secrets.txt, config/.env"
    print_info "  - Path to a text file with one file per line: @files-to-clean.txt"
    echo ""
    read -p "Enter file paths (or @filename for file list, or press Enter to exit): " USER_INPUT
    
    if [[ -z "$USER_INPUT" ]]; then
        exit 0
    fi
    
    # Check if user provided a file reference
    if [[ "$USER_INPUT" == @* ]]; then
        INPUT_FILE="${USER_INPUT:1}" # Remove @ prefix
        if [[ -f "$INPUT_FILE" ]]; then
            print_info "Reading files from: $INPUT_FILE"
            while IFS= read -r file || [[ -n "$file" ]]; do
                file=$(echo "$file" | xargs)
                [[ -z "$file" ]] && continue
                [[ "$file" == \#* ]] && continue
                
                if git log --all --full-history --oneline -- "$file" 2>/dev/null | head -1 | grep -q .; then
                    FILES_IN_HISTORY+=("$file|manual")
                    print_success "  ✓ Found in history: $file"
                else
                    print_warning "  ✗ Not in history: $file"
                fi
            done < "$INPUT_FILE"
        else
            print_error "File not found: $INPUT_FILE"
            exit 1
        fi
    else
        # Comma-separated list
        IFS=',' read -ra FILES_ARRAY <<< "$USER_INPUT"
        for file in "${FILES_ARRAY[@]}"; do
            file=$(echo "$file" | xargs)
            [[ -z "$file" ]] && continue
            
            if git log --all --full-history --oneline -- "$file" 2>/dev/null | head -1 | grep -q .; then
                FILES_IN_HISTORY+=("$file|manual")
                print_success "  ✓ Found in history: $file"
            else
                print_warning "  ✗ Not in history: $file"
            fi
        done
    fi
fi

if [[ ${#FILES_IN_HISTORY[@]} -eq 0 ]]; then
    print_error "No valid files to clean! None of the specified files exist in git history."
    exit 1
fi

echo ""

# ============================================================================
# Step 5: Let user select which files to clean
# ============================================================================
print_header "Step 5: Select files to clean from history"

echo ""
echo -e "${YELLOW}Files found in git history:${NC}"
echo ""

INDEX=1
for file_entry in "${FILES_IN_HISTORY[@]}"; do
    IFS='|' read -r file_path rules <<< "$file_entry"
    echo -e "  ${CYAN}[$INDEX] $file_path${NC}"
    if [[ "$rules" != "manual" ]]; then
        echo -e "      ${GRAY}Secrets: $rules${NC}"
    fi
    ((INDEX++))
done

echo ""
echo -e "${GREEN}  [A] All files${NC}"
echo -e "${RED}  [N] None (cancel)${NC}"
echo ""

read -p "Enter file numbers (comma-separated) or 'A' for all, 'N' to cancel: " SELECTION

if [[ "$SELECTION" == "N" ]] || [[ "$SELECTION" == "n" ]]; then
    print_info "Cancelled by user."
    exit 0
fi

SELECTED_FILES=()
if [[ "$SELECTION" == "A" ]] || [[ "$SELECTION" == "a" ]]; then
    SELECTED_FILES=("${FILES_IN_HISTORY[@]}")
    print_success "Selected all ${#SELECTED_FILES[@]} files"
else
    IFS=',' read -ra INDICES <<< "$SELECTION"
    for idx in "${INDICES[@]}"; do
        idx=$(echo "$idx" | xargs) # trim
        if [[ "$idx" -ge 1 ]] && [[ "$idx" -le ${#FILES_IN_HISTORY[@]} ]]; then
            SELECTED_FILES+=("${FILES_IN_HISTORY[$((idx-1))]}")
        else
            print_warning "Invalid index: $idx (skipping)"
        fi
    done
    
    if [[ ${#SELECTED_FILES[@]} -eq 0 ]]; then
        print_error "No valid files selected!"
        exit 1
    fi
    
    print_success "Selected ${#SELECTED_FILES[@]} file(s)"
fi

echo ""
echo -e "${YELLOW}Files that will be removed from history:${NC}"
for file_entry in "${SELECTED_FILES[@]}"; do
    IFS='|' read -r file_path rules <<< "$file_entry"
    echo -e "  ${GRAY}- $file_path${NC}"
done
echo ""

if [[ "$DRY_RUN" == true ]]; then
    print_success "DRY RUN MODE - No changes will be made"
    echo ""
    print_info "Would remove these files from history:"
    for file_entry in "${SELECTED_FILES[@]}"; do
        IFS='|' read -r file_path rules <<< "$file_entry"
        echo -e "  ${GREEN}✓ $file_path${NC}"
    done
    exit 0
fi

# ============================================================================
# Step 6: Confirm and proceed with cleanup
# ============================================================================
print_error "⚠️  WARNING: This will rewrite git history!"
print_error "⚠️  All commit SHAs will change!"
print_error "⚠️  You will need to force push!"
print_error "⚠️  All team members must re-clone the repository!"
echo ""
read -p "Type 'YES' to continue: " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
    print_info "Aborted."
    exit 0
fi

# Save remote information (git-filter-repo removes remotes)
echo ""
print_header "Step 7: Saving remote configuration..."
declare -A REMOTE_INFO
while IFS= read -r remote; do
    [[ -z "$remote" ]] && continue
    REMOTE_URL=$(git remote get-url "$remote" 2>/dev/null || echo "")
    if [[ -n "$REMOTE_URL" ]]; then
        REMOTE_INFO["$remote"]="$REMOTE_URL"
        print_info "Saved remote '$remote': $REMOTE_URL"
    fi
done < <(git remote)

# Create backup branch
echo ""
print_header "Step 8: Creating backup branch..."
BACKUP_BRANCH="backup-before-secret-cleanup-$(date +%Y%m%d-%H%M%S)"
git branch "$BACKUP_BRANCH"
print_success "Backup branch created: $BACKUP_BRANCH"

# Remove files from history
echo ""
print_header "Step 9: Removing files from git history..."
print_info "This may take a while..."

# Build git-filter-repo command
FILTER_REPO_ARGS=("--invert-paths" "--force")
for file_entry in "${SELECTED_FILES[@]}"; do
    IFS='|' read -r file_path rules <<< "$file_entry"
    FILTER_REPO_ARGS+=("--path")
    FILTER_REPO_ARGS+=("$file_path")
done

print_info "Running: git filter-repo ${FILTER_REPO_ARGS[*]}"

# Use system git-filter-repo if available, otherwise use python module
if [[ "$USE_SYSTEM_FILTER_REPO" == true ]]; then
    if ! "$FILTER_REPO_CMD" "${FILTER_REPO_ARGS[@]}"; then
        echo ""
        print_error "ERROR: git-filter-repo failed!"
        print_warning "You can restore from backup branch: $BACKUP_BRANCH"
        exit 1
    fi
else
    if ! "$VENV_PYTHON" -m git_filter_repo "${FILTER_REPO_ARGS[@]}"; then
        echo ""
        print_error "ERROR: git-filter-repo failed!"
        print_warning "You can restore from backup branch: $BACKUP_BRANCH"
        exit 1
    fi
fi

# Clean up
echo ""
print_header "Step 10: Cleaning up git references..."
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Restore remotes (git-filter-repo removes them)
echo ""
print_header "Step 11: Restoring remote configuration..."
for remote in "${!REMOTE_INFO[@]}"; do
    REMOTE_URL="${REMOTE_INFO[$remote]}"
    if git remote add "$remote" "$REMOTE_URL" 2>/dev/null; then
        print_success "Restored remote '$remote': $REMOTE_URL"
    elif git remote set-url "$remote" "$REMOTE_URL" 2>/dev/null; then
        print_success "Updated remote '$remote': $REMOTE_URL"
    else
        print_warning "Could not restore remote '$remote' - you may need to add it manually"
    fi
done

if [[ ${#REMOTE_INFO[@]} -eq 0 ]]; then
    print_info "No remotes were configured before cleanup"
fi

echo ""
print_success "========================================"
print_success "Cleanup completed successfully!"
print_success "========================================"
echo ""

# ============================================================================
# Step 12: Verify with gitleaks
# ============================================================================
if [[ "$SKIP_GITLEAKS" == false ]]; then
    echo ""
    print_header "Step 12: Verifying cleanup with gitleaks..."
    print_info "Running gitleaks scan to verify secrets are removed..."
    echo ""
    
    GITLEAKS_CMD="${GITLEAKS_PATH:-gitleaks}"
    # Use same format as detection scan for consistency
    # Exit code 0 = no secrets, 1 = secrets found
    # Temporarily disable set -e to capture exit code properly
    set +e
    VERIFY_OUTPUT=$("$GITLEAKS_CMD" detect --source . --log-opts="--all --full-history" --no-banner --report-format json --report-path /dev/stdout 2>/dev/null)
    VERIFY_EXIT=$?
    set -e
    
    if [[ "$VERIFY_EXIT" -eq 0 ]] || [[ -z "$VERIFY_OUTPUT" ]] || [[ "$VERIFY_OUTPUT" == "[]" ]]; then
        print_success "✓ No secrets detected by gitleaks!"
    elif [[ "$VERIFY_EXIT" -eq 1 ]]; then
        print_warning "gitleaks still detected some secrets!"
        print_info "This might be expected if:"
        print_info "  - Secrets exist in other files not cleaned"
        print_info "  - gitleaks is detecting false positives"
        echo ""
        print_info "Run 'gitleaks detect --source . --log-opts=\"--all\"' to see what was detected."
    else
        print_warning "gitleaks verification encountered an error (exit code: $VERIFY_EXIT)"
    fi
    echo ""
fi

print_header "Next steps:"
print_info "1. Review the changes: git log --oneline -10"
print_info "2. Verify remote is configured: git remote -v"
echo ""

if [[ ${#REMOTE_INFO[@]} -gt 0 ]]; then
    PRIMARY_REMOTE="origin"
    if [[ -z "${REMOTE_INFO[$PRIMARY_REMOTE]:-}" ]]; then
        PRIMARY_REMOTE="${!REMOTE_INFO[@]}"
        PRIMARY_REMOTE="${PRIMARY_REMOTE%% *}"
    fi
    
    print_warning "⚠️  IMPORTANT: Protected Branch Notice"
    echo ""
    print_info "If your branch is protected in GitLab/GitHub, you have these options:"
    echo ""
    print_info "Option 1: Temporarily unprotect the branch (if you have admin access)"
    print_info "  1. Go to Repository > Settings > Protected Branches"
    print_info "  2. Temporarily unprotect '$CURRENT_BRANCH'"
    print_info "  3. Force push: git push $PRIMARY_REMOTE --force --all"
    print_info "  4. Re-protect the branch after push"
    echo ""
    print_info "Option 2: Use a new branch and merge (recommended for protected branches)"
    print_info "  1. Create a new branch: git checkout -b cleanup-secrets-history"
    print_info "  2. Push new branch: git push $PRIMARY_REMOTE cleanup-secrets-history"
    print_info "  3. Create a Merge Request to replace the protected branch"
    print_info "  4. After merge, delete old branch and rename new one"
    echo ""
    print_info "Option 3: Contact repository admin"
    print_info "  Ask an admin to temporarily allow force push or unprotect the branch"
    echo ""
    print_info "3. Coordinate with your team (they must re-clone after push)"
    print_info "4. Force push (if branch is not protected):"
    echo -e "   ${CYAN}git push $PRIMARY_REMOTE --force --all${NC}"
    echo -e "   ${CYAN}git push $PRIMARY_REMOTE --force --tags${NC}"
else
    print_warning "No remote was configured. You'll need to add one before pushing:"
    print_info "  git remote add origin <your-repo-url>"
    print_info "  git push origin --force --all"
fi

echo ""
print_info "Backup branch: $BACKUP_BRANCH"
echo ""

print_error "╔══════════════════════════════════════════════════════════════════╗"
print_error "║  ⚠️  REMINDER: After force-push, ALL teammates must RE-CLONE!     ║"
print_error "║  Their local copies will be incompatible with the new history.  ║"
print_error "╚══════════════════════════════════════════════════════════════════╝"
echo ""

