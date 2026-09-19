#!/usr/bin/env bash
# ==============================================================================
# Script: ensure-gitleaks.sh
# Purpose: Ensure the pinned gitleaks binary exists locally; print its path.
#          Downloads the release tarball and verifies its sha256 against the
#          pins below BEFORE extraction, then installs the one binary to
#          <tools-root>/gitleaks/<version>/gitleaks.
#
# Author: infra-commons
# Date: 2026-09-19
# Version: 1.0.0
#
# Usage: ensure-gitleaks.sh [--tools-root <dir>]
#
# Options:
#   --tools-root <dir>  Install root. Default: <calling repo's root>/.tools
#                       (`git rev-parse --show-toplevel` from the current
#                       directory). The consumer keeps it ignored by git.
#   -h, --help          Show usage
#
# Exit codes:
#   0  binary present; its path is the only line on stdout
#   1  usage error, or no --tools-root and not inside a git work tree
#   2  unsupported platform (no pin for it)
#   3  checksum mismatch (nothing is installed)
#   4  download failed
#   5  extraction or install failed
#
# Examples:
#   GITLEAKS_BIN="$(hooks/ensure-gitleaks.sh)"
#   GITLEAKS_BIN="$(hooks/ensure-gitleaks.sh --tools-root "$HOME/.cache/tools")"
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME
readonly USAGE="usage: ensure-gitleaks.sh [--tools-root <dir>]"

# Pinned version + per-platform sha256 of the release tarballs. Bumping the
# version REQUIRES re-pinning every checksum from the release's checksums file.
# The pins live here on purpose: a consumer freezes them by pinning the ref of
# this repository that it consumes. There is no override.
readonly GITLEAKS_VERSION="8.30.1"
readonly SHA256_DARWIN_ARM64="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
readonly SHA256_DARWIN_X64="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
readonly SHA256_LINUX_X64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
readonly SHA256_LINUX_ARM64="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"

TOOLS_ROOT=""
TMP_DIR=""

# ==============================================================================
# FUNCTIONS
# ==============================================================================

log_error() {
    echo "[$SCRIPT_NAME] ERROR: $*" >&2
}

error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    log_error "$message"
    exit "$exit_code"
}

cleanup() {
    local exit_code=$?
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    return "$exit_code"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tools-root)
                if [[ $# -lt 2 || -z "$2" ]]; then
                    error_exit "--tools-root needs a directory ($USAGE)" 1
                fi
                TOOLS_ROOT="$2"
                shift 2
                ;;
            -h|--help)
                echo "$USAGE"
                exit 0
                ;;
            *)
                error_exit "unknown argument: $1 ($USAGE)" 1
                ;;
        esac
    done
}

# Resolve platform to (asset suffix, pinned sha256)
platform_asset() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)
    case "$os/$arch" in
        Darwin/arm64)          echo "darwin_arm64 $SHA256_DARWIN_ARM64" ;;
        Darwin/x86_64)         echo "darwin_x64 $SHA256_DARWIN_X64" ;;
        Linux/x86_64)          echo "linux_x64 $SHA256_LINUX_X64" ;;
        Linux/aarch64|Linux/arm64) echo "linux_arm64 $SHA256_LINUX_ARM64" ;;
        *) error_exit "Unsupported platform: $os/$arch (add a pin for it)" 2 ;;
    esac
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    fi
    if [[ "$actual" != "$expected" ]]; then
        error_exit "Checksum mismatch for $(basename "$file"): expected $expected got $actual" 3
    fi
}

main() {
    trap cleanup EXIT
    trap 'error_exit "Interrupted" 130' INT TERM

    parse_arguments "$@"

    if [[ -z "$TOOLS_ROOT" ]]; then
        local repo_root
        if ! repo_root=$(git rev-parse --show-toplevel 2>/dev/null); then
            error_exit "not inside a git work tree and no --tools-root given" 1
        fi
        TOOLS_ROOT="$repo_root/.tools"
    fi

    local bin_dir="$TOOLS_ROOT/gitleaks/$GITLEAKS_VERSION"
    local bin="$bin_dir/gitleaks"

    if [[ -x "$bin" ]]; then
        echo "$bin"
        return 0
    fi

    # platform_asset runs in a command substitution: its error_exit leaves the
    # subshell only, so the status is carried out explicitly.
    local asset sha suffix
    asset=$(platform_asset) || exit $?
    suffix=${asset%% *}
    sha=${asset##* }

    local tarball="gitleaks_${GITLEAKS_VERSION}_${suffix}.tar.gz"
    local url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${tarball}"

    TMP_DIR=$(mktemp -d)
    echo "[$SCRIPT_NAME] downloading $tarball ..." >&2
    curl -fsSL -o "$TMP_DIR/$tarball" "$url" \
        || error_exit "Download failed: $url" 4
    verify_sha256 "$TMP_DIR/$tarball" "$sha"
    tar -xzf "$TMP_DIR/$tarball" -C "$TMP_DIR" gitleaks \
        || error_exit "Extraction failed: $tarball" 5

    mkdir -p "$bin_dir" || error_exit "Cannot create $bin_dir" 5
    # cat-into-place (not mv) so an existing path keeps its permissions
    cat "$TMP_DIR/gitleaks" > "$bin" || error_exit "Cannot write $bin" 5
    chmod 0755 "$bin"

    echo "$bin"
    return 0
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
