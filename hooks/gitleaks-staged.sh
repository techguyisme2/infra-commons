#!/usr/bin/env bash
# ==============================================================================
# Script: gitleaks-staged.sh
# Purpose: pre-commit mechanism — scan the STAGED diff with the pinned gitleaks
#          and block the commit on a finding. Fails closed: no config, no
#          scanner, an unknown option or a scanner that logged an error and
#          still exited 0 is a refusal, never "scan skipped". There is no skip
#          variable here; a bypass switch is consumer policy and lives in the
#          consumer's shim.
#
# Author: infra-commons
# Date: 2026-09-19
# Version: 1.0.0
#
# Usage: gitleaks-staged.sh --config <path> [--hint <text>]... [--tools-root <dir>]
#
# Options:
#   --config <path>     gitleaks config of the calling repo (required)
#   --hint <text>       extra line printed after a finding (repeatable), e.g.
#                       where the consumer keeps its triage rules
#   --tools-root <dir>  passed to ensure-gitleaks.sh (default: <repo>/.tools)
#   -h, --help          Show usage
#
# Exit codes:
#   0  staged diff is clean
#   1  gitleaks reported a finding
#   2  usage or configuration error (unknown option, no --config, config file
#      missing, not inside a git work tree)
#   3  the scan could not run (the pinned gitleaks is unavailable, it exited
#      0 with an ERR line in its own log — its git child failed — or it did
#      not complete: a fatal error of its own, or death by signal. Never
#      reported as a finding.)
#
# Examples:
#   hooks/gitleaks-staged.sh --config "$ROOT/.gitleaks.toml"
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_NAME SCRIPT_DIR
readonly USAGE="usage: gitleaks-staged.sh --config <path> [--hint <text>]... [--tools-root <dir>]"

# The scanner's status for "a finding", set with --exit-code. Its default, 1, is
# ALSO what it exits with on a fatal error (an unparsable config, say), so with
# the default a crash would read as "a secret was found". Anything that is
# neither 0 nor this value — a fatal error, death by signal — did not complete.
readonly LEAK_STATUS=42

CONFIG=""
TOOLS_ROOT=""
HINTS=()
SCAN_LOG=""

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
    if [[ -n "$SCAN_LOG" && -f "$SCAN_LOG" ]]; then
        rm -f "$SCAN_LOG"
    fi
    return "$exit_code"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config|--hint|--tools-root)
                if [[ $# -lt 2 || -z "$2" ]]; then
                    error_exit "$1 needs a value ($USAGE)" 2
                fi
                case "$1" in
                    --config)     CONFIG="$2" ;;
                    --hint)       HINTS[${#HINTS[@]}]="$2" ;;
                    --tools-root) TOOLS_ROOT="$2" ;;
                esac
                shift 2
                ;;
            -h|--help)
                echo "$USAGE"
                exit 0
                ;;
            *)
                error_exit "unknown argument: $1 ($USAGE)" 2
                ;;
        esac
    done
    if [[ -z "$CONFIG" ]]; then
        error_exit "--config is required ($USAGE)" 2
    fi
    if [[ ! -f "$CONFIG" ]]; then
        error_exit "gitleaks config not found: $CONFIG" 2
    fi
}

# Print the pinned binary's path, or fail: a gate that cannot scan must not pass.
locate_gitleaks() {
    local bin
    if [[ -n "$TOOLS_ROOT" ]]; then
        bin=$("$SCRIPT_DIR/ensure-gitleaks.sh" --tools-root "$TOOLS_ROOT") || return 1
    else
        bin=$("$SCRIPT_DIR/ensure-gitleaks.sh") || return 1
    fi
    echo "$bin"
}

print_hints() {
    local i=0
    while [[ "$i" -lt "${#HINTS[@]}" ]]; do
        echo "[$SCRIPT_NAME] ${HINTS[$i]}" >&2
        i=$((i + 1))
    done
}

# The scanner reads the output of a git child and takes its OWN exit 0 for
# "scanned clean" even when it could not read that output: anything on the
# child's stderr (GIT_TRACE*) stops its reader early, and a colored diff does
# not parse at all. Pin what the child sees. GIT_CONFIG_PARAMETERS is the one
# config layer that outranks `git -c` and every config file; appending keeps
# the caller's other settings, and the last entry wins.
pin_git_child_environment() {
    local name
    for name in "${!GIT_TRACE@}"; do
        unset "$name"
    done
    export GIT_CONFIG_PARAMETERS="${GIT_CONFIG_PARAMETERS:+$GIT_CONFIG_PARAMETERS }'color.ui=false' 'color.diff=false'"
}

# Run the scanner ("$@") with its log captured, then replayed. Returns its
# status — unless it exited 0 with an ERR line in that log: the git child
# failed for a reason the pinning above cannot enumerate, little or nothing
# was read, and "no leaks found" is not a result.
run_scanner() {
    local status=0
    "$@" 2> "$SCAN_LOG" || status=$?
    cat "$SCAN_LOG" >&2
    if [[ "$status" -eq 0 ]]; then
        if grep -Eq '(^|[[:space:]])ERR([[:space:]]|$)' "$SCAN_LOG"; then
            error_exit "the scanner logged an error and still exited 0 — refusing to pass without a full scan" 3
        fi
        return 0
    fi
    if [[ "$status" -ne "$LEAK_STATUS" ]]; then
        error_exit "the scanner did not complete (exit ${status}: a fatal error, or it was killed) — that is not a finding; refusing to pass without a full scan" 3
    fi
    return 1
}

main() {
    trap cleanup EXIT
    parse_arguments "$@"

    local repo_root gitleaks_bin
    if ! repo_root=$(git rev-parse --show-toplevel 2>/dev/null); then
        error_exit "not inside a git work tree" 2
    fi
    if ! gitleaks_bin=$(locate_gitleaks); then
        error_exit "the pinned gitleaks is unavailable — refusing to pass without a scan" 3
    fi

    pin_git_child_environment
    SCAN_LOG=$(mktemp) || error_exit "cannot create a temporary file for the scanner's log" 3
    # --no-color: the log is matched above, and it is colored even into a file
    if ! run_scanner "$gitleaks_bin" git --pre-commit --staged --redact --no-banner --no-color \
            --exit-code "$LEAK_STATUS" --config "$CONFIG" "$repo_root"; then
        {
            echo ""
            echo "[$SCRIPT_NAME] gitleaks found a potential secret in the staged diff."
            echo "[$SCRIPT_NAME] Real secret -> unstage, rotate, rewrite. False positive ->"
            echo "[$SCRIPT_NAME] a narrowly-shaped allowlist entry with a justification."
        } >&2
        print_hints
        exit 1
    fi
    return 0
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
