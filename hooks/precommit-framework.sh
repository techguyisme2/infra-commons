#!/usr/bin/env bash
# ==============================================================================
# Script: precommit-framework.sh
# Purpose: pre-commit mechanism — run the pre-commit framework over the STAGED
#          files with the calling repo's config. For repos that route hooks
#          through core.hooksPath, where `pre-commit install` refuses to write
#          into .git/hooks. Fails closed: no config, no framework binary or an
#          unknown option is a refusal, never "lint skipped". There is no skip
#          variable here — the framework's own SKIP is removed from its
#          environment; a bypass switch is consumer policy and lives in the
#          consumer's shim.
#
# Author: infra-commons
# Date: 2026-09-19
# Version: 1.0.0
#
# Usage: precommit-framework.sh --config <path> [--bin <candidate>]...
#                               [--install-hint <text>]...
#
# Options:
#   --config <path>        the framework's config file (required)
#   --bin <candidate>      a path or a command name, tried in the order given;
#                          the first one `command -v` resolves is used
#                          (repeatable; default: the single candidate
#                          "pre-commit" from PATH)
#   --install-hint <text>  extra line printed when NO candidate resolves
#                          (repeatable), e.g. the consumer's install command
#   -h, --help             Show usage
#
# Exit codes:
#   0  the framework passed
#   1  the framework reported failures (its own status is printed)
#   2  usage or configuration error (unknown option, no --config, config file
#      missing, not inside a git work tree)
#   3  the check could not run (no candidate binary found)
#
# Examples:
#   hooks/precommit-framework.sh --config "$ROOT/.pre-commit-config.yaml" \
#       --bin "$ROOT/.venv/bin/pre-commit" --bin pre-commit
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME
readonly USAGE="usage: precommit-framework.sh --config <path> [--bin <candidate>]... [--install-hint <text>]..."

CONFIG=""
CANDIDATES=()
INSTALL_HINTS=()

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

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config|--bin|--install-hint)
                if [[ $# -lt 2 || -z "$2" ]]; then
                    error_exit "$1 needs a value ($USAGE)" 2
                fi
                case "$1" in
                    --config)       CONFIG="$2" ;;
                    --bin)          CANDIDATES[${#CANDIDATES[@]}]="$2" ;;
                    --install-hint) INSTALL_HINTS[${#INSTALL_HINTS[@]}]="$2" ;;
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
        error_exit "pre-commit config not found: $CONFIG" 2
    fi
    # The framework runs from the repo root; keep a relative path meaningful.
    case "$CONFIG" in
        /*) ;;
        *)  CONFIG="$PWD/$CONFIG" ;;
    esac
    if [[ "${#CANDIDATES[@]}" -eq 0 ]]; then
        CANDIDATES[0]="pre-commit"
    fi
}

# Print the first candidate that resolves; return 1 when none does.
find_framework() {
    local i=0
    while [[ "$i" -lt "${#CANDIDATES[@]}" ]]; do
        if command -v "${CANDIDATES[$i]}" >/dev/null 2>&1; then
            echo "${CANDIDATES[$i]}"
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

main() {
    parse_arguments "$@"

    local repo_root bin
    if ! repo_root=$(git rev-parse --show-toplevel 2>/dev/null); then
        error_exit "not inside a git work tree" 2
    fi
    if ! bin=$(find_framework); then
        log_error "the pre-commit framework was not found — refusing to pass without it"
        local i=0
        while [[ "$i" -lt "${#INSTALL_HINTS[@]}" ]]; do
            echo "[$SCRIPT_NAME] ${INSTALL_HINTS[$i]}" >&2
            i=$((i + 1))
        done
        exit 3
    fi

    # `run` with no file list = the staged files only; the framework stashes
    # unstaged edits for the duration, so the gate sees what the commit will.
    cd "$repo_root"
    # The framework honours its own SKIP=<hook id>,... from the environment;
    # left in place it is a skip variable no shim controls.
    unset SKIP
    local status=0
    "$bin" run --config "$CONFIG" || status=$?
    if [[ "$status" -ne 0 ]]; then
        log_error "the pre-commit framework failed (exit $status)"
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
