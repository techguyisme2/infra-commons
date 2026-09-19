#!/usr/bin/env bash
# ==============================================================================
# Script: refgate-run.sh
# Purpose: pre-push mechanism — run a consumer-supplied command ONLY when the
#          push updates one of the given protected refs; exit with that
#          command's status. For gates too expensive to run on every push
#          (a test suite before a protected branch moves). Fails closed: no
#          --ref, no command, an unparsable stdin line or an unknown option is
#          a refusal. There is no skip variable here; a bypass switch is
#          consumer policy and lives in the consumer's shim (or its command).
#
# Author: infra-commons
# Date: 2026-09-19
# Version: 1.0.0
#
# Usage: refgate-run.sh --ref <full ref name> [--ref <full ref name>]... -- <command> [args...]
#
# Stdin: git's pre-push lines, one per pushed ref:
#          <local ref> SP <local sha> SP <remote ref> SP <remote sha>
#        Blank lines are ignored. A line counts when its REMOTE ref equals a
#        --ref exactly (no patterns) and it is not a deletion (local sha all
#        zeros). All of stdin is read first; the command runs at most ONCE,
#        from the current directory, with the caller's environment.
#
# Options:
#   --ref <name>   protected ref on the remote, e.g. refs/heads/main (repeatable,
#                  at least one)
#   --             end of options; everything after it is the command
#   -h, --help     Show usage
#
# Exit codes:
#   0    no protected ref is updated (command NOT run), or the command passed
#   2    usage or stdin error — raised BEFORE the command would run
#   any  otherwise the command's own exit status, unchanged
#
# Examples:
#   printf '%s\n' "$PUSH_LINES" | hooks/refgate-run.sh --ref refs/heads/main -- "$ROOT/scripts/test-gate.sh"
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME
readonly USAGE="usage: refgate-run.sh --ref <full ref name> [--ref ...] -- <command> [args...]  < pre-push lines"
# Object names are 40 hex digits (sha1) or 64 (sha256); all zeros = "no object".
readonly SHA_RE='^([0-9a-f]{40}|[0-9a-f]{64})$'
readonly ZERO_RE='^0+$'

REFS=()
COMMAND=()
PROTECTED_HIT=0

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
            --ref)
                if [[ $# -lt 2 || -z "$2" ]]; then
                    error_exit "--ref needs a ref name ($USAGE)" 2
                fi
                REFS[${#REFS[@]}]="$2"
                shift 2
                ;;
            --)
                shift
                while [[ $# -gt 0 ]]; do
                    COMMAND[${#COMMAND[@]}]="$1"
                    shift
                done
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
    if [[ "${#REFS[@]}" -eq 0 ]]; then
        error_exit "at least one --ref is required ($USAGE)" 2
    fi
    if [[ "${#COMMAND[@]}" -eq 0 ]]; then
        error_exit "no command after -- ($USAGE)" 2
    fi
}

is_protected() {
    local ref="$1"
    local i=0
    while [[ "$i" -lt "${#REFS[@]}" ]]; do
        if [[ "${REFS[$i]}" == "$ref" ]]; then
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

# Read ALL of stdin; set PROTECTED_HIT=1 when a protected ref is updated. A line
# that cannot be parsed refuses the push instead of silently dropping a ref.
read_push_lines() {
    local line local_sha remote_ref remote_sha extra
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" ]]; then
            continue
        fi
        # stdin fields are space-separated — override the script-wide IFS
        IFS=' ' read -r _ local_sha remote_ref remote_sha extra <<< "$line"
        if [[ -z "$remote_sha" || -n "$extra" ]] \
                || ! [[ "$local_sha" =~ $SHA_RE && "$remote_sha" =~ $SHA_RE ]]; then
            error_exit "unparsable pre-push line (want: <local ref> <local sha> <remote ref> <remote sha>): $line" 2
        fi
        if [[ "$local_sha" =~ $ZERO_RE ]]; then
            continue  # ref deletion — nothing to gate
        fi
        if is_protected "$remote_ref"; then
            PROTECTED_HIT=1
        fi
    done
}

main() {
    parse_arguments "$@"

    read_push_lines
    if [[ "$PROTECTED_HIT" -ne 1 ]]; then
        return 0
    fi

    local status=0
    "${COMMAND[@]}" || status=$?
    exit "$status"
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
