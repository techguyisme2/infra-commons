# hooks/ — git hook mechanisms

Bash mechanisms for a consumer's git hooks. **Mechanism only; enforcement
policy is consumer-owned.** A consumer points `core.hooksPath` at a directory
of thin shims **in its own repo**; each shim verifies this checkout, then calls
the scripts here with the consumer's configuration. Nothing here knows who the
consumers are.

Three rules hold for every script:

- **Configuration comes from the shim** — arguments (and the caller's
  environment for the command `refgate-run.sh` runs). No config file is read
  from this repository, and there is no consumer branching.
- **No skip variable.** A bypass switch is policy, so it lives in the
  consumer's shim, never here. That covers the wrapped tools too: the
  pre-commit framework's own `SKIP` is removed from its environment.
- **Fail closed.** A failed download, a missing config, an unparsable stdin
  line, an unknown option or a scanner that logged an error and still exited 0
  is a non-zero exit — never "scan skipped".

All scripts run on bash 3.2 and newer, resolve the calling repository with
`git rev-parse --show-toplevel` from the current directory (git runs hooks
from the work tree's root) and write their own messages to stderr. Pass
absolute paths.

## Interfaces

### `ensure-gitleaks.sh [--tools-root <dir>]`

Prints the path of the pinned gitleaks binary, downloading it first when it is
not there yet. The version and the per-platform sha256 pins live in the
script; **a consumer freezes them by pinning the ref of this repository**.
There is no override, by argument or by environment.

| | |
|---|---|
| `--tools-root <dir>` | install root; default `<calling repo's root>/.tools` — the consumer ignores it in git |
| install path | `<tools-root>/gitleaks/<GITLEAKS_VERSION>/gitleaks`, mode 0755 |
| stdout | the binary's path, one line; progress goes to stderr |
| network | only when the binary is absent: one `curl` of the release tarball, sha256 verified **before** extraction, only the `gitleaks` member extracted |
| exit | `0` ok · `1` usage, or no `--tools-root` outside a git work tree · `2` unsupported platform · `3` checksum mismatch (nothing installed) · `4` download failed · `5` extraction/install failed |

An executable already at the install path is used as is (no download). A test
harness pre-places its fake there; the version is the script's
`readonly GITLEAKS_VERSION="x.y.z"` line. The default root is per work tree —
a linked worktree fetches its own copy unless the shim passes a shared
`--tools-root`.

### `gitleaks-staged.sh --config <path> [--hint <text>]... [--tools-root <dir>]`

pre-commit: scans the **staged diff**
(`gitleaks git --pre-commit --staged --redact --no-banner --no-color --config <path> <repo root>`).

| | |
|---|---|
| `--config <path>` | required; the consumer's gitleaks config (must exist) |
| `--hint <text>` | repeatable; printed after a finding, e.g. where the consumer keeps its triage rules |
| `--tools-root <dir>` | passed to `ensure-gitleaks.sh` |
| stdin | not read |
| exit | `0` clean · `1` finding, and ONLY a finding · `2` usage/config error · `3` the scan could not run: gitleaks unavailable, it exited 0 with an `ERR` line in its own log, or it did not complete (its own fatal error, or killed) |

**`1` means a finding and nothing else.** gitleaks exits `1` for a finding by default — and `1`
for its own fatal error (an unparsable config, say) — so both scans ask it for a distinctive
finding status (`--exit-code`). A consumer may therefore wire exit `1` to its triage or rotation
procedure: a scanner that crashed, or was killed, is exit `3` and never reads as a secret found.

Both scans **pin what the scanner's git child sees**, because gitleaks takes
its own exit 0 for "scanned clean" even when it could not read that child:
any output on the child's stderr stops its reader early, and a colored diff
does not parse at all. So every `GIT_TRACE*` variable is unset and
`color.ui=false` / `color.diff=false` are appended to `GIT_CONFIG_PARAMETERS`
(the one config layer that outranks `git -c` and every config file; the
caller's other entries are kept). For the causes that cannot be enumerated —
a `trace2.*` config target, a git warning, a fatal git error — the scanner's
log is captured and replayed, and exit 0 with an `ERR` line in it is exit `3`,
never a pass.

### `gitleaks-outgoing.sh --config <path> [--hint <text>]... [--tools-root <dir>]`

pre-push: scans the **full outgoing range of every pushed ref**, so a commit
made with the commit hook bypassed is still caught before it leaves.

| | |
|---|---|
| options | as `gitleaks-staged.sh` |
| stdin | git's pre-push lines: `<local ref> <local sha> <remote ref> <remote sha>`; blank lines ignored |
| deletion (local sha all zeros) | skipped — nothing is outgoing |
| new remote ref (remote sha all zeros) | `--log-opts "<local sha> --not --remotes"` |
| update | `--log-opts "<remote sha>..<local sha>"` |
| several refs | all of stdin is parsed first, then **every** range is scanned; one failing ref fails the push even when a later ref is clean |
| nothing outgoing | exit `0` without needing gitleaks |
| exit | `0` clean · `1` finding in at least one range · `2` usage/config error or an unparsable line (nothing is scanned) · `3` the scan could not run: gitleaks unavailable, an update's remote sha is not in this clone (`git fetch`, push again), gitleaks exited 0 with an `ERR` line in its own log (see above), or it did not complete (its own fatal error, or killed) |

### `precommit-framework.sh --config <path> [--bin <candidate>]... [--install-hint <text>]...`

pre-commit: runs the [pre-commit framework](https://pre-commit.com) over the
staged files (`<bin> run --config <path>` from the repo root) — for repos that
route hooks through `core.hooksPath`, where `pre-commit install` refuses to
write into `.git/hooks`. Which hooks run is the consumer's config file — and
only that: the framework's own `SKIP=<hook id>,...` variable is removed from
its environment, or it would be a skip switch no shim controls.

| | |
|---|---|
| `--config <path>` | required; the framework's config (must exist) |
| `--bin <candidate>` | repeatable, tried in order; a path or a command name; the first one `command -v` resolves wins. Default: the single candidate `pre-commit` from `PATH` |
| `--install-hint <text>` | repeatable; printed when **no** candidate resolves |
| stdin | not read |
| exit | `0` passed · `1` the framework failed (its status is printed) · `2` usage/config error · `3` no candidate found |

### `refgate-run.sh --ref <full ref name> [--ref ...] -- <command> [args...]`

pre-push: runs the command **only when the push updates a protected ref** —
for gates too expensive for every push (a test suite before a protected branch
moves). What the command does is the consumer's policy.

| | |
|---|---|
| `--ref <name>` | repeatable, at least one; compared **exactly** with the line's *remote* ref (`refs/heads/main`), no patterns |
| `-- <command> [args...]` | required; run at most **once**, from the current directory, with the caller's environment |
| stdin | git's pre-push lines as above; blank lines ignored; all of it is read before the command runs |
| deletion of a protected ref | does not count |
| exit | `0` no protected ref updated (command **not** run) · `2` usage error or an unparsable line (raised before the command would run) · otherwise **the command's own status** |

## What these hooks do not defend against

They are a gate for the person at the keyboard, not a sandbox around them. Anyone who can write
the consumer's hooks directory, its tools root, or put a directory ahead on `PATH` can already
replace a shim, the scanner, or `git` itself — so the mechanisms do not try to out-verify that
person. Concretely: `ensure-gitleaks.sh` verifies what it **downloads** (sha256 before extraction)
and does not re-attest a binary that is already installed; `curl`, `tar` and the sha256 tool are
taken from `PATH`. A local gate can also always be skipped by whoever runs `git` (`--no-verify`),
which is why a finding that matters needs a server-side or CI check as well.

## Consuming the hooks

1. Clone this repository as a sibling checkout and record the ref you consume
   on line 1 of a pin file in your own repo.
2. Keep a hooks directory in your repo (`git config core.hooksPath <dir>`, once
   per clone) holding one thin shim per hook.
3. Every shim **verifies the content pin before it runs anything from the
   checkout**: the pinned ref's `hooks/` tree must equal the checkout's `HEAD`
   `hooks/` tree, and nothing under `hooks/` may be modified or untracked
   (ask `git status` with `--untracked-files=all`: a user's
   `status.showUntrackedFiles=no` would otherwise hide the untracked half).
   `HEAD` itself may be newer — doc commits and other subtrees move it — but
   any change under `hooks/` needs a new tag and a deliberate pin move in the
   consumer, so an update here can never silently change what a consumer
   enforces.
4. The pin check is **consumer-owned on purpose**: a checker shipped inside
   the checkout it is meant to verify proves nothing. A few duplicated lines
   per consumer are the price.
5. Ignore the tools root (`.tools/`) in the consumer's `.gitignore`.

Two things every shim author trips over:

- **Git exports repo-local variables to hooks** — `GIT_INDEX_FILE` always for
  pre-commit (an absolute path to a *temporary* index under `git commit -a`),
  `GIT_DIR` in linked worktrees. Left in place, `git -C <checkout> status`
  reads the *consumer's* index against the *checkout's* work tree. Run the pin
  check with `git rev-parse --local-env-vars` unset, as below. The mechanisms
  themselves need those variables and must keep them.
- **pre-push stdin can be read once.** Capture it, then feed each mechanism
  its own copy. `printf '%s\n' "$lines"` of an empty capture yields one blank
  line; the mechanisms ignore blank lines for exactly that reason.

### A generic shim

Every shim starts with the same preamble (locate, pin-check, fail closed):

<!-- shim:preamble -->
```bash
#!/usr/bin/env bash
# <hook> shim — consumer-owned. Posture: <level>; bypass: <none | how>.
set -euo pipefail
IFS=$'\n\t'

ROOT=$(git rev-parse --show-toplevel)
COMMONS="$HOME/infra-commons"
PIN_FILE="$ROOT/infra-commons.pin"      # line 1 = the pinned ref

refuse() {
    echo "hook shim: REFUSING — $*" >&2
    exit 1
}

# Consumer-owned content pin. A subshell with git's repo-local variables
# unset: they describe THIS repository and must not reach the other one.
verify_commons() (
    # shellcheck disable=SC2046  # one variable name per line, split on purpose
    unset $(git rev-parse --local-env-vars)
    [[ -d "$COMMONS/hooks" ]] || refuse "no commons checkout at $COMMONS"
    pin=$(awk 'NR == 1 { print $1 }' "$PIN_FILE") || refuse "cannot read $PIN_FILE"
    [[ -n "$pin" ]] || refuse "no ref on line 1 of $PIN_FILE"
    want=$(git -C "$COMMONS" rev-parse --verify --quiet "${pin}^{commit}") \
        || refuse "pinned ref $pin not found in $COMMONS (fetch its tags)"
    git -C "$COMMONS" diff --quiet "$want" HEAD -- hooks \
        || refuse "$COMMONS/hooks differs from the pinned ref $pin"
    dirty=$(git -C "$COMMONS" status --porcelain --untracked-files=all -- hooks) \
        || refuse "cannot read the state of $COMMONS"
    [[ -z "$dirty" ]] || refuse "$COMMONS/hooks has modified or untracked files"
)
verify_commons
```

Then the hook's own lines. `pre-commit`:

<!-- shim:pre-commit -->
```bash
"$COMMONS/hooks/gitleaks-staged.sh" --config "$ROOT/.gitleaks.toml" \
    --hint "Triage rules: <where this repo keeps them>"
```

`pre-push`:

<!-- shim:pre-push -->
```bash
# git feeds the pushed refs on stdin ONCE; every mechanism gets its own copy.
PUSH_LINES=$(cat)
printf '%s\n' "$PUSH_LINES" | "$COMMONS/hooks/gitleaks-outgoing.sh" \
    --config "$ROOT/.gitleaks.toml"
printf '%s\n' "$PUSH_LINES" | "$COMMONS/hooks/refgate-run.sh" \
    --ref refs/heads/main -- "$ROOT/scripts/test-gate.sh"
```

With `set -e` and `pipefail` the first failing mechanism ends the hook with
its status. A consumer whose posture allows a bypass wraps the call in its
own switch — `if [[ "${MY_REPO_SKIP_SCAN:-}" != "1" ]]; then ...; fi` — and
documents it in the shim's header and its posture record. `tests/test_hooks.py`
runs exactly these three blocks through a real `git commit` and `git push`.

## Posture levels

The same mechanisms serve different postures. The level is a property of the
**consumer's shims and rules**, not of anything here:

| Level | Meaning |
|---|---|
| **mandatory** | Armed in every clone. The shims carry no bypass switch and `--no-verify` is against the repo's rules; the outgoing-range scan is the backstop for a commit that skipped the commit hook. A server-side or CI re-run is the tripwire. |
| **bypassable** | Blocks by default; the shims document a deliberate bypass (`--no-verify`, a skip variable the shim defines). CI re-runs the same checks after the fact. |
| **advisory** | Reports and never blocks: the shim prints the mechanism's result and exits 0. For trial periods and noisy new rules. |

Per-consumer posture is **not** recorded in this repository. Each consumer
keeps a dated record in its own repo — next to its pin is a good place:

```text
# hooks posture — <YYYY-MM-DD>, commons ref <tag> (hooks/ content-pinned)
#   pre-commit : <mechanisms called>        level: <mandatory|bypassable|advisory>
#                bypass: <none | the documented switch>
#   pre-push   : <mechanisms called>        level: <...>
#                bypass: <none | the documented switch>
#   protected refs for refgate-run : <refs>   command: <path in this repo>
#   gitleaks config: <path>   tools root: <path, git-ignored>
#   baseline scan: <date, scope, how hits were dispositioned>
#   CI tripwire: <job that re-runs the checks>
#   next review: <date>
```
