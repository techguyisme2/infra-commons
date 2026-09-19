# CLAUDE.md — infra-commons

**This repo is PUBLIC. A push is a publication.** Before writing anything
here, apply the public-grade content policy in README.md: no credentials or
key material, no private repo names or paths, no infrastructure topology
(hostnames, domains, non-documentation IPs — tests use RFC-5737 ranges), no
vault entry names, no personal email addresses. Consumer-specific enforcement
detail (who pins what, protected addresses, allowlists) belongs in the
consumer's own private repo, never here. Commit messages are public too —
write them to the same standard.

Mechanism only; enforcement policy is consumer-owned. No consumer branching
in shared code — consumers configure via parameters from their own shims.

## Dev loop
```bash
python -m pytest -q tests            # 60+ mechanism tests, stdlib+pytest only
ruff check .                         # same rule shape as the consumers' gates
shellcheck hooks/*.sh                # the hook mechanisms; CI runs it too
git config core.hooksPath .githooks  # once per clone — arms the pre-push gate
```
`hooks/*.sh` are bash with a 3.2 floor (`/bin/bash -n` each one; keep the exec
bit) and no skip variables — bypass is consumer policy. `tests/test_hooks.py`
is hermetic (fake gitleaks, stub curl, temp repos; needs git + bash) and also
runs the shim blocks of `hooks/README.md` through a real commit and push, so
edit those blocks as code. `.githooks/` is this repo's own publication gate,
not part of the bundle.
The pre-push hook fail-closes without gitleaks (`brew install gitleaks`) and
also checks the operator-local pattern file
`~/.config/infra-commons/forbidden.grep` (outside the repo on purpose).
Commit identity: repo-local git config pins the noreply address — never
commit here with a personal email.

## Releases
Annotated tags (`vX.Y.Z`). Consumers pin by tag in their own repos and
verify the pinned ref's subtree (`tofu_runner/` at import, `hooks/` in every
hook shim) matches the checkout, so any change under either needs a new tag —
`hooks/README.md` included, it is inside the pinned subtree; doc-only commits
elsewhere don't.
