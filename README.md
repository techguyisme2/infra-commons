# infra-commons

Shared deploy/infra mechanisms, extracted from proven private deployments and
consumed by their repos at pinned refs.

**Mechanism only; enforcement policy is consumer-owned.** Every module here is
generic; each consumer supplies its own configuration (credential key names,
protected addresses, facts allowlists) from a thin shim in its own tree. No
consumer branching lives here, and per-consumer posture (which repo pins which
version, with what enforcement) is recorded in each consumer's own repo — not
here.

## Contents

- **`tofu_runner/`** — deny-by-default OpenTofu driver: verbs exactly
  `init | plan | apply | destroy` (`state pull` / `show` / `output -json`
  unreachable — they print decrypted secrets); gated planfile pipeline
  (`plan -out` → internal `show -json` → pluggable in-process gate →
  `apply <planfile>`; native `tofu destroy` never invoked); entry guards
  (tfvars/auto-tfvars credential scan incl. nested JSON, provisioner +
  `data "external"` refusal, clean env, env-only `TF_VAR_*`); serialized
  applies; default-deny allowlisted 0600 facts cache.
  `tofu_runner/plangate.py` — the destructive-plan gate: default-refuse
  deletes of consumer-listed protected addresses, per-run CLI overrides with
  a stated reason, address-only refusal messages.
- **`hooks/`** — bash mechanisms for a consumer's git hooks, called from thin
  shims in the consumer's own `core.hooksPath` directory: a sha256-pinned
  gitleaks fetcher (`ensure-gitleaks.sh`), a staged-diff scan for pre-commit
  (`gitleaks-staged.sh`), a full-outgoing-range scan for pre-push
  (`gitleaks-outgoing.sh` — every pushed ref, new branches included), a
  pre-commit-framework runner (`precommit-framework.sh`) and a protected-ref
  gate that runs a consumer command only when a listed ref is updated
  (`refgate-run.sh`). Every mechanism fails closed and none has a skip
  variable: bypass switches and the posture level (mandatory / bypassable /
  advisory) are the consumer's, recorded in the consumer's repo.
  Interfaces, a generic shim and the posture-record template:
  [`hooks/README.md`](hooks/README.md).

## Consumption contract

Sibling checkout at a **pinned ref**:

```bash
git clone https://github.com/techguyisme2/infra-commons.git ~/infra-commons
git -C ~/infra-commons checkout <pinned-ref>     # the consumer's recorded pin
```

Python is imported via path (`sys.path` insert of the checkout) from a
consumer shim that records its pin in-repo (e.g. `deploy/infra-commons.pin`)
and fails closed when the pinned ref's package tree doesn't match the
checkout's. Hook mechanisms are called by path from consumer-owned shims
that apply the same rule to `hooks/` before running anything from the checkout
(the check lives in the consumer on purpose — see `hooks/README.md`). Never
vendor wholesale; future HCL snippets are copied with a
`# source: infra-commons@<ref>` provenance line. Rollback for a consumer =
pin the previous ref.

Releases are annotated tags (`v0.1.2`, ...). A consumer upgrades by moving
its pin, running its own contract tests and its verify gate. The pins are
content-based per subtree, so **any change under `tofu_runner/` or `hooks/`
needs a new tag** before a consumer of that subtree can take it; doc-only
commits don't.

## Tests

```bash
python -m pytest -q tests        # mechanism tests (stdlib + pytest only)
shellcheck hooks/*.sh            # the hook mechanisms (also a CI job)
```

The hooks tests are hermetic — temp git repos, a fake gitleaks, a stub `curl`;
they need `git` and `bash`, never the network. One extra test runs only where
a real `gitleaks` is on `PATH`.

Mechanism tests run here in CI. **Consumer tripwires stay in each consumer's
own CI** — they scan the consumer's tree and are meaningless here.

## Public-grade content policy

This repo is public; a push is a publication. What may never land here:
credentials or key material of any kind; private repo names or paths;
infrastructure topology (hostnames, domains, non-documentation IP addresses
— tests use RFC-5737 ranges); vault entry names; personal email addresses.
Consumer-specific enforcement detail belongs in the consumer's own repo.

Enforced mechanically, not by memory:

```bash
git config core.hooksPath .githooks   # once per clone — arms the pre-push gate
```

`.githooks/pre-push` runs a full gitleaks scan (fail-closed: refuses to push
if gitleaks isn't installed) plus an optional operator-local pattern check
(`~/.config/infra-commons/forbidden.grep` — kept outside the repo on purpose:
the forbidden identifiers must not appear here, even inside a rule). CI runs
the same gitleaks scan as an after-the-fact tripwire. Commit identity is
pinned to a noreply address via repo-local git config.
