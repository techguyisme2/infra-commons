<!-- source: infra-commons templates/cutover-runbook.md — copy, fill, keep the executed record at the bottom -->
# `<Change>` — one sitting, hardware key in hand

One paragraph: what this one-time procedure moves, rotates or retires, and
what it must never do (names only in this file; a value never appears on a
command line, in a file the repo can see, or in a transcript). Contract:
`<key-inventory.md>`. Decisions: `<date>` (`<the decisions, one clause each>`).

**Budget:** every `secret-put` and every wrapper run is one touch. About
`<N>` touches and `<M>` minutes. Do not start with less than an hour.

```bash
export V=<broker socket>              # used below
export <FACTOR VARIABLE>=<hardware factor>   # the CLI's default factor is refused by this broker
<broker status command>               # must say live; else start it attended
<hardware key present check>          # key #1 present, and ONLY key #1
```

A touch that comes too late fails the ceremony (`<the two error strings>`):
nothing is stored or fetched, just re-run the line. A line that emptied the
clipboard has already done so by then — re-copy first.

## 0. Preconditions

- The change is merged (`<PR>`); from that moment deploys need the new path, so
  steps 1–`<k>` happen right after the merge.
- Clipboard history disabled; the browser copies below are the only clipboard
  moments and go through the copy tool, never a raw paste.
- Every worktree clean; the second role fast-forwarded to the same commit.

## 1. `<First step that changes nothing in use>`

Steps are numbered; each line that costs a touch says so in a trailing
comment (`# 1 touch`). Group steps so that **everything before the gate can be
abandoned** with nothing in use having changed.

## 2. Intake: existing values, program to program (`<n>` touches)

`<copy tool> | <broker put> NAME --stdin --socket $V      # 1 touch` per name, or one
batched put for several names (a mid-batch failure leaves the store partially
written — re-run; puts are idempotent upserts).

## 3. Rotate what the decisions said to rotate

Mint in the provider console, `secret-put` the new value, delete the old one in
the console — in that order, so a failed put leaves the old credential working.

## 4. Root passwords / break-glass values

**Gate:** every name present, escrow proven:

```bash
<broker escrow drill> NAME1 NAME2 ... --socket $V
# must print: <READY token>  — do not continue without it
```

## 5. Retire the files, migrate the states — the rebuildable role FIRST

In **each** worktree (`<role B path>`, then `<role A path>`): the steps that
delete plaintext, each followed by the wrapper verb that proves the new path
works (`make plan` → "No changes."; `make verify` → all passed).

## 6. First deploy on the new path: role A

`make deploy && make verify` (one touch) — the counts go in the record below.

## 7. Enforce (a follow-up commit)

Whatever fallback the migration needed (an "unencrypted" method, a warning
instead of a refusal) is removed in a separate commit once step 6 is proven.

## 8. The dev loop and the residue

What changes for daily work (one extra touch per sitting, a renamed file), and
the local residue to clean (caches, indexes, transcripts).

## Rollback

Before step `<5>` nothing on disk has changed: revert the merge and deploy as
before. After step `<5>` the plaintext files are gone by design: a rollback
means reverting the merge AND rebuilding the env file by hand from the vault —
which is exactly the exposure this change removes. Prefer fixing forward.

## Verified at the sitting (`<date>`)

Steps `<1–6>` ran as written (with `<any deviation, named>`): `<what was
proven, with counts — "verify 18/18 including the certificate dry run on the
rolled token">`. Still untested: `<the honest list>`.

## Rollout record — EXECUTED `<date>`

The in-repo custody record. One paragraph: which names were vaulted, that the
escrow drill printed its token BEFORE any file was touched, the sequence each
worktree ran (quarantine → agent-path verify → deploy + verify, with counts),
and that the quarantined files were then shredded. Preflight state afterwards:
what no longer exists on the operator machine.
