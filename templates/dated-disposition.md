<!-- source: infra-commons templates/dated-disposition.md -->
# Dated dispositions — `.gitleaks.toml` allowlists and `.gitignore` entries

An allowlist entry is a decision to stop looking at something. Written badly it
is a hole that outlives the reason for it. The convention: every entry carries
**the date, the reason, the narrowest shape that still matches, and a negative
control** — so that a later reader can re-check the decision without re-doing
the investigation, and so that a real secret with the same shape still trips.

## Triage rules for a finding

| Finding is … | Do |
|---|---|
| a real secret | do NOT allowlist it. Unstage, rotate the credential, rewrite the commit(s) before anything is pushed. |
| ciphertext by design (an encrypted store, a recipients file of public keys) | allowlist the **path**, with the reason "ciphertext only, safe to commit by design". |
| a fixture or a false positive | ONE entry, shaped as narrowly as the hit allows: path AND line shape — never a whole directory or a whole rule when a shape will do — with a dated one-line reason. |

## The baseline line

The config header names the baseline every entry below it belongs to:

```
# Baseline: <YYYY-MM-DD>, gitleaks <version> --redact over the full history
# (--all) and the tracked + unignored working tree. Every hit is dispositioned
# below.
```

Re-run the baseline at every scanner pin bump; a new baseline gets its own
dated line, entries it re-confirms keep their original date.

## Entry shape — per-entry form

```toml
# <YYYY-MM-DD> baseline: <what the hit is, in one sentence, and why it is not a
# credential for any account>. <what the next line / the test asserts, if that
# is the negative control>.
[[allowlists]]
description = "<file>: <what>"
targetRules = ["<the one rule that fired>"]
condition = "AND"
regexTarget = "line"
paths = ['''(^|/)docs/api-spec\.md$''']
regexes = ['''"sample_password": "[A-Za-z0-9]{12,14}"''']
```

## Entry shape — single-allowlist form (older configs)

```toml
[allowlist]
regexTarget = "line"
paths = [
    # Age-encrypted secret store: ciphertext only, safe to commit by design.
    '''^\.secrets/config\.enc$''',
]
regexes = [
    # Threat-model prose that trips generic-api-key's entropy heuristic (a
    # sentence with the word "credential" followed by an unusual token):
    # dispositioned false positive, baseline <date>. Shortened <date>: the
    # regex was written from the RENDERED sentence, but the source wraps
    # after the third word, so a directory-mode scan never matched it.
    '''credential, <the exact text on that ONE physical line>''',
    # <file> token identifier tags: provider token IDs are non-secret path
    # parameters (the secret is the token VALUE, never stored here).
    # Dispositioned <date>. Scoped to the manifest's field syntax so real
    # secrets in the file still trip.
    '''token_id\s+= "[0-9a-f]{32}"''',
]
```

## The negative control

Every prose or fixture disposition names what must STILL be refused, and a
test (or the next baseline) proves it: a key-shaped value on a line holding
only the first prose word must trip; a real key body of the same length in the
same file must trip. Without the control, an allowlist regex that is a hair
too wide passes review because nothing measures its width.

Two shapes that have bitten: a regex written from a rendered line that the
source **wraps** (the scan sees each physical line; anchor on the text that is
actually on one line), and a rule-wide disposition (`targetRules` without a
path) that silences the rule for every file.

## `.gitignore` entries

Same idea, lighter: a comment above each group says what the entries are and
why they must never land (`# Pinned scanner binary, fetched by the hook
mechanisms — one copy per work tree`, `# Local copies of the production data`).
An ignore entry that protects a secret is also listed in the key inventory's
"public values that stay in plain files" or "retired" tables — the two files
must agree.
