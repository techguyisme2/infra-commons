# templates/ — document shapes (Tier B: knowledge, not code)

Templates for the documents every pipeline project ends up writing. Each file
gives the **shape** — headings, columns, the rules a reader can grade the
document against — with a fictional example (example.com-class names, made-up
vault names) where a column is easier shown than described.

| File | Shape of |
|---|---|
| `key-inventory.md` | the names-only secret inventory: what exists, by name, where it flows, how it rotates; the "retired by vN" exceptions table |
| `cutover-runbook.md` | a one-sitting ceremony with a touch budget, a hard gate before the irreversible step, ordered roles, rollback, and the executed record |
| `rotation-log.md` | the dated rotation log, and the staged rotation of a deploy SSH key (stage beside the live key, prove, promote, drop, self-judging proof) |
| `dated-disposition.md` | how an allowlist or ignore entry is written so that it can be audited later: date, reason, narrowest shape, negative control |
| `LAUNCHER-SEAM.md` | the normative boundary between a generic deploy harness and a project-specific launcher / control panel, and the test for extracting one |

## Copy-with-audit

Copy the file, fill it in, delete the example rows. The copy carries a
provenance line at the top:

```
<!-- source: infra-commons@<ref> templates/<file> — audited <YYYY-MM-DD> -->
```

A template is a contract the document is graded against, not prose to keep:
if the consumer's reality needs a column the template lacks, add it in the
consumer's copy and open a change here when a second consumer needs it too.
Never copy a filled-in consumer document back into this repository — the
example columns here are fictional on purpose (public-grade content policy,
root README).
