# harness/ — the deploy model (Tier B: knowledge, not code)

`HARNESS.md` is the node/gate model for driving a repo → remote host production
deployment: idempotent nodes, external-adversarial gates, first-class rollback
edges, the secrets channel, and the touch-budget / sitting vocabulary for
deployments whose secrets live behind a hardware factor.

It is **generic on purpose**. A consumer does not import it; it instantiates
it: the node graph and gate predicates below are the contract, the consumer's
own `HARNESS.md` (or deploy README) holds the instantiation table — which
tool implements each gate, the exact predicate, and any role-specific rows.
Nothing consumer-specific (hostnames, unit names, file paths, credential
names) belongs in this copy.

## Copy-with-audit

Tier B content is copied, never linked or vendored. The copy carries a
provenance line so drift is visible and a later diff is cheap:

```
<!-- source: infra-commons@<ref> harness/HARNESS.md — audited <YYYY-MM-DD> -->
```

"Audited" means a human read the copy against the consumer's reality at that
date: every gate in the table has a tool behind it and every rollback edge has
been exercised or is explicitly marked untested. Re-audit when the pinned ref
moves or when the deployment gains a node.
