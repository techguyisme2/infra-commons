# hcl/ — snippet library (Tier B: copy-with-audit, NOT a module)

Proven OpenTofu/HCL fragments, copied into a consumer's own root module with
a provenance header. There is deliberately **no shared Terraform module**: a
two-host mail graph and a one-host app graph are different topologies, and a
module would force one shape on both. A snippet is evidence plus a caveat; the
consumer owns the copy.

## Two classes

| Directory | Meaning | May a consumer adopt it without re-deriving? |
|---|---|---|
| `shared/` | proven in at least two independent consumers — a blessed default | yes, after reading the caveats |
| `single-source/` | proven in one consumer, recorded with provenance and a context caveat | no — the caveat names what must be re-derived or decided for the new context |

A single-source recipe moves to `shared/` when a second consumer has proven
it live; that move gets its own commit and the header's `proven-in` count
changes.

## Provenance header (every file, first lines)

```hcl
# source: infra-commons@<ref> hcl/<class>/<file>
# class: shared | single-source
# proven-in: <n> consumer(s), last <YYYY-MM-DD>
# caveats: <one line per caveat; "none" is not an answer for single-source>
```

The consumer keeps the header in its copy and adds one line:
`# audited: <YYYY-MM-DD> by <role>` — the date a human compared the copy with
the consumer's reality (provider version, variable names, the caveat's
decision). Re-audit when the pinned ref moves.

## Validation

Every snippet is a self-contained configuration (its own `terraform {
required_providers }` block and variables) so that `tofu fmt -check` and
`tofu validate` pass on the file alone. A consumer copying one into an
existing root module drops the duplicate `terraform` block and the variables
it already has.

## What is not here

Consumer topology (regions, plans, zone ids, addresses), protected-address
lists (a consumer's plan-gate policy), and anything that only makes sense with
one consumer's other resources. Those live in the consumer's repo.
