<!-- source: infra-commons templates/LAUNCHER-SEAM.md — normative; the seam is recorded here, the launcher is not -->
# The launcher seam — where a generic harness meets a project's control panel

**Decision recorded here, once:** a launcher (a control panel that renders a
form from a plan document, runs preflight gates and streams a staged pipeline)
is **not** part of this commons. The seam between a generic deploy harness and
such a panel is normative and documented; the panel code stays in the project
that needs it.

## Two kinds of project

- A **pipeline project** has an orchestrated deploy: human-in-the-loop
  blockers, strict ordering, gates, a repeatability requirement. Nearly every
  first dev → production move qualifies; the harness model
  (`harness/HARNESS.md`) and the runbook templates are what such a project
  shares.
- A **launcher-eligible project** additionally expresses its inputs as
  machine-parsed BLOCKER stubs feeding a programmatic DAG engine that a panel
  can drive end to end, with no interleaved human steps a form cannot express
  (a hardware-key touch per verb, a typed approval, a provider-console click, a
  real-browser claim are all such steps).

A CLI-orchestrated pipeline with interleaved human steps is a pipeline project
and **not** launcher-eligible. It gets nothing from a panel and would pay the
panel's constants.

## The seam (mechanism boundary)

A launcher that stays healthy has three layers, and the panel owns **zero
pipeline logic**:

| Layer | Owns | Example contract |
|---|---|---|
| schema | parsing the plan document's BLOCKER stubs into typed inputs | `<!-- BLOCKER:id=<name> type=<secret\|string\|enum> required=<bool> secret=<bool> depends_on=<id>=<value> -->` — one stub per input, in the plan document itself, so the form can never drift from the plan |
| rules | validation of supplied values, completeness per phase, the escrow acknowledgment | "every start-phase required blocker has a value or a default"; "a secret field is write-only: the panel never echoes a stored value" |
| view | the form, the preflight-gate display, the streamed stage log | renders whatever the schema says; carries the project's constants (tab names, badges, human-command patterns) |

The two contracts a consumer must keep even without a panel: **write-only
secret fields** (a value goes in, never comes back out through the UI or its
API) and **preflight gates** (the panel cannot start a stage the preflight
refused).

## The extraction test

When a second launcher-eligible project appears, ask one question: *can it
express its form purely as a BLOCKER-stub plan document?*

- Yes → extract the schema + rules layers into this commons (the view follows
  as a template, not a module).
- No (it needs edits to the UI code) → copy, with provenance, and record the
  divergence.

Until then: **no ad-hoc partial copying.** Panel code carries project-specific
constants that would land silently in another project's control plane.

## What a consumer records

In its own repo: which kind of project it is (one line), and — if
launcher-eligible — that its panel keeps the three-layer seam and the two
contracts, with the file that enforces "the panel owns zero pipeline logic".
