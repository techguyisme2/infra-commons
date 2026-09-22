<!-- source: infra-commons harness/HARNESS.md — the generic model; consumers copy and add their instantiation table -->
# Deployment Harness — Nodes & Gates

A reusable model for driving a **repo → remote host** production deployment as a
directed graph of **nodes** (units of work that change state) and **gates**
(pass/fail predicates that must hold before the next node runs). The harness is
*fail-closed*: a red gate halts the pipeline and selects a rollback edge rather
than letting a half-built system limp forward.

The model is written to generalize to any single-host deployment (one VPS behind
a CDN/proxy, IaC for the cloud resources, idempotent scripts for the host). A
consumer's `deploy/` directory is a concrete instantiation; section 7 says what
a consumer records and what stays here.

---

## 1. Design principles

1. **Separate provisioning from configuration.** Cloud resources (compute, DNS,
   firewall) are declarative IaC with state; host configuration is idempotent
   scripts. Never entangle the two — it makes both un-rerunnable.
2. **Every node is idempotent.** Re-running a node from any prior state converges
   to the same result. This is what makes the harness resumable after a failed gate.
3. **Gates are external and adversarial.** A gate verifies from *outside* the node
   that produced the artifact (curl the public URL, not "the script exited 0").
   The hardest / most-likely-to-fail case is the gate, not the happy path.
4. **Secrets never enter state or VCS.** They flow through a single channel and
   are shredded after transfer; state that can contain them is encrypted.
5. **Default-deny everywhere.** Firewall, file permissions, service capabilities,
   SSH.
6. **Rollback is a first-class edge,** not an afterthought — each mutating node
   names how to undo it.

---

## 2. Node / Gate graph

```
        ┌────────────────────────────────────────────────────────────────┐
        │                         (local, free)                           │
  N0 ── Preflight ───────────────────────────────────────────────► G0
        │  toolchain present; artifact builds clean; deploy key         │
        │  reachable (agent or vault); credentials reachable            │
        ▼
  N1 ── Resolve & Scaffold ──────────────────────────────────────► G1
        │  resolve dynamic facts (image id, plan, zone id) from the      │
        │  provider APIs; render IaC vars; validate + plan clean         │
        ▼
 ╔══════════════════ GATE A — human approval before paid/remote ══════════════════╗
        ▼
  N2 ── Provision (IaC apply) ───────────────────────────────────► G2
        │  host live; firewall attached (default-deny); DNS record       │
        │  resolves; outputs (address) captured                          │
        │  rollback ─► IaC destroy (gated: see plangate)                   │
        ▼
  N3 ── First-boot harden (cloud-init) ──────────────────────────► G3
        │  patched OS; non-root deploy user (keys only); root + password │
        │  SSH disabled; host firewall up; brute-force ban; unattended   │
        │  upgrades; completion marker                                   │
        │  rollback ─► re-image (destroy + apply) — cloud-init is one-shot │
        ▼
  N4 ── Ship artifact + data ────────────────────────────────────► G4
        │  build the artifact FRESH before any server contact; pull +    │
        │  VALIDATE a live-data snapshot first (no backup, no ship);     │
        │  sync code (no secrets / data / build junk) through a root     │
        │  receiver so the tree stays service-owned; stage the runtime   │
        │  env (0600); stage data only when the target provably has none │
        │  rollback ─► re-sync the previous revision                       │
        ▼
  N5 ── Configure runtime ───────────────────────────────────────► G5
        │  runtime deps; TLS certificate; reverse proxy; real-client-IP  │
        │  restore; service user; additive schema migration with the    │
        │  service stopped; service unit active                         │
        │  rollback ─► redeploy the prior unit + config                    │
        ▼
  N6 ── Verify (hard cases) ─────────────────────────────────────► G6
        │  external HTTPS 200; HTTP→HTTPS; HSTS; anonymous → 401;        │
        │  authorization matrix (403/404) via the test suite; nothing    │
        │  reflected that should not be; port scan shows only intended  │
        │  ingress                                                       │
        │  rollback ─► fail closed; do not flip traffic / promote          │
        ▼
  N7 ── Operate ─────────────────────────────────────────────────► G7
        │  scheduled data backup (+ offsite); certificate auto-renew +   │
        │  reload hook; log rotation; health check; optional snapshots   │
        ▼
  N8 ── Record ──────────────────────────────────────────────────► G8
        │  IaC committed (no secrets); harness / runbook written;        │
        │  decisions + problems + gate results logged to durable memory │
```

### Gate predicates — the instantiation table (template)

Each consumer fills this table in its own copy. A gate without a tool is not a
gate; a predicate that can fail for reasons other than the thing it tests must
distinguish *false* from *unknown* and treat unknown as stop (section 4).

| Gate | Predicate (exact, checkable) | Tool |
|------|------------------------------|------|
| G0 | toolchain binaries present; artifact build exits 0; deploy key's public half pinned and its private half reachable (agent loaded / vault answering) | preflight |
| G1 | `validate` ok; `plan` shows only intended changes; every resolved fact non-empty | plan wrapper |
| **A** | **operator types approval** (paid resources next) | human |
| G2 | host address output set; DNS name resolves to it | provider API / dig |
| G3 | cloud-init status = done; hardening marker exists; SSH as the deploy user works; root SSH refused | ssh |
| G4 | validated data snapshot exists locally; runtime env present (0600, service-owned); no secret or data file leaked from VCS | ssh |
| G5 | service active; local health endpoint answers the expected code, **polled with a bound, fail-closed**; proxy config test ok; certificate present | ssh |
| G6 | the verify script: public HTTPS, redirect, HSTS, anonymous refusals, port scan | verify wrapper |
| G7 | backup timer enabled; certificate renewal dry-run ok | ssh |
| G8 | tree clean of secrets; harness + memory written | review |
| G4/G5/G6 (role = *second role*) | the second role's own rows — what must be present, what must be **absent** (hard failures, never quietly locked down) | bootstrap / verify |

---

## 3. Secrets-handling model

```
   vault / broker  ──►  wrapper process memory  ──►  IaC vars (sensitive, never in plan output)
                                                ──►  ssh channel to /tmp on the host ──► install 0600 ──► shred the /tmp copy
```

- **One channel.** Secrets reach a host through exactly one path (a staged
  batch over SSH into `/tmp`, installed at 0600, shredded). Nothing secret lives
  anywhere else on the operator machine than the vault, one short-lived wrapper
  process, or — for the deploy SSH key — the ssh-agent for one sitting.
- **Never in state / VCS.** Provider credentials are `sensitive` variables
  supplied as environment (`TF_VAR_*`), never in a tfvars file the tool
  auto-loads. State and plan files can contain secrets → encrypted at rest
  (`hcl/shared/state-plan-encryption.tf`) and gitignored.
- **Minted, not reused.** Production signing secrets are freshly generated; a
  production value never equals a development value.
- **Shredded after use.** Staged secrets in `/tmp` are `shred -u`'d by the
  bootstrap step that installs them.
- **Least privilege.** Every API token is scoped to the one permission the
  pipeline uses (a DNS-edit token serves both the DNS record and a DNS-01
  challenge; it never has account-level rights).
- **Two stacks share at most one secret.** A second role (a training or staging
  box built from the same module) has its own worktree, state, and secret set;
  it never holds the production role's signing, OAuth, mail or data secrets.
  Whatever the two must share (a handoff secret) is a stable, minted-once value
  recorded in the key inventory — and the production side refuses to fall back
  to a shared value it was not given.
- **Rotation log.** Dated lines, one per change to the *model* or to a secret's
  lifetime; shape in `templates/rotation-log.md`.

### Touch budget and sitting vocabulary

For a vault behind a hardware factor, every fetch or put costs one **touch**.
The words below keep runbooks honest about what an operator is asked to do:

- **Touch** — one physical confirmation on the hardware key. A touch that comes
  too late fails the ceremony with nothing stored or fetched; re-run the line.
- **Batch** — one wrapper fetch of everything a verb needs, all-or-nothing
  (`secret-get-many` shape). A mistyped name aborts before any host contact.
  One verb = one touch.
- **Sitting** — the window during which the deploy key sits in ssh-agent (a
  fixed TTL, e.g. 4 h). Loading the agent is **1 touch per sitting**, not per
  deploy. Within a sitting, verify / ssh / status need no touch.
- **Ceremony** — an attended sequence with touches in brackets per step, a
  budget line at the top (touches and minutes; "do not start with less than an
  hour"), and a named gate that must print its pass token before the
  irreversible step.
- **TTL expiry mid-deploy** aborts cleanly at the next SSH ("Permission denied
  (publickey)"); because every node is idempotent the remedy is reload and
  re-run. A remaining-TTL tracker (refuse to start with < N minutes left) is a
  documented non-goal: the agent exposes no lifetime, a deploy is minutes
  against hours, and the failure mode costs one reload.
- **Availability trade-off, disclosed.** With no private key on disk, host
  access depends on the vault. Break-glass is the provider console with a
  vault-held root password; the last resort is the vault's own escrow. Before
  any key file is shredded: (1) the escrow drill must print its READY token
  for the new names, and (2) the console path is written into the consumer's
  README as the runbook of last resort — an outage never starts with "how do we
  get in".

---

## 4. Idempotency guarantees

| Node | How re-running converges |
|------|--------------------------|
| Resolve / Scaffold | pure functions of API state; variables upserted by key |
| Provision | IaC state reconciles desired vs actual; no duplicates |
| First-boot | cloud-init runs once per instance; re-image to redo |
| Ship | `rsync --delete` makes destination match source; excluded files protected; the artifact is rebuilt every run so "source" is never a stale bundle; the receiver runs as root so the live tree is never chowned away from the running service mid-transfer |
| Configure | every step guards (`id -u`, `test -d`, `ln -sf`, `daemon-reload`); the schema migration is additive + idempotent; the data install **refuses to overwrite** an existing server copy |
| Operate | timers / units enabled idempotently; backups rotate by count |

> ⚠️ **An idempotency guard is only as good as its permissions.** A guard such
> as "refuse to overwrite an existing server copy" is usually a file test, and a
> file test run by an account that cannot read the directory returns *false* —
> indistinguishable from "nothing is there". Run such probes with the privilege
> that can actually see the target, push the same reasoning up into the ship
> step (do not stage a local copy unless absence is *proved*) and into the
> pre-deploy backup (an unreadable probe aborts rather than counting as "first
> deploy"). Generalizes: **a predicate that can fail for reasons other than the
> thing it tests must distinguish false from unknown, and treat unknown as
> stop.**

---

## 5. Failure-mode taxonomy

| Class | Example | Detection | Response |
|-------|---------|-----------|----------|
| **Provider** | quota / region / plan unavailable; API 4xx | apply error; resolve step empty | fix variables; re-plan (pre-Gate A, no cost) |
| **Boot** | cloud-init package failure, lockout | G3 marker missing / SSH fails | provider console (break-glass); re-image |
| **DNS / TLS** | DNS-01 propagation slow; token scope wrong | certificate client non-zero | raise propagation seconds; verify token; re-run bootstrap |
| **Proxy / edge** | CDN TLS mode mismatch; origin not reachable from the CDN | G6 curl fails | set the CDN mode to full-strict; confirm the firewall's source ranges (see `hcl/single-source/cloudflare-cidr-firewall.tf`) |
| **App** | bad env, migration, port clash | G5 health poll never sees the expected code | service journal; fix env; restart |
| **Authorization regression** | object- or function-level hole | test suite + G6 anonymous checks | block promotion; do not ship |
| **Data** | clobber / corruption | pre-deploy snapshot validation; overwrite guard | abort the deploy; restore the newest validated snapshot |
| **Drift** | manual host change vs IaC | `plan` non-empty | reconcile via re-apply; a plan that *replaces* a protected resource is refused by the plan gate — find the ForceNew attribute before overriding (`hcl/shared/instance-first-boot-ignore-changes.tf`) |

---

## 6. What a single-host instantiation deliberately scopes out

- Multi-node / HA / zero-downtime cutover (a second role is a second,
  independent stack of the same module, not a cluster).
- Team-grade remote state locking (one operator; encryption still applies).
- Application-code changes — **the harness never patches the app.** Whatever
  is in the working tree is what ships (working-tree-based, not git-ref-based,
  deploys), and security gaps that can only be fixed in code are mitigated at
  the edge and flagged, not patched. Fixing them is the application's job, on
  its own release cycle.

---

## 7. How a consumer instantiates this

Copy this file into the consumer's deploy directory with the provenance line
from `harness/README.md`, then:

1. Keep sections 1, 3 (model + vocabulary), 4 (the lesson), 5 and 6 as they
   are — or shorten them; do not add consumer facts to them.
2. Replace the **instantiation table** in section 2 with the real one: one row
   per gate, the exact predicate, the tool that runs it, and extra rows for a
   second role. Every row must be checkable by someone who has never seen the
   repo.
3. Add a **rotation log** under section 3 (`templates/rotation-log.md`) and
   point at the key inventory (`templates/key-inventory.md`).
4. Record, next to each rollback edge, whether it has been exercised.
5. The launcher / control-panel question is answered once, in
   `templates/LAUNCHER-SEAM.md`: a pipeline project instantiates this model;
   only a launcher-eligible project also drives it from a form.
