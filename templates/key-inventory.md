<!-- source: infra-commons templates/key-inventory.md — copy, fill, delete the example rows -->
# Vault key contract — every `<project>` secret, by name

Names only. This file is the inventory the vault cannot give you (a put-only
broker can neither list nor delete keys) and the contract the deploy and IaC
wrappers are graded against. A secret **value** never appears in this repo, in
a tfvars file, on a command line, or in a tool transcript. Design authority:
`<link to the design page and the dated decisions>`.

Rules the wrappers enforce (keep the ones that are true; a rule that is not
enforced by code is a wish, not a rule):

1. **Vault or process memory only.** A secret exists in the sealed store, in
   the memory of one short-lived wrapper process, or — for the deploy SSH key —
   in ssh-agent for one sitting. It reaches a host over an SSH channel into
   `/tmp`, where bootstrap installs it at 0600 and shreds the copy.
2. **One batch, one touch.** A wrapper fetches everything it needs with a single
   all-or-nothing batch. A mistyped name aborts before any host contact.
3. **Role guard.** `role` comes from the worktree's own IaC output. Role A may
   fetch `<project>_*` and shared names; role B may fetch `<project>_<roleB>_*`
   and shared names. A cross-role name is refused before the fetch.
4. **Skeletons are secret-free.** Env generators emit files containing no line
   whose key is in the "Env / secret key" column. The wrapper refuses a
   skeleton that contains one, so a stale file can never ride along.
5. **Facts are not secrets.** Host address, domain, role and the other IaC
   outputs are cached (0600, gitignored) after every IaC run, so verify / ssh /
   status never need the state passphrase.

## Shared names (every role)

| Vault name | What it is | Env / secret key | Consumers | Rotation |
|---|---|---|---|---|
| `example_cloud_api_key` | Cloud provider API key, scoped to this project's resources. | `TF_VAR_cloud_api_key`; header-file transport for the resolve script | IaC wrapper, `make resolve` | Console: create new, `secret-put`, delete old. **Expires `<date>`** (recorded `<date>`). |
| `example_dns_token` | DNS-edit token for `example.com`, client-IP filtered to the operator machine and the host. | `TF_VAR_dns_api_token`; streamed to the host for the DNS-01 challenge | IaC wrapper, deploy wrapper (role A only) | In-broker roll, then deploy in the same sitting. |
| `example_handoff_secret` | The one secret the two roles share (must differ from every signing secret). | `HANDOFF_SECRET` in both env files | deploy wrapper, both roles | Chained: `secret-put`, then deploy role B, then role A. |

## Role A names (`role = "app"`, the `<path>` worktree)

| Vault name | What it is | Env / secret key | Consumers | Rotation |
|---|---|---|---|---|
| `example_deploy_ssh_key` | The role's deploy SSH private key (ed25519; its `.pub` is what the host authorizes). Never a file on the operator machine. | none — `make ssh-agent` loads it into ssh-agent for one sitting | every ssh/scp/rsync (pinned `.pub` + `IdentitiesOnly`) | **Not an apply** — see `rotation-log.md`, "Staged rotation of a deploy SSH key". |
| `example_tf_state_passphrase` | The IaC state + plan encryption passphrase. Lost = unreadable state. | `TF_VAR_state_passphrase` | IaC wrapper | Re-key via the tool's key rotation; escrow first. |
| `example_root_password` | Provider-console root password — break-glass only. | never on a host | the operator, by hand | Console reset; `secret-put`. |

## Role B names (`role = "<roleB>"`, the `<path>` worktree)

| Vault name | What it is | Env / secret key | Consumers | Rotation |
|---|---|---|---|---|
| `example_<roleB>_deploy_ssh_key` | as above, for the second role | … | … | … |

## Rotating a deploy SSH key

Point here at the consumer's copy of the staged-rotation ceremony
(`rotation-log.md` gives the shape). State the two facts that shape it: an
apply never re-keys a running host, and a vault put is an upsert with no list
or delete.

## Public values that stay in plain files

| File | Holds | Why plain |
|---|---|---|
| `deploy/.secrets/settings.env` (0600) | every non-secret production setting: OAuth client IDs, mail host/port/user, cookie names, tunables | Public or non-secret; needs its own home once the dev env file holds dev-only clients. |
| `deploy/.secrets/known_hosts`, `deploy_ed25519.pub`, `origin-ca.pem` | host keys, the deploy key's public half (what every ssh call pins), the public certificate | Public. |

## Disclosed exceptions — retired by v`<N>` (`<date>`, `<runbook>`)

Version `<N-1>` kept these private keys on disk at 0600. Version `<N>` moved them
into the vault (rows above); the wrappers now **refuse to run while either file
exists**, and a quarantined `*.hold` copy from the rollout only warns until it
is shredded.

| File (gone) | Was | Now |
|---|---|---|
| `deploy/.secrets/deploy_ed25519` | the disclosed exception, host firewall as the guard | `example_deploy_ssh_key`, loaded into ssh-agent per sitting |
| `deploy/.secrets/origin-ca.key` | deferred | `example_<roleB>_origin_ca_key`, streamed at deploy behind an SPKI check |

## Retired at the cutover (deleted or reduced, in this order)

1. Credential lines in `terraform.tfvars` (the IaC wrapper refuses to run while one exists).
2. The DNS-01 credentials file (streamed from the vault instead).
3. Persisted env files with secret lines (the wrapper streams from memory; skeletons contain no secret).
4. Production secret lines in the development env file.
5. The plaintext state copies, once the encrypted state is proven.

## What stays on the hosts (out of scope by decision)

The runtime env at 0600, the DNS-01 credentials file until an HTTP-01 path
lands, and the seconds-long `/tmp` window during a deploy.
