<!-- source: infra-commons templates/rotation-log.md — the log shape, and the staged deploy-key rotation shape -->
# Rotation log — shape

Dated lines under a "Rotation log" heading in the consumer's harness or key
inventory, appended at every pin bump of a secret-bearing component or at
most yearly. One line per event; two kinds of event, named as such:

```
- <YYYY-MM-DD> — MODEL: <what changed about how a secret is minted, stored or
  scoped> (e.g. "handoff secret: minted-per-deploy -> stable file, minted once").
- <YYYY-MM-DD> — ROTATED: <name> (<why: scheduled | exposure | pin bump>);
  <what else it re-keys> (e.g. "rotating the mailbox secret re-keys every
  derived mailbox handle — do it together with a wipe of the derived data").
```

Rules: never a value, never a fingerprint of a private half; the line says
what a reader must re-do because of the event. A credential with a console
expiry date gets that date in the inventory row, not here.

---

# Staged rotation of a deploy SSH key — shape

Two facts shape the ceremony; state both in the consumer's copy:

1. **An apply never re-keys a running host.** cloud-init's
   `ssh_authorized_keys` runs at first boot only, and nothing in the deploy
   tree writes `authorized_keys`. The IaC key object and the templated
   `user_data` are the trust anchor for a **rebuild**, not a rotation channel
   (`hcl/shared/instance-first-boot-ignore-changes.tf` keeps a rotation from
   planning a replacement).
2. **A vault put is an upsert, and the broker can neither list nor delete.**
   Minting straight over the live name destroys the old private half on the
   spot while every host still trusts only the old key: ssh-agent then holds
   its only copy, and an agent expiry or a reboot mid-ceremony is console
   recovery on every host. So the rotation is **staged**: the new pair is
   written BESIDE the live one (`<name>_next` in the vault,
   `<key>.next.pub` on disk); only *promote* writes the live name, and only
   after every host has accepted the new key.

Tooling contract (three verbs; build them, do not hand-run the vault calls):

- `keygen` is rotation-only staging: it writes the `_next` name and the
  staged `.pub` and nothing else; it refuses while a staged `.pub` exists (one
  rotation in flight). The private sibling file `<key>.next` must never exist:
  given `-i X.pub`, ssh silently signs from a private FILE named `X`.
- `ssh-agent --next` loads the staged key beside the live one.
- `promote` is all-or-nothing across every host: it requires the agent to hold
  the staged key (checked first, so a refusal spends no touch); logs in to
  EVERY host once, pinned to the staged `.pub` with
  `-o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -F /dev/null
  -o ControlMaster=no -o ControlPath=none` (a `ControlMaster` connection
  opened earlier on the LIVE key answers `ssh … true` with rc 0 and no
  authentication at all); any refusal = nothing changed, the host named. Only
  then: fetch the staged private half, check it IS the key behind the staged
  `.pub` (the agent's copy was tied to `_next` only when `--next` ran; a
  `_next` minted again since would put a key no host trusts under the live
  name), put it under the live name, and only after that put succeeds swap
  the `.pub`. Vault first, `.pub` second: safe to repeat; the staged `.pub` is
  the resume point. The line that announces the put is the point of no
  return — name it in the runbook.

The ceremony (attended, in a real terminal; touches in brackets; nothing
before step 6 changes what the live key depends on, so it can be abandoned):

1. Load the live key `[1 touch; none when loaded]`.
2. Stage the new pair `[1 touch]`. Everything keeps running on the live key.
3. Keep the OLD public half (`cp -p live.pub retiring.pub`): promote replaces
   the live `.pub`, and step 9 needs the exact old text to remove the right
   line. Identify the old key by its **blob**, never by its comment.
4. Append the staged public half on EVERY host, over the live key:
   `'(echo; cat) >> ~/.ssh/authorized_keys' < staged.pub`. The leading `echo`
   matters: a bare `cat >>` onto a file that does not end in a newline glues
   the new key onto the old key's comment — the old key keeps working, the new
   one silently never exists. Then prove it landed as a line of its own:
   `grep -c '^ssh-ed25519 <blob> ' ~/.ssh/authorized_keys` prints 1 per host.
5. Load the staged key beside the live one `[1 touch]`.
6. Promote `[touches: the fetch and the put, after every host accepted]`. A
   refusal that does not say "do NOT abandon" = nothing changed: fix what it
   names, re-run. Past the point of no return, only PROMOTED ends the step:
   interrupted → run it again.
7. Point the trust anchor the consumer keeps in its config at the new `.pub`,
   then the preflight stage `[1 touch]` and one real SSH-using check on the
   new key.
8. The IaC trust anchor, so a REBUILT host gets the new key: plan (expect the
   key object updated in place and NO change to the instance; unrelated drift
   may ride along — read it), then apply through the plan gate. Not urgent: a
   running host never reads it.
9. Only now: drop the OLD line on every host, over the NEW key. The removal
   refuses to touch a file that lacks the new key, keeps a copy on the host,
   and swaps by rename:
   ```
   set -eu; cd ~/.ssh
   grep -qF '<new blob>' authorized_keys
   cp -p authorized_keys authorized_keys.pre-rotation
   grep -vF '<old blob>' authorized_keys.pre-rotation > authorized_keys.new
   grep -qF '<new blob>' authorized_keys.new
   chmod 600 authorized_keys.new && mv authorized_keys.new authorized_keys
   ```
   Then the proof, **while the agent still holds the old key** (so a refusal
   comes from the host), with fresh logins and the ssh config shut out. The
   loop judges itself — a drop that did not work makes the old-key login
   SUCCEED, and a success prints nothing, so a proof that waits for you to
   notice a missing "Permission denied" reads as green. The new key goes
   first: ssh answers 255 for a refusal AND for an unreachable host, so "old
   key refused" means something only on a host that just let the new key in.
   Must print, for every host, `new key OK, old key refused`; any STOP line:
   stop.
   ```
   FRESH=(-o BatchMode=yes -F /dev/null -o ControlMaster=no -o ControlPath=none
          -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=<pinned file>)
   for H in "${HOSTS[@]}"; do
     if ssh -i live.pub -o IdentitiesOnly=yes "${FRESH[@]}" deploy@$H true; then
       ssh -i retiring.pub -o IdentitiesOnly=yes "${FRESH[@]}" deploy@$H true 2>/dev/null \
         && echo "$H: STOP - the OLD key is STILL accepted, the drop did not work" \
         || echo "$H: new key OK, old key refused"
     else
       echo "$H: STOP - the NEW key was refused or the host is unreachable; remove nothing else"
     fi
   done
   ```
10. Finish: `ssh-add -d retiring.pub && rm retiring.pub`; preflight `[1 touch]`;
    the repo's tripwire tests green. Remove `authorized_keys.pre-rotation` on
    the hosts when satisfied (public keys only). The `_next` entry cannot be
    deleted; after a promote it duplicates the live key and the next rotation
    overwrites it.

Gotchas worth a line in every copy: at a default macOS zsh prompt `#` is not a
comment (`setopt interactivecomments` first, or paste into a script); write
loops with `${A:?}`-style guards INSIDE the loop so a pasted block refuses to
run with a host variable unset; a bash array for the ssh options — a scalar in
zsh is not word-split.
