"""tofu_runner — deny-by-default OpenTofu driver shared across repos.

Extracted from two proven private deployments: a single-VPS app stack
(entry guards, clean env, facts cache) and a two-VPS mail stack (planfile
pipeline, destructive-plan gate).

Semantics:
  * Verbs: exactly ``init | plan | apply | destroy``. ``state pull``, ``show``
    and ``output -json`` print decrypted state/secret values and are
    unreachable from any consumer CLI built on :func:`run_verb`
    (``output -json`` runs only internally, captured, for the facts cache).
  * ``apply`` and ``destroy`` go through a saved plan file:
    ``plan -out`` -> internal ``show -json`` (captured; never printed, logged
    or written to disk) -> gate hook -> ``apply <planfile>``. Native ungated
    ``tofu destroy`` is never invoked; ``destroy`` is ``plan -destroy`` plus
    the same pipeline.
  * The gate hook receives the parsed plan JSON in-process; refusals name
    resource addresses only (see :mod:`tofu_runner.plangate`).
  * Applies are serialized per process (one state file).
  * The facts cache is default-deny: only outputs the consumer names in an
    explicit allowlist are written (0600, atomic); any output marked
    sensitive refuses the whole refresh, even if named.

Errors carry names and reasons only — never a secret value. The consumer
supplies its own configuration (credential key names, facts allowlist, gate,
TF_VAR values); no consumer branching lives here.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

VERBS = ("init", "plan", "apply", "destroy")
_CLEAN_ENV_BASE = ("PATH", "HOME", "TF_IN_AUTOMATION", "TF_INPUT")
_APPLY_LOCK = threading.Lock()  # one state file per consumer process


class RunnerError(RuntimeError):
    """Names/reasons only — never a value."""


def _json_keys(node: object) -> set[str]:
    """All object keys at any depth (a credential nested under another key
    would not reach tofu as a variable, but it would still rest on disk)."""
    out: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            out.add(str(k))
            out |= _json_keys(v)
    elif isinstance(node, list):
        for v in node:
            out |= _json_keys(v)
    return out


def guard_tfvars(tf_dir: Path, credential_keys: tuple[str, ...]) -> None:
    """Refuse while any auto-loaded tfvars variant carries a credential key —
    those files silently outrank TF_VAR_* and would put a credential back on
    disk. ``*.example`` files are ignored."""
    cred_line = re.compile(r"^\s*(" + "|".join(map(re.escape, credential_keys)) + r")\s*=", re.M)
    files = sorted(set(tf_dir.glob("*.tfvars")) | set(tf_dir.glob("*.tfvars.json"))
                   | set(tf_dir.glob("*.auto.tfvars")) | set(tf_dir.glob("*.auto.tfvars.json")))
    for f in files:
        if f.name.endswith(".example"):
            continue
        text = f.read_text()
        if f.suffix == ".json":  # tofu auto-loads *.tfvars.json too — same keys, JSON shape
            try:
                doc = json.loads(text or "{}")
            except json.JSONDecodeError as e:
                raise RunnerError(f"{f.name} is not valid JSON — refusing to guess its keys") from e
            keys = _json_keys(doc)
            found = [k for k in credential_keys if k in keys]
        else:
            m = cred_line.search(text)
            found = [m.group(1)] if m else []
        if found:
            raise RunnerError(f"{f.name} still carries a credential line ({found[0]}) — "
                              f"delete it; the vault is the only source")


def guard_config(tf_dir: Path) -> None:
    """Refuse a configuration that could hand the credentials to an
    arbitrary program."""
    for f in sorted(tf_dir.glob("*.tf")):
        text = f.read_text()
        if re.search(r"^\s*provisioner\s+\"", text, re.M):
            raise RunnerError(f"{f.name} declares a provisioner — refused (it would receive the credentials)")
        if re.search(r"^\s*data\s+\"external\"", text, re.M):
            raise RunnerError(f"{f.name} declares an external data source — refused")


def clean_env(tf_vars: dict[str, str]) -> dict[str, str]:
    """Environment holding only PATH, HOME, TF_IN_AUTOMATION, TF_INPUT and
    the given TF_VAR_* values — secrets travel env-only, never argv or file."""
    bad = sorted(k for k in tf_vars if not k.startswith("TF_VAR_"))
    if bad:
        raise RunnerError(f"non-TF_VAR_ keys in the tofu environment: {bad}")
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"),
        "HOME": str(Path.home()),
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
        **tf_vars,
    }


def refresh_facts(env: dict[str, str], tf_dir: Path, allowlist: frozenset[str],
                  run=subprocess.run) -> Path:
    """Write the allowlisted output values to ``<tf_dir>/outputs.json`` (0600,
    atomic). Default-deny: an output not named in ``allowlist`` is not cached
    (noted on stderr, names only); an output marked sensitive refuses the
    whole refresh even if named."""
    proc = run(["tofu", "output", "-json"], cwd=tf_dir, env=env,  # noqa: S603, S607
               capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RunnerError(f"tofu output -json exited {proc.returncode}; facts cache not refreshed")
    doc = json.loads(proc.stdout or "{}")
    sensitive = sorted(k for k, v in doc.items() if v.get("sensitive"))
    if sensitive:
        raise RunnerError(f"outputs {sensitive} are marked sensitive — refusing to cache them")
    skipped = sorted(set(doc) - allowlist)
    if skipped:
        print(f"facts cache: outputs not in the allowlist, not cached: {skipped}", file=sys.stderr)
    facts = {k: v.get("value") for k, v in doc.items() if k in allowlist}
    out = tf_dir / "outputs.json"
    tmp = out.with_suffix(".json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(facts, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, out)
    return out


def parse_gate_overrides(args: list[str]) -> tuple[list[str], dict[str, str]]:
    """Extract ``--allow-protected-destroy <addr>`` (repeatable) and one
    ``--reason <text>`` from consumer CLI args; the reason covers the run.
    Returns (remaining args for tofu, {address: reason})."""
    rest: list[str] = []
    addrs: list[str] = []
    reason: str | None = None
    it = iter(args)
    for a in it:
        if a in ("--allow-protected-destroy", "--reason"):
            try:
                val = next(it)
            except StopIteration:
                raise RunnerError(f"{a} needs a value") from None
            if a == "--reason":
                if reason is not None:
                    raise RunnerError("--reason given more than once — one reason covers the run")
                reason = val
            else:
                addrs.append(val)
        else:
            rest.append(a)
    if addrs and not (reason or "").strip():
        raise RunnerError("--allow-protected-destroy needs --reason '<why>'")
    return rest, {a: reason for a in addrs}


def run_verb(verb: str, extra: list[str], env: dict[str, str], tf_dir: Path,
             gate=None, run=subprocess.run) -> int:
    """Execute one verb. ``plan`` streams tofu's human-readable output;
    ``apply``/``destroy`` run the gated planfile pipeline (module docstring).
    ``gate`` is called with the parsed plan JSON and raises to refuse."""
    if verb not in VERBS:
        raise RunnerError(f"verb {verb!r} is not one of {'|'.join(VERBS)} — "
                          "other tofu verbs print decrypted secrets and are unreachable here")
    if verb == "init":
        return run(["tofu", "init", "-input=false", *extra], cwd=tf_dir, env=env, check=False).returncode  # noqa: S603, S607
    rc = run(["tofu", "init", "-input=false"], cwd=tf_dir, env=env, check=False).returncode  # noqa: S603, S607
    if rc != 0:
        return rc
    if verb == "plan":
        return run(["tofu", "plan", "-input=false", *extra], cwd=tf_dir, env=env, check=False).returncode  # noqa: S603, S607
    with _APPLY_LOCK, tempfile.TemporaryDirectory(prefix="tofu-plan-") as tmp:
        # Private 0700 temp dir: the plan file can embed sensitive values.
        planfile = str(Path(tmp) / "planfile")
        plan_args = ["plan", "-input=false", f"-out={planfile}"]
        if verb == "destroy":
            plan_args.append("-destroy")
        rc = run(["tofu", *plan_args, *extra], cwd=tf_dir, env=env, check=False).returncode  # noqa: S603, S607
        if rc != 0:
            return rc
        shown = run(["tofu", "show", "-json", planfile], cwd=tf_dir, env=env,  # noqa: S603, S607
                    capture_output=True, text=True, check=False)
        if shown.returncode != 0:
            # Deliberately no output excerpt: plan JSON carries secret values.
            raise RunnerError(f"tofu show -json on the plan file exited {shown.returncode}")
        if gate is not None:
            gate(json.loads(shown.stdout or "{}"))
        return run(["tofu", "apply", "-input=false", planfile], cwd=tf_dir, env=env, check=False).returncode  # noqa: S603, S607
