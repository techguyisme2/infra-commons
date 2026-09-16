"""Destructive-plan gate — refuse tofu plans that delete protected resources.

Generalized from a proven private deployment's destroy gate: the
protected-address list and the per-run overrides are parameters here, not
module globals, so each consumer supplies its own policy. The gate sits
between ``tofu plan`` and ``tofu apply`` — the runner applies from a saved
plan file, so what was checked is exactly what applies.

Default is refuse; the override (``--allow-protected-destroy <addr>
--reason <text>``, parsed by ``tofu_runner.parse_gate_overrides``) exists so
a legitimate teardown never requires a code edit. Deliberately NOT
``prevent_destroy`` in the consumer's HCL — that would force a mid-incident
code edit.

Refusal messages name resource addresses only — never plan values.
"""
from __future__ import annotations

from . import RunnerError


class ProtectedDestroyError(RunnerError):
    """A tofu plan wants to delete protected resources and no override
    covers them. Message lists every violating address."""

    def __init__(self, addresses: list[str]):
        self.addresses = addresses
        listing = "\n".join(f"  - {a}" for a in addresses)
        super().__init__(
            "refusing to apply: this plan DELETES protected resources:\n"
            f"{listing}\n"
            "If this is intentional (e.g. burn-and-rebuild), re-run with\n"
            "  --allow-protected-destroy <addr> --reason '<why>'\n"
            "per address.")


def planned_deletes(plan_doc: dict) -> list[str]:
    """Addresses the plan deletes or replaces (replace = delete+create)."""
    out = []
    for rc in plan_doc.get("resource_changes", []):
        actions = rc.get("change", {}).get("actions", [])
        if "delete" in actions:
            out.append(rc.get("address", "?"))
    return out


def check_plan(plan_doc: dict, protected: frozenset[str],
               overrides: dict[str, str] | None = None, log=print,
               tag: str = "gate", on_override_used=None) -> None:
    """Raise :class:`ProtectedDestroyError` unless every protected delete in
    ``plan_doc`` (a ``tofu show -json <planfile>`` document) is overridden.
    Logs every delete it sees and every override it consumes."""
    overrides = overrides or {}
    violations = []
    for addr in planned_deletes(plan_doc):
        if addr not in protected:
            log(f"[{tag}] plan deletes {addr} (not protected — allowed)")
            continue
        reason = overrides.get(addr)
        if reason is None:
            violations.append(addr)
            continue
        log(f"[{tag}] OVERRIDE consumed: protected delete of {addr} "
            f"allowed — reason: {reason}")
        if on_override_used is not None:
            on_override_used(addr, reason)
    if violations:
        raise ProtectedDestroyError(sorted(violations))


def make_gate(protected: frozenset[str], overrides: dict[str, str] | None = None,
              log=print, tag: str = "gate", on_override_used=None):
    """A gate callable for ``tofu_runner.run_verb(gate=...)``."""
    def gate(plan_doc: dict) -> None:
        check_plan(plan_doc, protected, overrides, log=log, tag=tag,
                   on_override_used=on_override_used)
    return gate
