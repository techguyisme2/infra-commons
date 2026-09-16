"""Mechanism tests for tofu_runner — guards, clean env, allowlisted facts
cache, override parsing, and the gated planfile pipeline against a fake tofu
binary that records every invocation. No network, no real tofu, no secrets.

Run:  python -m pytest -q tests
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tofu_runner as tr  # noqa: E402
from tofu_runner import plangate  # noqa: E402

CREDENTIAL_KEYS = ("vultr_api_key", "cloudflare_api_token", "state_passphrase")
CANARY = "secret-canary-value-9c1"


@pytest.fixture
def tf_dir(tmp_path):
    d = tmp_path / "terraform"
    d.mkdir()
    (d / "main.tf").write_text('resource "vultr_instance" "app" {}\n')
    (d / "terraform.tfvars").write_text('domain = "app.example.com"\nrole = "practice"\n')
    return d


# ------------------------------------------------------------------ guards

def test_guard_tfvars_refuses_every_credential_key_in_every_variant(tf_dir):
    tr.guard_tfvars(tf_dir, CREDENTIAL_KEYS)  # facts only: fine
    for fname, key in (("terraform.tfvars", "vultr_api_key"), ("x.auto.tfvars", "cloudflare_api_token"),
                       ("terraform.tfvars.json", "state_passphrase")):
        f = tf_dir / fname
        f.write_text(f'{key} = "leak"\n' if not fname.endswith(".json") else json.dumps({key: "leak"}) + "\n")
        with pytest.raises(tr.RunnerError) as e:
            tr.guard_tfvars(tf_dir, CREDENTIAL_KEYS)
        assert key in str(e.value) and "leak" not in str(e.value)
        f.unlink()


def test_guard_tfvars_refuses_a_credential_nested_in_json(tf_dir):
    (tf_dir / "terraform.tfvars.json").write_text(
        json.dumps({"secrets": {"vultr_api_key": "leak"}, "list": [{"state_passphrase": "x"}]}))
    with pytest.raises(tr.RunnerError, match="vultr_api_key|state_passphrase"):
        tr.guard_tfvars(tf_dir, CREDENTIAL_KEYS)
    (tf_dir / "terraform.tfvars.json").write_text("{not json")
    with pytest.raises(tr.RunnerError, match="not valid JSON"):
        tr.guard_tfvars(tf_dir, CREDENTIAL_KEYS)


def test_guard_tfvars_ignores_the_committed_example(tf_dir):
    (tf_dir / "terraform.tfvars.example").write_text('vultr_api_key = "..."\n')
    tr.guard_tfvars(tf_dir, CREDENTIAL_KEYS)


def test_guard_tfvars_takes_consumer_credential_keys(tf_dir):
    (tf_dir / "terraform.tfvars").write_text('cf_api_token = "leak"\n')
    tr.guard_tfvars(tf_dir, CREDENTIAL_KEYS)  # not in this consumer's list
    with pytest.raises(tr.RunnerError, match="cf_api_token"):
        tr.guard_tfvars(tf_dir, ("cf_api_token",))


def test_guard_config_refuses_provisioners_and_external_data(tf_dir):
    tr.guard_config(tf_dir)
    (tf_dir / "evil.tf").write_text('resource "null_resource" "x" {\n  provisioner "local-exec" { command = "env" }\n}\n')
    with pytest.raises(tr.RunnerError, match="provisioner"):
        tr.guard_config(tf_dir)
    (tf_dir / "evil.tf").write_text('data "external" "x" { program = ["env"] }\n')
    with pytest.raises(tr.RunnerError, match="external"):
        tr.guard_config(tf_dir)


# --------------------------------------------------------------- clean env

def test_clean_env_holds_exactly_base_plus_tf_vars(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "should-not-leak")
    monkeypatch.setenv("AWS_PROFILE", "nope")
    env = tr.clean_env({"TF_VAR_vultr_api_key": "vk", "TF_VAR_state_passphrase": "pp"})
    assert set(env) == {"PATH", "HOME", "TF_IN_AUTOMATION", "TF_INPUT",
                        "TF_VAR_vultr_api_key", "TF_VAR_state_passphrase"}
    assert env["TF_VAR_state_passphrase"] == "pp" and "OPENAI_API_KEY" not in env


def test_clean_env_refuses_non_tf_var_keys():
    with pytest.raises(tr.RunnerError, match="AWS_PROFILE"):
        tr.clean_env({"AWS_PROFILE": "x", "TF_VAR_ok": "y"})


# ------------------------------------------------------------- facts cache

FAKE_TOFU = '''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TOFU_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
verb = sys.argv[1]
if verb == "show":
    print(os.environ.get("PLAN_JSON", "{}"))
elif verb == "output":
    print(os.environ.get("FAKE_OUTPUTS", "{}"))
elif verb == "plan":
    out = [a.split("=", 1)[1] for a in sys.argv if a.startswith("-out=")]
    if out:
        open(out[0], "w").write("BINARYPLAN")
    print("Plan: 1 to add, 0 to change, 0 to destroy.")
sys.exit(int(os.environ.get("FAKE_RC_" + verb.upper(), "0")))
'''


@pytest.fixture
def fake_tofu(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "tofu"
    exe.write_text(FAKE_TOFU)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return bin_dir


@pytest.fixture
def tofu_log(tmp_path):
    return tmp_path / "tofu.log"


def _env(fake_bin: Path, log: Path, **extra: str) -> dict[str, str]:
    return {"PATH": f"{fake_bin}:{os.environ['PATH']}", "HOME": os.environ["HOME"],
            "TOFU_LOG": str(log), **extra}


def _calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_refresh_facts_caches_only_allowlisted_values_at_0600(tf_dir, fake_tofu, tofu_log, capsys):
    outputs = {"instance_ip": {"sensitive": False, "value": "203.0.113.5"},
               "role": {"sensitive": False, "value": "app"},
               "unlisted_extra": {"sensitive": False, "value": "not-cached"}}
    env = _env(fake_tofu, tofu_log, FAKE_OUTPUTS=json.dumps(outputs))
    out = tr.refresh_facts(env, tf_dir, frozenset({"instance_ip", "role"}))
    assert out == tf_dir / "outputs.json"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text()) == {"instance_ip": "203.0.113.5", "role": "app"}
    assert not (tf_dir / "outputs.json.tmp").exists()
    assert "unlisted_extra" in capsys.readouterr().err  # default-deny is named, not silent


def test_refresh_facts_refuses_a_sensitive_output_even_if_allowlisted(tf_dir, fake_tofu, tofu_log):
    outputs = {"root_password": {"sensitive": True, "value": CANARY}}
    env = _env(fake_tofu, tofu_log, FAKE_OUTPUTS=json.dumps(outputs))
    with pytest.raises(tr.RunnerError) as e:
        tr.refresh_facts(env, tf_dir, frozenset({"root_password"}))
    assert "root_password" in str(e.value) and CANARY not in str(e.value)
    assert not (tf_dir / "outputs.json").exists()


def test_refresh_facts_fails_closed_on_tofu_error(tf_dir, fake_tofu, tofu_log):
    env = _env(fake_tofu, tofu_log, FAKE_RC_OUTPUT="3")
    with pytest.raises(tr.RunnerError, match="exited 3"):
        tr.refresh_facts(env, tf_dir, frozenset({"instance_ip"}))


# -------------------------------------------------------- override parsing

def test_parse_gate_overrides_extracts_pairs_and_leaves_tofu_args():
    rest, ov = tr.parse_gate_overrides(
        ["-compact-warnings", "--allow-protected-destroy", "vultr_instance.app",
         "--allow-protected-destroy", "aws_s3_bucket.restic", "--reason", "burn and rebuild"])
    assert rest == ["-compact-warnings"]
    assert ov == {"vultr_instance.app": "burn and rebuild", "aws_s3_bucket.restic": "burn and rebuild"}


def test_parse_gate_overrides_requires_a_reason_and_values():
    with pytest.raises(tr.RunnerError, match="--reason"):
        tr.parse_gate_overrides(["--allow-protected-destroy", "vultr_instance.app"])
    with pytest.raises(tr.RunnerError, match="needs a value"):
        tr.parse_gate_overrides(["--allow-protected-destroy"])
    assert tr.parse_gate_overrides(["plan-arg"]) == (["plan-arg"], {})


def test_parse_gate_overrides_refuses_a_repeated_reason():
    # Audit attribution must be unambiguous (cross-vendor review finding #2).
    with pytest.raises(tr.RunnerError, match="more than once"):
        tr.parse_gate_overrides(["--allow-protected-destroy", "a.b",
                                 "--reason", "ticket-1", "--reason", "other"])
    with pytest.raises(tr.RunnerError, match="more than once"):
        tr.parse_gate_overrides(["--reason", "", "--reason", "sneaky"])


# ----------------------------------------------------------- verb pipeline

PLAN_DOC = {"resource_changes": [
    {"address": "vultr_instance.app", "change": {"actions": ["delete"]},
     "after": {"password": CANARY}},
]}


def test_run_verb_refuses_anything_but_the_four_verbs(tf_dir):
    for verb in ("state", "show", "output", "console", "refresh"):
        with pytest.raises(tr.RunnerError, match="unreachable"):
            tr.run_verb(verb, [], {}, tf_dir)


def test_apply_runs_the_gated_planfile_pipeline(tf_dir, fake_tofu, tofu_log, capfd):
    seen: list[dict] = []
    env = _env(fake_tofu, tofu_log, PLAN_JSON=json.dumps(PLAN_DOC))
    rc = tr.run_verb("apply", ["-compact-warnings"], env, tf_dir, gate=seen.append)
    assert rc == 0
    calls = _calls(tofu_log)
    assert calls[0] == ["init", "-input=false"]
    assert calls[1][0] == "plan" and "-compact-warnings" in calls[1]
    planfile = [a.split("=", 1)[1] for a in calls[1] if a.startswith("-out=")][0]
    assert calls[2] == ["show", "-json", planfile]
    assert calls[3] == ["apply", "-input=false", planfile]
    assert seen == [PLAN_DOC]                      # the gate got the parsed plan, in-process
    assert not Path(planfile).exists()             # private temp dir cleaned up
    out = capfd.readouterr()
    assert CANARY not in out.out and CANARY not in out.err  # plan JSON never reaches the terminal
    assert "Plan: 1 to add" in out.out             # the human-readable plan still streams


def test_destroy_is_plan_destroy_never_native_destroy(tf_dir, fake_tofu, tofu_log):
    env = _env(fake_tofu, tofu_log, PLAN_JSON=json.dumps(PLAN_DOC))
    assert tr.run_verb("destroy", [], env, tf_dir) == 0
    calls = _calls(tofu_log)
    assert "-destroy" in calls[1] and calls[1][0] == "plan"
    assert all(c[0] != "destroy" for c in calls)


def test_gate_refusal_stops_before_apply_and_names_addresses_only(tf_dir, fake_tofu, tofu_log):
    env = _env(fake_tofu, tofu_log, PLAN_JSON=json.dumps(PLAN_DOC))
    gate = plangate.make_gate(frozenset({"vultr_instance.app"}), log=lambda *_: None)
    with pytest.raises(plangate.ProtectedDestroyError) as e:
        tr.run_verb("apply", [], env, tf_dir, gate=gate)
    assert "vultr_instance.app" in str(e.value) and CANARY not in str(e.value)
    assert all(c[0] != "apply" for c in _calls(tofu_log))


def test_failed_plan_stops_the_pipeline(tf_dir, fake_tofu, tofu_log):
    env = _env(fake_tofu, tofu_log, FAKE_RC_PLAN="1")
    assert tr.run_verb("apply", [], env, tf_dir) == 1
    assert all(c[0] not in ("show", "apply") for c in _calls(tofu_log))


def test_failed_show_fails_closed_without_leaking(tf_dir, fake_tofu, tofu_log):
    env = _env(fake_tofu, tofu_log, FAKE_RC_SHOW="1", PLAN_JSON=json.dumps(PLAN_DOC))
    with pytest.raises(tr.RunnerError, match="exited 1") as e:
        tr.run_verb("apply", [], env, tf_dir)
    assert CANARY not in str(e.value)


def test_init_passes_through(tf_dir, fake_tofu, tofu_log):
    assert tr.run_verb("init", [], _env(fake_tofu, tofu_log), tf_dir) == 0
    assert _calls(tofu_log) == [["init", "-input=false"]]


def test_ensure_init_false_skips_the_plain_init(tf_dir, fake_tofu, tofu_log):
    # For consumers whose init needs -backend-config and runs separately.
    env = _env(fake_tofu, tofu_log, PLAN_JSON=json.dumps(PLAN_DOC))
    assert tr.run_verb("apply", [], env, tf_dir, ensure_init=False) == 0
    assert _calls(tofu_log)[0][0] == "plan"


# ---------------------------------------------------------------- plangate

def test_planned_deletes_includes_replaces():
    doc = {"resource_changes": [
        {"address": "a.b", "change": {"actions": ["delete"]}},
        {"address": "c.d", "change": {"actions": ["create", "delete"]}},   # replace
        {"address": "e.f", "change": {"actions": ["update"]}},
    ]}
    assert plangate.planned_deletes(doc) == ["a.b", "c.d"]


def test_check_plan_allows_unprotected_and_consumes_overrides():
    logged: list[str] = []
    used: list[tuple[str, str]] = []
    doc = {"resource_changes": [
        {"address": "cloudflare_dns_record.app", "change": {"actions": ["delete"]}},
        {"address": "vultr_instance.app", "change": {"actions": ["delete"]}},
    ]}
    plangate.check_plan(doc, frozenset({"vultr_instance.app"}),
                        {"vultr_instance.app": "rebuild"}, log=logged.append,
                        on_override_used=lambda a, r: used.append((a, r)))
    assert any("not protected" in line for line in logged)
    assert any("OVERRIDE consumed" in line for line in logged)
    assert used == [("vultr_instance.app", "rebuild")]


def test_check_plan_refuses_and_sorts_violations():
    doc = {"resource_changes": [
        {"address": "z.z", "change": {"actions": ["delete"]}},
        {"address": "a.a", "change": {"actions": ["delete"]}},
    ]}
    with pytest.raises(plangate.ProtectedDestroyError) as e:
        plangate.check_plan(doc, frozenset({"z.z", "a.a"}), log=lambda *_: None)
    assert e.value.addresses == ["a.a", "z.z"]
