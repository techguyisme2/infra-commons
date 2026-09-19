"""Mechanism tests for hooks/ — the pinned gitleaks fetcher, the staged and
outgoing-range scans, the pre-commit-framework runner and the protected-ref
gate. Hermetic: temp git repos, a FAKE gitleaks that records its argv (exit
status controllable per invocation), a fake pre-commit binary, and a stub
`curl` first on PATH serving a locally built tarball. No network.

What the fakes cannot prove — that the argv is what a real gitleaks accepts —
is covered by one opt-in test that runs only where a gitleaks is on PATH.

Run:  python -m pytest -q tests
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HOOKS = REPO / "hooks"
# The floor interpreter where it is old (bash 3.2 on macOS); any bash elsewhere.
BASH = "/bin/bash" if Path("/bin/bash").exists() else (shutil.which("bash") or "bash")
GIT = shutil.which("git") or "git"
REAL_GITLEAKS = shutil.which("gitleaks")
REAL_TAR = shutil.which("tar") or "tar"
ZERO = "0" * 40
VERSION = re.search(r'^readonly GITLEAKS_VERSION="([^"]+)"$',
                    (HOOKS / "ensure-gitleaks.sh").read_text(), re.M).group(1)

FAKE_GITLEAKS = '''#!/usr/bin/env python3
"""Logs argv, one JSON list per call; call N exits with the Nth value of
FAKE_GITLEAKS_EXITS (comma-separated, default 0). The value "leak" is a
FINDING and exits like the real scanner: with the --exit-code it was given, 1
by default. A number is any other ending: 1 = its fatal error, 137 = killed. FAKE_GITLEAKS_STDERR goes to
stderr as is (the scanner's own log); FAKE_GITLEAKS_ENV_LOG receives what a
git child of the scanner would inherit and resolve, and the file this
process's stderr points at."""
import json, os, subprocess, sys
log = os.environ["FAKE_GITLEAKS_LOG"]
with open(log, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
with open(log) as f:
    n = sum(1 for _ in f)
sys.stderr.write(os.environ.get("FAKE_GITLEAKS_STDERR", ""))
if os.environ.get("FAKE_GITLEAKS_ENV_LOG"):
    def resolved(key):
        return subprocess.run(["git", "config", "--get", key], capture_output=True, text=True).stdout.strip()
    try:
        stderr_file = os.readlink("/proc/self/fd/2")
    except OSError:                                     # no /proc: macOS
        import fcntl
        stderr_file = fcntl.fcntl(2, fcntl.F_GETPATH, b"\\0" * 1024).rstrip(b"\\0").decode()
    seen = {"stderr": stderr_file, "trace": sorted(k for k in os.environ if k.startswith("GIT_TRACE"))}
    seen.update((key, resolved(key)) for key in ("color.ui", "color.diff", "core.abbrev"))
    with open(os.environ["FAKE_GITLEAKS_ENV_LOG"], "a") as f:
        f.write(json.dumps(seen) + "\\n")
exits = [e for e in os.environ.get("FAKE_GITLEAKS_EXITS", "").split(",") if e]
argv = sys.argv[1:]
leak = int(argv[argv.index("--exit-code") + 1]) if "--exit-code" in argv else 1
how = exits[n - 1] if n <= len(exits) else "0"
sys.exit(leak if how == "leak" else int(how))
'''

FAKE_PRECOMMIT = '''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_PRECOMMIT_LOG"], "a") as f:
    f.write(json.dumps({"self": sys.argv[0], "argv": sys.argv[1:], "cwd": os.getcwd(),
                        "SKIP": os.environ.get("SKIP")}) + "\\n")
sys.exit(int(os.environ.get("FAKE_PRECOMMIT_EXIT", "0")))
'''

STUB_CURL = '''#!/usr/bin/env python3
"""Stands in for curl: logs argv, then serves STUB_CURL_TARBALL into the -o
path — or fails the way `curl -f` does when STUB_CURL_FAIL is set."""
import json, os, shutil, sys
argv = sys.argv[1:]
with open(os.environ["STUB_CURL_LOG"], "a") as f:
    f.write(json.dumps(argv) + "\\n")
if os.environ.get("STUB_CURL_FAIL"):
    sys.exit(22)
shutil.copyfile(os.environ["STUB_CURL_TARBALL"], argv[argv.index("-o") + 1])
'''

STUB_TAR = '''#!/usr/bin/env python3
"""Stands in for tar: logs argv, then hands over to the real one."""
import json, os, sys
with open(os.environ["STUB_TAR_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
os.execv(os.environ["STUB_TAR_REAL"], ["tar", *sys.argv[1:]])
'''

STUB_UNAME = '#!/bin/sh\ncase "$1" in -s) echo Plan9 ;; -m) echo mips ;; esac\n'


# ------------------------------------------------------------------ harness

def _exe(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _lines(log: Path) -> list:
    return [json.loads(ln) for ln in log.read_text().splitlines()] if log.exists() else []


class Sandbox:
    """One temp world: a HOME, a PATH-first bin dir for stubs, the logs, and an
    environment built from scratch — nothing of the developer's git config,
    and no GIT_* variable of an enclosing hook, leaks in. The stub curl is
    always first on PATH and FAILS unless a test opts in to being served, so
    no test can reach the network even when the code under test is broken.
    The stub tar beside it only records how the real one was called."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.home = tmp / "home"
        self.bin = tmp / "bin"
        self.home.mkdir()
        self.bin.mkdir()
        self.gitleaks_log = tmp / "gitleaks.log"
        self.precommit_log = tmp / "precommit.log"
        self.curl_log = tmp / "curl.log"
        self.tar_log = tmp / "tar.log"
        self.env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.home),
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
            "FAKE_GITLEAKS_LOG": str(self.gitleaks_log),
            "FAKE_PRECOMMIT_LOG": str(self.precommit_log),
            "STUB_CURL_LOG": str(self.curl_log), "STUB_CURL_FAIL": "1",
            "STUB_TAR_LOG": str(self.tar_log), "STUB_TAR_REAL": REAL_TAR,
        }
        _exe(self.bin / "curl", STUB_CURL)
        _exe(self.bin / "tar", STUB_TAR)

    def git(self, *args: str, cwd: Path, check: bool = True, **env: str):
        return subprocess.run([GIT, *args], cwd=cwd, env={**self.env, **env},
                              capture_output=True, text=True, check=check)

    def new_repo(self, name: str = "repo") -> Path:
        repo = self.tmp / name
        repo.mkdir()
        self.git("init", "-q", "-b", "main", cwd=repo)
        (repo / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
        (repo / ".gitignore").write_text(".tools/\n")
        return Path(os.path.realpath(repo))

    def commit(self, repo: Path, name: str, text: str = "x\n") -> str:
        (repo / name).write_text(text)
        self.git("add", "-A", cwd=repo)
        self.git("commit", "-q", "--no-verify", "-m", f"add {name}", cwd=repo)
        return self.git("rev-parse", "HEAD", cwd=repo).stdout.strip()

    def place_gitleaks(self, tools_root: Path, text: str = FAKE_GITLEAKS) -> Path:
        return _exe(tools_root / "gitleaks" / VERSION / "gitleaks", text)

    def run(self, script: str, *args: str, cwd: Path, stdin: str = "",
            hooks: Path = HOOKS, **env: str):
        return subprocess.run([BASH, str(hooks / script), *args], cwd=cwd, input=stdin,
                              env={**self.env, **env}, capture_output=True, text=True,
                              check=False)


@pytest.fixture
def box(tmp_path):
    return Sandbox(tmp_path)


@pytest.fixture
def repo(box):
    """A repo with two commits and the fake gitleaks already 'installed'."""
    r = box.new_repo()
    box.first = box.commit(r, "a.txt")
    box.second = box.commit(r, "b.txt")
    box.place_gitleaks(r / ".tools")
    return r


def _cfg(repo: Path) -> str:
    return str(repo / ".gitleaks.toml")


def test_every_mechanism_is_executable():
    scripts = sorted(HOOKS.glob("*.sh"))
    assert [s.name for s in scripts] == ["ensure-gitleaks.sh", "gitleaks-outgoing.sh",
                                         "gitleaks-staged.sh", "precommit-framework.sh",
                                         "refgate-run.sh"]
    for s in scripts:
        assert s.stat().st_mode & stat.S_IXUSR, f"{s.name} lost its exec bit"


# The ONLY names each mechanism may take from the environment it is handed.
# Every other UPPERCASE name it expands must be one it assigns itself.
AMBIENT = {
    "ensure-gitleaks.sh": {"BASH_SOURCE"},
    "gitleaks-outgoing.sh": {"BASH_SOURCE", "GIT_CONFIG_PARAMETERS", "GIT_TRACE"},
    "gitleaks-staged.sh": {"BASH_SOURCE", "GIT_CONFIG_PARAMETERS", "GIT_TRACE"},
    "precommit-framework.sh": {"BASH_SOURCE", "PWD"},
    "refgate-run.sh": {"BASH_SOURCE"},
}


def test_mechanisms_read_nothing_from_the_environment_beyond_their_allow_list():
    """Static, so it holds for a skip switch under ANY name — probing guessed
    names (below) cannot promise that."""
    for script in sorted(HOOKS.glob("*.sh")):
        code = "\n".join(ln for ln in script.read_text().splitlines()
                         if not ln.lstrip().startswith("#"))
        assigned = set(re.findall(r"^\s*(?:readonly\s+|local\s+)?([A-Z][A-Z0-9_]*)=", code, re.M))
        expanded = set(re.findall(r"\$\{?[!#]?([A-Z][A-Z0-9_]*)", code))
        assert expanded - assigned == AMBIENT[script.name], script.name


# ----------------------------------------------------------- gitleaks-staged

def test_staged_scans_the_staged_diff_with_the_callers_config(box, repo):
    p = box.run("gitleaks-staged.sh", "--config", _cfg(repo), cwd=repo)
    assert p.returncode == 0, p.stderr
    assert _lines(box.gitleaks_log) == [["git", "--pre-commit", "--staged", "--redact", "--no-banner",
                                         "--no-color", "--exit-code", "42", "--config", _cfg(repo), str(repo)]]


def test_staged_finding_blocks_and_prints_the_consumers_hints(box, repo):
    p = box.run("gitleaks-staged.sh", "--config", _cfg(repo), "--hint", "triage: see the local doc",
                "--hint", "second hint", cwd=repo, FAKE_GITLEAKS_EXITS="leak")
    assert p.returncode == 1
    assert "potential secret in the staged diff" in p.stderr
    assert "triage: see the local doc" in p.stderr and "second hint" in p.stderr


def test_staged_fails_closed_on_every_usage_error_before_scanning(box, repo):
    for args in ([], ["--config"], ["--config", str(repo / "absent.toml")],
                 ["--config", _cfg(repo), "--skip"], ["--config", _cfg(repo), "stray"]):
        p = box.run("gitleaks-staged.sh", *args, cwd=repo)
        assert p.returncode == 2, (args, p.stderr)
    assert _lines(box.gitleaks_log) == []


def test_gates_have_no_skip_variable(box, repo):
    skips = {"SKIP": "1", "SKIP_HOOKS": "1", "GITLEAKS_SKIP": "1", "NO_VERIFY": "1"}
    p = box.run("gitleaks-staged.sh", "--config", _cfg(repo), cwd=repo,
                FAKE_GITLEAKS_EXITS="leak", **skips)
    assert p.returncode == 1
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo,
                stdin=f"refs/heads/main {box.second} refs/heads/main {box.first}\n",
                FAKE_GITLEAKS_EXITS="0,leak", **skips)
    assert p.returncode == 1


def test_the_scanners_git_child_sees_no_trace_variable_and_no_forced_color(box, repo):
    """The real scanner exits 0 when it cannot READ its git child: trace output
    on the child's stderr stops its reader, a colored diff does not parse. Both
    scans pin that environment — over a config file, over `git -c` (which
    reaches a hook as GIT_CONFIG_PARAMETERS) — and keep the caller's other
    settings."""
    colored = box.tmp / "gitconfig-colored"
    colored.write_text("[color]\n\tui = always\n\tdiff = always\n")
    env_log = box.tmp / "scanner-env.log"
    hostile = {"GIT_TRACE": "1", "GIT_TRACE2_EVENT": "1", "GIT_TRACE_PERFORMANCE": "1",
               "GIT_CONFIG_GLOBAL": str(colored),
               "GIT_CONFIG_PARAMETERS": "'core.abbrev=9' 'color.diff=always' 'color.ui=always'",
               "FAKE_GITLEAKS_ENV_LOG": str(env_log)}
    assert box.run("gitleaks-staged.sh", "--config", _cfg(repo), cwd=repo, **hostile).returncode == 0
    assert box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo, **hostile,
                   stdin=f"refs/heads/main {box.second} refs/heads/main {box.first}\n").returncode == 0
    want = {"trace": [], "color.ui": "false", "color.diff": "false", "core.abbrev": "9"}
    assert [{k: v for k, v in seen.items() if k != "stderr"} for seen in _lines(env_log)] == [want, want]


def test_a_scanner_that_logs_an_error_and_exits_zero_is_refused_never_passed(box, repo):
    """What the real scanner does when its git child fails for a cause the
    pinning above cannot enumerate: an ERR line, "no leaks found", exit 0."""
    env_log = box.tmp / "scanner-env.log"
    failed = '9:11AM ERR error="stderr is not empty"\n9:11AM INF no leaks found\n'
    fine = "9:11AM INF 1 commits scanned.\n9:11AM WRN not an ERRor line\n"
    update = f"refs/heads/main {box.second} refs/heads/main {box.first}\n"
    for script, stdin in (("gitleaks-staged.sh", ""), ("gitleaks-outgoing.sh", update)):
        def scan(log: str, exits: str = ""):
            box.gitleaks_log.unlink(missing_ok=True)
            return box.run(script, "--config", _cfg(repo), cwd=repo, stdin=stdin,
                           FAKE_GITLEAKS_ENV_LOG=str(env_log),
                           FAKE_GITLEAKS_STDERR=log, FAKE_GITLEAKS_EXITS=exits)
        p = scan(failed)
        assert p.returncode == 3, (script, p.stderr)
        assert 'ERR error="stderr is not empty"' in p.stderr          # the log is replayed
        assert "refusing to pass without a full scan" in p.stderr
        p = scan(fine)
        assert p.returncode == 0 and "1 commits scanned." in p.stderr, (script, p.stderr)
        assert scan(failed, exits="leak").returncode == 1             # a finding stays a finding
    captured = [Path(seen["stderr"]) for seen in _lines(env_log)]
    assert len(captured) == 6 and all(c.is_absolute() for c in captured)    # a file, each time
    assert not any(c.exists() for c in captured)                      # ...and removed on every exit


def test_tools_root_is_passed_through_to_the_fetcher(box):
    r = box.new_repo()
    box.commit(r, "a.txt")
    elsewhere = box.tmp / "shared-tools"
    box.place_gitleaks(elsewhere)
    p = box.run("gitleaks-staged.sh", "--config", _cfg(r), "--tools-root", str(elsewhere), cwd=r)
    assert p.returncode == 0, p.stderr
    assert len(_lines(box.gitleaks_log)) == 1 and not (r / ".tools").exists()


# --------------------------------------------------------- gitleaks-outgoing

def _log_opts(box) -> list[str]:
    calls = _lines(box.gitleaks_log)
    for c in calls:
        assert c[:1] == ["git"] and "--redact" in c and "--staged" not in c
    return [c[c.index("--log-opts") + 1] for c in calls]


def test_outgoing_update_scans_remote_to_local(box, repo):
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo,
                stdin=f"refs/heads/main {box.second} refs/heads/main {box.first}\n")
    assert p.returncode == 0, p.stderr
    assert _lines(box.gitleaks_log) == [["git", "--redact", "--no-banner", "--no-color",
                                         "--exit-code", "42", "--config", _cfg(repo),
                                         "--log-opts", f"{box.first}..{box.second}", str(repo)]]


def test_outgoing_new_branch_scans_everything_not_on_a_remote(box, repo):
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo,
                stdin=f"refs/heads/topic {box.second} refs/heads/topic {ZERO}\n")
    assert p.returncode == 0, p.stderr
    assert _log_opts(box) == [f"{box.second} --not --remotes"]


def test_outgoing_branch_deletion_is_skipped(box, repo):
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo,
                stdin=f"(delete) {ZERO} refs/heads/topic {box.first}\n")
    assert p.returncode == 0, p.stderr
    assert _lines(box.gitleaks_log) == []


def test_outgoing_first_ref_leaks_later_refs_clean_still_fails_and_scans_all(box, repo):
    stdin = (f"refs/heads/one {box.second} refs/heads/one {box.first}\n"
             f"refs/heads/gone {ZERO} refs/heads/gone {box.first}\n"
             f"refs/heads/two {box.second} refs/heads/two {ZERO}\n"
             f"refs/heads/three {box.first} refs/heads/three {ZERO}\n")
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), "--hint", "triage: local doc",
                cwd=repo, stdin=stdin, FAKE_GITLEAKS_EXITS="leak,0,0")
    assert p.returncode == 1
    assert _log_opts(box) == [f"{box.first}..{box.second}", f"{box.second} --not --remotes",
                              f"{box.first} --not --remotes"]
    assert "outgoing range" in p.stderr and "triage: local doc" in p.stderr


def test_outgoing_last_ref_leaks_fails_too(box, repo):
    stdin = (f"refs/heads/one {box.second} refs/heads/one {box.first}\n"
             f"refs/heads/two {box.second} refs/heads/two {ZERO}\n")
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo, stdin=stdin,
                FAKE_GITLEAKS_EXITS="0,leak")
    assert p.returncode == 1 and len(_log_opts(box)) == 2


def test_a_scanner_that_does_not_complete_is_never_reported_as_a_finding(box, repo):
    """The real scanner exits 1 for a finding BY DEFAULT — and 1 for its own
    fatal error (an unparsable config). Read by status alone, a crash says "a
    secret was found", and a consumer that rotates credentials on a finding
    acts on a lie. Both scans ask for a distinctive finding status; every other
    ending — fatal error, killed — is exit 3, with no finding text and no hint."""
    update = f"refs/heads/main {box.second} refs/heads/main {box.first}\n"
    for script, stdin, words in (("gitleaks-staged.sh", "", "potential secret in the staged diff"),
                                 ("gitleaks-outgoing.sh", update, "potential secret in the outgoing range")):
        def scan(exits: str):
            box.gitleaks_log.unlink(missing_ok=True)
            return box.run(script, "--config", _cfg(repo), "--hint", "triage: local doc", cwd=repo,
                           stdin=stdin, FAKE_GITLEAKS_EXITS=exits)
        for ending in ("1", "2", "137", "143"):                # fatal error, usage error, SIGKILL, SIGTERM
            p = scan(ending)
            assert p.returncode == 3, (script, ending, p.stderr)
            assert "did not complete" in p.stderr and f"exit {ending}" in p.stderr
            assert words not in p.stderr and "triage: local doc" not in p.stderr
        p = scan("leak")                                       # the control: a real finding is still exit 1
        assert p.returncode == 1 and words in p.stderr and "triage: local doc" in p.stderr
        [call] = _lines(box.gitleaks_log)
        asked = call[call.index("--exit-code") + 1]
        assert asked not in ("0", "1", "2", "3") and int(asked) < 126, asked   # never the fatal status, never a signal


def test_outgoing_a_crash_on_a_later_range_is_not_a_finding_either(box, repo):
    stdin = (f"refs/heads/one {box.second} refs/heads/one {box.first}\n"
             f"refs/heads/two {box.second} refs/heads/two {ZERO}\n")
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo, stdin=stdin,
                FAKE_GITLEAKS_EXITS="0,1")
    assert p.returncode == 3 and "did not complete" in p.stderr
    assert "potential secret" not in p.stderr


def test_outgoing_empty_stdin_passes_without_a_scanner(box):
    r = box.new_repo()          # no gitleaks installed, curl would fail
    box.commit(r, "a.txt")
    for stdin in ("", "\n"):    # "\n" is what `printf '%s\n' "$empty"` feeds
        p = box.run("gitleaks-outgoing.sh", "--config", _cfg(r), cwd=r, stdin=stdin)
        assert p.returncode == 0, p.stderr
    assert _lines(box.curl_log) == []


def test_outgoing_last_line_without_a_newline_is_still_scanned(box, repo):
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo,
                stdin=f"refs/heads/main {box.second} refs/heads/main {box.first}")
    assert p.returncode == 0 and _log_opts(box) == [f"{box.first}..{box.second}"]


def test_outgoing_unparsable_line_refuses_the_whole_push_unscanned(box, repo):
    good = f"refs/heads/main {box.second} refs/heads/main {box.first}\n"
    for bad in (f"refs/heads/x {box.second} refs/heads/x\n",                 # 3 fields
                f"refs/heads/x {box.second} refs/heads/x {ZERO} extra\n",    # 5 fields
                f"refs/heads/x not-a-sha refs/heads/x {ZERO}\n",
                f"refs/heads/x {box.second} refs/heads/x {ZERO[:-1]}\n",     # 39 digits
                f"refs/heads/x\t{box.second}\trefs/heads/x\t{ZERO}\n"):      # tabs
        p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo, stdin=good + bad)
        assert p.returncode == 2, (bad, p.stderr)
        assert "unparsable pre-push line" in p.stderr
    assert _lines(box.gitleaks_log) == []


def test_outgoing_fails_closed_without_a_config(box, repo):
    stdin = f"refs/heads/main {box.second} refs/heads/main {box.first}\n"
    for args in ([], ["--config", str(repo / "absent.toml")], ["--config", _cfg(repo), "--force"]):
        assert box.run("gitleaks-outgoing.sh", *args, cwd=repo, stdin=stdin).returncode == 2
    assert _lines(box.gitleaks_log) == []


def test_outgoing_update_from_a_commit_this_clone_lacks_refuses(box, repo):
    unknown = hashlib.sha1(b"not an object here", usedforsecurity=False).hexdigest()
    a_tree = box.git("rev-parse", "HEAD^{tree}", cwd=repo).stdout.strip()   # here, but no commit
    for remote_sha in (unknown, a_tree):
        p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo,
                    stdin=f"refs/heads/main {box.second} refs/heads/main {remote_sha}\n")
        assert p.returncode == 3 and "git fetch" in p.stderr, remote_sha
    assert _lines(box.gitleaks_log) == []


def test_sha256_object_names_are_accepted(box, repo):
    """64-digit names (sha256 repositories) parse; their zero is 64 zeros."""
    p = box.run("gitleaks-outgoing.sh", "--config", _cfg(repo), cwd=repo,
                stdin=f"(delete) {'0' * 64} refs/heads/topic {'a' * 64}\n")
    assert p.returncode == 0, p.stderr


def test_a_download_failure_makes_both_gates_fail_never_pass(box):
    r = box.new_repo()          # nothing installed: the gates must fetch
    first = box.commit(r, "a.txt")
    staged = box.run("gitleaks-staged.sh", "--config", _cfg(r), cwd=r)
    outgoing = box.run("gitleaks-outgoing.sh", "--config", _cfg(r), cwd=r,
                       stdin=f"refs/heads/main {first} refs/heads/main {ZERO}\n")
    for p in (staged, outgoing):
        assert p.returncode == 3, p.stderr
        assert "Download failed" in p.stderr and "refusing to pass without a scan" in p.stderr
    assert len(_lines(box.curl_log)) == 2 and not (r / ".tools").exists()


# ----------------------------------------------------------- ensure-gitleaks

def _tarball(path: Path, payload: bytes) -> str:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in (("gitleaks", payload), ("README.md", b"never installed\n")):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            tar.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _installed(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()) if root.exists() else []


def test_fetcher_existing_binary_means_no_download(box, repo):
    p = box.run("ensure-gitleaks.sh", cwd=repo)
    assert p.returncode == 0, p.stderr
    assert p.stdout == f"{repo}/.tools/gitleaks/{VERSION}/gitleaks\n"
    assert _lines(box.curl_log) == []


def test_fetcher_checksum_mismatch_refuses_and_installs_nothing(box):
    r = box.new_repo()
    local_sha = _tarball(box.tmp / "local.tar.gz", b"#!/bin/sh\necho not the pinned build\n")
    # The pins cannot be overridden from the environment either.
    override = {f"SHA256_{plat}": local_sha
                for plat in ("DARWIN_ARM64", "DARWIN_X64", "LINUX_X64", "LINUX_ARM64")}
    p = box.run("ensure-gitleaks.sh", cwd=r, STUB_CURL_FAIL="",
                STUB_CURL_TARBALL=str(box.tmp / "local.tar.gz"), GITLEAKS_VERSION="0.0.0", **override)
    assert p.returncode == 3 and "Checksum mismatch" in p.stderr and p.stdout == ""
    assert _installed(r / ".tools") == []
    assert _lines(box.tar_log) == []        # verified BEFORE extraction: tar never saw it
    (url,) = [a for a in _lines(box.curl_log)[0] if a.startswith("https://")]
    assert url.startswith(f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_")


def test_fetcher_unsupported_platform_refuses(box):
    r = box.new_repo()
    _exe(box.bin / "uname", STUB_UNAME)
    p = box.run("ensure-gitleaks.sh", cwd=r)
    assert p.returncode == 2 and "Unsupported platform: Plan9/mips" in p.stderr
    assert _lines(box.curl_log) == [] and _installed(r / ".tools") == []


def test_fetcher_download_failure_refuses(box):
    r = box.new_repo()
    p = box.run("ensure-gitleaks.sh", cwd=r)
    assert p.returncode == 4 and p.stdout == "" and _installed(r / ".tools") == []


def test_fetcher_usage_errors(box, tmp_path):
    r = box.new_repo()
    assert box.run("ensure-gitleaks.sh", "--nope", cwd=r).returncode == 1
    assert box.run("ensure-gitleaks.sh", "--tools-root", cwd=r).returncode == 1
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    p = box.run("ensure-gitleaks.sh", cwd=outside, GIT_CEILING_DIRECTORIES=str(tmp_path))
    assert p.returncode == 1 and "not inside a git work tree" in p.stderr


def test_fetcher_verified_tarball_installs_only_the_binary(box):
    """The success path. The shipped script has no pin override (asserted
    above), so this runs a COPY whose four pins are rewritten to the local
    tarball's sha256 — everything else is the shipped text."""
    r = box.new_repo()
    payload = b"#!/bin/sh\necho locally built stand-in\n"
    local_sha = _tarball(box.tmp / "local.tar.gz", payload)
    patched = box.tmp / "patched-hooks"
    patched.mkdir()
    text, n = re.subn(r'^(readonly SHA256_\w+=)"[0-9a-f]{64}"$', rf'\1"{local_sha}"',
                      (HOOKS / "ensure-gitleaks.sh").read_text(), flags=re.M)
    assert n == 4
    (patched / "ensure-gitleaks.sh").write_text(text)
    root = box.tmp / "tools"
    leftover = root / "gitleaks" / VERSION / "gitleaks"
    leftover.parent.mkdir(parents=True)
    leftover.write_text("an interrupted install: not executable, never trusted\n")
    leftover.chmod(0o644)
    for _ in range(2):          # the second run finds the binary: no second download
        p = box.run("ensure-gitleaks.sh", "--tools-root", str(root), cwd=r, hooks=patched,
                    STUB_CURL_FAIL="", STUB_CURL_TARBALL=str(box.tmp / "local.tar.gz"))
        assert p.returncode == 0, p.stderr
        assert p.stdout == f"{root}/gitleaks/{VERSION}/gitleaks\n"
    assert len(_lines(box.curl_log)) == 1
    assert "-fsSL" in _lines(box.curl_log)[0]           # -f: an HTTP error page is a failure
    (tar_call,) = _lines(box.tar_log)
    assert tar_call[-1] == "gitleaks"                   # the one member, nothing else
    assert _installed(root) == [f"gitleaks/{VERSION}/gitleaks"]
    binary = root / "gitleaks" / VERSION / "gitleaks"
    assert binary.read_bytes() == payload and stat.S_IMODE(binary.stat().st_mode) == 0o755


# ------------------------------------------------------- precommit-framework

@pytest.fixture
def pc_config(repo):
    cfg = repo / ".pre-commit-config.yaml"
    cfg.write_text("repos: []\n")
    return str(cfg)


def test_framework_first_resolvable_candidate_wins_in_order(box, repo, pc_config):
    venv = _exe(repo / "venv" / "bin" / "pre-commit", FAKE_PRECOMMIT)
    _exe(box.bin / "pre-commit", FAKE_PRECOMMIT)
    sub = repo / "sub"
    sub.mkdir()
    p = box.run("precommit-framework.sh", "--config", pc_config, "--bin", str(repo / "absent"),
                "--bin", str(venv), "--bin", "pre-commit", cwd=sub)
    assert p.returncode == 0, p.stderr
    assert _lines(box.precommit_log) == [{"self": str(venv), "argv": ["run", "--config", pc_config],
                                          "cwd": str(repo), "SKIP": None}]


def test_framework_default_candidate_is_pre_commit_on_path(box, repo, pc_config):
    _exe(box.bin / "pre-commit", FAKE_PRECOMMIT)
    assert box.run("precommit-framework.sh", "--config", pc_config, cwd=repo).returncode == 0
    assert _lines(box.precommit_log)[0]["self"] == str(box.bin / "pre-commit")


def test_framework_never_sees_its_own_skip_variable(box, repo, pc_config):
    """The framework honours SKIP=<hook id>,...; passed through, it would be a
    skip switch that no shim controls."""
    _exe(box.bin / "pre-commit", FAKE_PRECOMMIT)
    assert box.run("precommit-framework.sh", "--config", pc_config, cwd=repo,
                   SKIP="ruff,every-other-hook").returncode == 0
    (call,) = _lines(box.precommit_log)
    assert call["SKIP"] is None


def test_framework_relative_config_survives_the_move_to_the_repo_root(box, repo, pc_config):
    _exe(box.bin / "pre-commit", FAKE_PRECOMMIT)
    sub = repo / "sub"
    sub.mkdir()
    p = box.run("precommit-framework.sh", "--config", "../.pre-commit-config.yaml", cwd=sub)
    assert p.returncode == 0, p.stderr
    (call,) = _lines(box.precommit_log)
    given = call["argv"][call["argv"].index("--config") + 1]
    assert os.path.isabs(given) and os.path.samefile(given, pc_config)


def test_framework_missing_binary_fails_closed_with_the_install_hint(box, repo, pc_config):
    p = box.run("precommit-framework.sh", "--config", pc_config, "--bin", str(repo / "absent"),
                "--bin", "no-such-command-on-any-path", "--install-hint", "install: the dev deps",
                cwd=repo)
    assert p.returncode == 3
    assert "refusing to pass without it" in p.stderr and "install: the dev deps" in p.stderr


def test_framework_failure_blocks(box, repo, pc_config):
    _exe(box.bin / "pre-commit", FAKE_PRECOMMIT)
    for rc in ("1", "3"):
        p = box.run("precommit-framework.sh", "--config", pc_config, cwd=repo, FAKE_PRECOMMIT_EXIT=rc)
        assert p.returncode == 1 and f"(exit {rc})" in p.stderr


def test_framework_usage_errors_fail_closed(box, repo, pc_config):
    _exe(box.bin / "pre-commit", FAKE_PRECOMMIT)
    for args in ([], ["--config", str(repo / "absent.yaml")], ["--config", pc_config, "--all-files"]):
        assert box.run("precommit-framework.sh", *args, cwd=repo).returncode == 2
    assert _lines(box.precommit_log) == []


# -------------------------------------------------------------- refgate-run

def _gate(box, repo, stdin: str, *refs: str, rc: int = 0):
    marker = box.tmp / "ran"
    cmd = ["/bin/sh", "-c", f'printf "%s|" "$@" >> "{marker}"; echo >> "{marker}"; exit {rc}',
           "gate", "one arg", "two"]
    flags = [x for r in (refs or ("refs/heads/main",)) for x in ("--ref", r)]
    p = box.run("refgate-run.sh", *flags, "--", *cmd, cwd=repo, stdin=stdin)
    return p, (marker.read_text().splitlines() if marker.exists() else [])


def test_refgate_protected_ref_updated_runs_the_command_and_returns_its_status(box, repo):
    p, ran = _gate(box, repo, f"refs/heads/topic {box.second} refs/heads/main {box.first}\n", rc=7)
    assert p.returncode == 7 and ran == ["one arg|two|"]
    p, ran = _gate(box, repo, f"refs/heads/main {box.second} refs/heads/main {ZERO}\n")
    assert p.returncode == 0 and len(ran) == 2


def test_refgate_last_line_without_a_newline_still_counts(box, repo):
    p, ran = _gate(box, repo, f"refs/heads/main {box.second} refs/heads/main {box.first}", rc=7)
    assert p.returncode == 7 and len(ran) == 1


def test_refgate_other_ref_does_not_run(box, repo):
    stdin = (f"refs/heads/main {box.second} refs/heads/topic {box.first}\n"      # LOCAL main only
             f"refs/heads/x {box.second} refs/heads/main-backup {ZERO}\n"
             f"refs/tags/main {box.second} refs/tags/main {ZERO}\n")
    p, ran = _gate(box, repo, stdin, rc=7)
    assert p.returncode == 0 and ran == []


def test_refgate_deleting_the_protected_ref_does_not_run(box, repo):
    p, ran = _gate(box, repo, f"(delete) {ZERO} refs/heads/main {box.first}\n", rc=7)
    assert p.returncode == 0 and ran == []


def test_refgate_protected_and_unprotected_in_one_push_runs_once(box, repo):
    stdin = (f"refs/heads/topic {box.second} refs/heads/topic {ZERO}\n"
             f"refs/heads/main {box.second} refs/heads/main {box.first}\n"
             f"refs/heads/release {box.second} refs/heads/release {box.first}\n")
    p, ran = _gate(box, repo, stdin, "refs/heads/main", "refs/heads/release")
    assert p.returncode == 0 and len(ran) == 1


def test_refgate_empty_stdin_does_not_run(box, repo):
    for stdin in ("", "\n"):
        p, ran = _gate(box, repo, stdin, rc=7)
        assert p.returncode == 0 and ran == []


def test_refgate_fails_closed_before_the_command_runs(box, repo):
    good = f"refs/heads/main {box.second} refs/heads/main {box.first}\n"
    p, ran = _gate(box, repo, good + "refs/heads/main garbage\n")
    assert p.returncode == 2 and ran == [] and "unparsable pre-push line" in p.stderr
    for args in (["--", "/bin/sh", "-c", "exit 0"],                      # no --ref
                 ["--ref", "refs/heads/main"],                           # no command
                 ["--ref", "refs/heads/main", "--"],
                 ["--ref", "refs/heads/main", "--skip", "--", "/bin/sh", "-c", "exit 0"]):
        assert box.run("refgate-run.sh", *args, cwd=repo, stdin=good).returncode == 2, args


# ------------------------------------- the documented shim, through real git

def _shim_blocks() -> dict[str, str]:
    text = (HOOKS / "README.md").read_text()
    blocks = dict(re.findall(r"<!-- shim:([\w-]+) -->\n```bash\n(.*?)```", text, re.S))
    assert sorted(blocks) == ["pre-commit", "pre-push", "preamble"]
    return blocks


@pytest.fixture
def consumer(box):
    """A consumer repo whose hooks are EXACTLY the README's shim blocks, a
    scratch commons checkout under the sandbox HOME (hooks/ copied from this
    working tree, committed and tagged there) and a local bare remote."""
    commons = box.home / "infra-commons"
    commons.mkdir()
    box.git("init", "-q", "-b", "main", cwd=commons)
    shutil.copytree(HOOKS, commons / "hooks")
    box.git("add", "-A", cwd=commons)
    box.git("commit", "-q", "-m", "hooks", cwd=commons)
    box.git("tag", "v9.9.9", cwd=commons)
    box.commons = commons

    r = box.new_repo("consumer")
    blocks = _shim_blocks()
    for hook in ("pre-commit", "pre-push"):
        _exe(r / ".githooks" / hook, blocks["preamble"] + "\n" + blocks[hook])
    box.gate_log = box.tmp / "gate.log"
    _exe(r / "scripts" / "test-gate.sh", f'#!/bin/sh\necho ran >> "{box.gate_log}"\n')
    (r / "infra-commons.pin").write_text("v9.9.9\n# posture notes follow the ref\n")
    box.git("config", "core.hooksPath", ".githooks", cwd=r)
    box.place_gitleaks(r / ".tools")
    box.git("init", "-q", "--bare", str(box.tmp / "remote.git"), cwd=box.tmp)
    box.git("remote", "add", "origin", str(box.tmp / "remote.git"), cwd=r)
    box.git("add", "-A", cwd=r)
    box.git("commit", "-q", "-m", "base", cwd=r)
    box.gitleaks_log.unlink()                      # the base commit's own scan
    return r


def _remote_has(box, ref: str) -> bool:
    return box.git("rev-parse", "--verify", "--quiet", ref, cwd=box.tmp / "remote.git",
                   check=False).returncode == 0


def test_shim_commit_and_push_through_real_git(box, consumer):
    # `commit -a` from a subdirectory: git hands the hook an absolute
    # GIT_INDEX_FILE for a temporary index — the pin check must not carry it
    # into the commons checkout, the staged scan must keep it.
    (consumer / "scripts" / "note.txt").write_text("one\n")
    box.git("add", "-A", cwd=consumer)
    box.git("commit", "-q", "-m", "note", cwd=consumer)
    (consumer / "scripts" / "note.txt").write_text("two\n")
    p = box.git("commit", "-q", "-a", "-m", "edit", cwd=consumer / "scripts", check=False)
    assert p.returncode == 0, p.stderr
    assert [c[:3] for c in _lines(box.gitleaks_log)] == [["git", "--pre-commit", "--staged"]] * 2

    box.gitleaks_log.unlink()
    head = box.git("rev-parse", "HEAD", cwd=consumer).stdout.strip()
    p = box.git("push", "-q", "origin", "main", "main:topic", cwd=consumer, check=False)
    assert p.returncode == 0, p.stderr
    assert sorted(_log_opts(box)) == [f"{head} --not --remotes"] * 2
    assert box.gate_log.read_text().splitlines() == ["ran"]       # once, for main
    assert _remote_has(box, "refs/heads/main") and _remote_has(box, "refs/heads/topic")

    # An update that leaks is refused and leaves the remote where it was;
    # a push that does not touch the protected ref never runs the gate.
    box.commit(consumer, "more.txt")
    p = box.git("push", "-q", "origin", "main:topic", cwd=consumer, check=False,
                FAKE_GITLEAKS_EXITS="0,0,leak")
    assert p.returncode != 0
    assert _log_opts(box)[-1] == f"{head}..{box.git('rev-parse', 'HEAD', cwd=consumer).stdout.strip()}"
    assert box.git("rev-parse", "refs/heads/topic", cwd=box.tmp / "remote.git").stdout.strip() == head
    assert box.gate_log.read_text().splitlines() == ["ran"]


def test_shim_works_from_a_linked_worktree(box, consumer):
    """git exports GIT_DIR to hooks there; the default tools root is per work tree."""
    wt = box.tmp / "linked"
    box.git("worktree", "add", "-q", "-b", "side", str(wt), cwd=consumer)
    box.place_gitleaks(wt / ".tools")
    (wt / "w.txt").write_text("x\n")
    box.git("add", "-A", cwd=wt)
    p = box.git("commit", "-q", "-m", "from a linked worktree", cwd=wt, check=False)
    assert p.returncode == 0, p.stderr
    (call,) = _lines(box.gitleaks_log)
    assert call[:3] == ["git", "--pre-commit", "--staged"] and call[-1] == os.path.realpath(wt)
    p = box.git("push", "-q", "origin", "side", cwd=wt, check=False)
    assert p.returncode == 0, p.stderr
    assert len(_lines(box.gitleaks_log)) == 2 and not box.gate_log.exists()


def test_shim_refuses_an_off_pin_checkout_before_any_mechanism_runs(box, consumer):
    def refused(why: str, **env: str):
        (consumer / "f.txt").write_text(why)
        box.git("add", "-A", cwd=consumer)
        p = box.git("commit", "-q", "-m", why, cwd=consumer, check=False, **env)
        assert p.returncode != 0 and "REFUSING" in p.stderr, (why, p.stderr)
        assert not box.gitleaks_log.exists(), why
        return p.stderr

    script = box.commons / "hooks" / "refgate-run.sh"
    original = script.read_text()
    script.write_text(original + "# edited\n")
    assert "modified or untracked" in refused("modified file under hooks/")
    script.write_text(original)

    (box.commons / "hooks" / "extra.sh").write_text("#!/bin/sh\n")
    assert "modified or untracked" in refused("untracked file under hooks/")
    hiding = box.tmp / "gitconfig-hides-untracked"
    hiding.write_text("[status]\n\tshowUntrackedFiles = no\n")
    assert "modified or untracked" in refused("untracked file, hidden by the user's git config",
                                              GIT_CONFIG_GLOBAL=str(hiding))
    (box.commons / "hooks" / "extra.sh").unlink()

    script.write_text(original + "# a later release\n")
    box.git("commit", "-q", "-a", "-m", "hooks change", cwd=box.commons)
    assert "differs from the pinned ref v9.9.9" in refused("HEAD's hooks/ moved past the pin")

    (consumer / "infra-commons.pin").write_text("v0.0.0-absent\n")
    assert "pinned ref v0.0.0-absent not found" in refused("unknown ref")

    shutil.move(str(box.commons), str(box.home / "elsewhere"))
    assert "no commons checkout" in refused("missing checkout")


def test_shim_accepts_a_newer_head_whose_hooks_tree_is_unchanged(box, consumer):
    (box.commons / "README.md").write_text("docs moved HEAD; hooks/ did not\n")
    box.git("add", "-A", cwd=box.commons)
    box.git("commit", "-q", "-m", "docs", cwd=box.commons)
    (consumer / "f.txt").write_text("x\n")
    box.git("add", "-A", cwd=consumer)
    p = box.git("commit", "-q", "-m", "ok", cwd=consumer, check=False)
    assert p.returncode == 0, p.stderr
    assert len(_lines(box.gitleaks_log)) == 1


# ------------------------------------------------- opt-in: a real gitleaks

@pytest.mark.skipif(REAL_GITLEAKS is None, reason="no gitleaks on PATH; the fake covers the contract")
def test_real_gitleaks_accepts_the_argv_and_catches_a_runtime_assembled_secret(box):
    """The fakes prove WHAT is passed; this proves a real binary accepts it.
    The secret-shaped string is assembled here so no tracked file holds one."""
    token = "gh" + "p_" + hashlib.sha256(b"fixture, not a credential").hexdigest()[:36]
    r = box.new_repo()
    base = box.commit(r, "a.txt")
    bin_dir = r / ".tools" / "gitleaks" / VERSION
    bin_dir.mkdir(parents=True)
    os.symlink(REAL_GITLEAKS, bin_dir / "gitleaks")

    # A real scanner exits 0 when it cannot read its git child, so the leak
    # must be caught under each of these too — and a clean scan must stay 0.
    colored = box.tmp / "gitconfig-colored"
    colored.write_text("[color]\n\tui = always\n\tdiff = always\n")
    perturbed = ({}, {"GIT_TRACE": "1"}, {"GIT_TRACE2": "1"}, {"GIT_CONFIG_GLOBAL": str(colored)},
                 {"GIT_CONFIG_PARAMETERS": "'color.diff=always'"})
    # ...and under a cause the mechanisms do not neutralize (the child still
    # writes to stderr) exit 0 is never the answer: a finding or a refusal.
    tracing = box.tmp / "gitconfig-trace2"
    tracing.write_text("[trace2]\n\tnormalTarget = true\n")

    assert box.run("gitleaks-staged.sh", "--config", _cfg(r), cwd=r).returncode == 0
    (r / "leak.txt").write_text(f"token = {token}\n")
    box.git("add", "leak.txt", cwd=r)
    for env in perturbed:
        p = box.run("gitleaks-staged.sh", "--config", _cfg(r), cwd=r, **env)
        assert p.returncode == 1 and token not in p.stdout + p.stderr, env
    p = box.run("gitleaks-staged.sh", "--config", _cfg(r), cwd=r, GIT_CONFIG_GLOBAL=str(tracing))
    assert p.returncode in (1, 3) and token not in p.stdout + p.stderr

    box.git("commit", "-q", "--no-verify", "-m", "leak", cwd=r)
    leak = box.git("rev-parse", "HEAD", cwd=r).stdout.strip()
    clean = box.commit(r, "c.txt")
    for stdin, want in ((f"refs/heads/main {leak} refs/heads/main {base}\n", 1),
                        (f"refs/heads/topic {clean} refs/heads/topic {ZERO}\n", 1),
                        (f"refs/heads/main {clean} refs/heads/main {leak}\n", 0)):
        for env in perturbed:
            p = box.run("gitleaks-outgoing.sh", "--config", _cfg(r), cwd=r, stdin=stdin, **env)
            assert p.returncode == want, (stdin, env, p.stdout, p.stderr)
            assert token not in p.stdout + p.stderr
        p = box.run("gitleaks-outgoing.sh", "--config", _cfg(r), cwd=r, stdin=stdin,
                    GIT_CONFIG_GLOBAL=str(tracing))
        assert p.returncode in (1, 3) and token not in p.stdout + p.stderr, stdin
