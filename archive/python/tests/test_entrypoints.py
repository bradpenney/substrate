"""The main() dispatchers and the last uncovered branches.

Entry points matter more than their line count suggests: main() is where a
crashing check must not hide the others, where an exit code decides whether
OnFailure fires, and where a missing SSH key must fail with an instruction
rather than a traceback.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load(filename, name):
    spec = importlib.util.spec_from_file_location(name, REPO / filename)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


# ------------------------------------------------------------- posture-check


@pytest.fixture
def pc(monkeypatch):
    m = _load("posture-check.py", "pc_main")
    m.failures.clear()
    m.notes.clear()
    monkeypatch.setattr(m, "_find_kubectl", lambda: "/usr/bin/kubectl")
    return m


def _silence_all_checks(pc, monkeypatch, raiser=None):
    for name in dir(pc):
        if name.startswith("check_"):
            fn = raiser if raiser and name == "check_flux" else (lambda: None)
            monkeypatch.setattr(pc, name, fn)


def test_main_returns_zero_when_every_invariant_holds(pc, monkeypatch):
    _silence_all_checks(pc, monkeypatch)
    monkeypatch.setattr(pc, "notes", ["ok"], raising=False)
    assert pc.main() == 0


def test_main_returns_nonzero_when_an_invariant_is_broken(pc, monkeypatch):
    """The exit code is what fires OnFailure and sends the notification."""
    _silence_all_checks(pc, monkeypatch)

    def boom():
        pc.failures.append("something is wrong")

    monkeypatch.setattr(pc, "check_flux", boom)
    assert pc.main() == 1


def test_a_crashing_check_does_not_hide_the_others(pc, monkeypatch):
    """A check that raises must be recorded and the run must continue —
    otherwise one bug silences every remaining invariant."""
    ran = []
    for name in dir(pc):
        if name.startswith("check_"):
            monkeypatch.setattr(pc, name, lambda n=name: ran.append(n))

    def raiser():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(pc, "check_flux", raiser)
    rc = pc.main()
    assert rc == 1
    assert any("kaboom" in f for f in pc.failures), pc.failures
    assert len(ran) >= 5, "later checks did not run after the exception"


# ---------------------------------------------------------------- siteconfig


def test_ssh_key_from_the_environment_is_used_verbatim(monkeypatch):
    monkeypatch.setenv("HOMELAB_SSH_PUBLIC_KEY", "ssh-ed25519 AAAAINLINE test@x")
    sc = _load("siteconfig.py", "sc_key")
    assert "AAAAINLINE" in sc.resolve_ssh_public_key()


def test_ssh_key_read_from_a_file_when_pointed_at_one(monkeypatch, tmp_path):
    kf = tmp_path / "id.pub"
    kf.write_text("ssh-ed25519 AAAAFROMFILE test@x\n")
    monkeypatch.delenv("HOMELAB_SSH_PUBLIC_KEY", raising=False)
    monkeypatch.setenv("HOMELAB_SSH_PUBLIC_KEY_FILE", str(kf))
    sc = _load("siteconfig.py", "sc_key_file")
    assert "AAAAFROMFILE" in sc.resolve_ssh_public_key()


def test_missing_ssh_key_fails_with_an_instruction_not_a_traceback(
    monkeypatch, tmp_path
):
    """This is what CI hit: a runner has no ~/.ssh/id_ed25519.pub. The message
    has to say how to fix it."""
    monkeypatch.delenv("HOMELAB_SSH_PUBLIC_KEY", raising=False)
    monkeypatch.setenv("HOMELAB_SSH_PUBLIC_KEY_FILE", str(tmp_path / "absent.pub"))
    sc = _load("siteconfig.py", "sc_key_missing")
    with pytest.raises(SystemExit) as e:
        sc.resolve_ssh_public_key()
    assert "ssh-keygen" in str(e.value)


# ---------------------------------------------------------------- deploy-cplb


def test_cplb_main_dry_run_does_not_touch_a_host(monkeypatch, capsys):
    """A dry run must reach no host at all — it prints the config and stops."""
    cplb = _load("deploy-cplb.py", "cplb_main")
    calls = []
    monkeypatch.setattr(
        cplb, "run", lambda host, script, apply: calls.append(host) or 0
    )
    monkeypatch.setattr(sys, "argv", ["deploy-cplb.py"])
    assert cplb.main() == 0
    assert calls == [], "a dry run contacted a host"
    assert "DRY RUN" in capsys.readouterr().out


def test_cplb_main_applies_only_when_asked(monkeypatch):
    cplb = _load("deploy-cplb.py", "cplb_apply")
    calls = []
    monkeypatch.setattr(
        cplb, "run", lambda host, script, apply: calls.append((host, apply)) or 0
    )
    monkeypatch.setattr(sys, "argv", ["deploy-cplb.py", "--apply"])
    cplb.main()
    assert calls and all(apply is True for _, apply in calls), calls


def test_cplb_run_is_inert_without_apply(monkeypatch):
    """apply=False returns 0 WITHOUT executing — the dry run must not be able to
    change a host even by accident."""
    cplb = _load("deploy-cplb.py", "cplb_run")
    executed = []
    monkeypatch.setattr(
        cplb.subprocess,
        "run",
        lambda *a, **k: executed.append(a)
        or types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    import hosts

    assert cplb.run(hosts.HOSTS[0].name, "echo hi", apply=False) == 0
    assert executed == [], "dry run executed a command"


def test_cplb_run_returns_the_process_status_when_applying(monkeypatch):
    cplb = _load("deploy-cplb.py", "cplb_run2")
    monkeypatch.setattr(
        cplb.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=3, stdout="", stderr=""),
    )
    import hosts

    assert cplb.run(hosts.HOSTS[0].name, "echo hi", apply=True) == 3


def test_cplb_main_reports_a_failed_host(monkeypatch):
    """One host failing must surface as a non-zero exit, not be averaged away."""
    cplb = _load("deploy-cplb.py", "cplb_fail")
    monkeypatch.setattr(cplb, "run", lambda host, script, apply: 1)
    monkeypatch.setattr(sys, "argv", ["deploy-cplb.py", "--apply"])
    assert cplb.main() == 1
