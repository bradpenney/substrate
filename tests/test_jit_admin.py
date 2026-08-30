"""The time-boxed cluster-admin grant (ADR-059/065).

This is the mechanism that replaced standing `system:masters`. Its whole value
is that a grant EXPIRES on its own, so the properties worth asserting are the
ones that would quietly turn it back into standing privilege: an expiry that is
not written, a second grant stacking on the first, or a binding that points at
something more powerful than intended.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def jit(monkeypatch):
    spec = importlib.util.spec_from_file_location("jit", REPO / "jit-admin.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["jit"] = m
    spec.loader.exec_module(m)
    return m


def _crb(expiry=None, user="brad"):
    meta = {"name": "jit-platform-admin", "annotations": {}}
    if expiry:
        meta["annotations"]["jit.bradpenney.io/expires-at"] = expiry
    return {
        "metadata": meta,
        "subjects": [{"kind": "User", "name": user}],
        "roleRef": {"kind": "ClusterRole", "name": "platform-admin"},
    }


def test_status_reports_no_grant_when_none_exists(jit, monkeypatch, capsys):
    monkeypatch.setattr(jit, "current", lambda: None)
    assert jit.cmd_status() == 0
    assert "no outstanding grant" in capsys.readouterr().out


def test_status_flags_a_grant_with_no_expiry(jit, monkeypatch, capsys):
    """A binding without the expiry annotation is standing privilege wearing the
    name of a temporary one. The reaper removes it, and status must say so
    rather than printing a reassuring line."""
    monkeypatch.setattr(jit, "current", lambda: _crb(expiry=None))
    jit.cmd_status()
    assert "NO expiry" in capsys.readouterr().out


def test_status_shows_time_remaining_for_a_live_grant(jit, monkeypatch, capsys):
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    monkeypatch.setattr(jit, "current", lambda: _crb(expiry=future))
    jit.cmd_status()
    out = capsys.readouterr().out
    assert "remaining" in out and "EXPIRED" not in out


def test_status_reports_an_expired_grant_as_awaiting_the_reaper(
    jit, monkeypatch, capsys
):
    """Expired-but-present is the state that matters: the window has closed but
    the privilege is still bound until the reaper runs."""
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    monkeypatch.setattr(jit, "current", lambda: _crb(expiry=past))
    jit.cmd_status()
    assert "EXPIRED" in capsys.readouterr().out


def test_grant_refuses_to_stack_on_an_existing_grant(jit, monkeypatch):
    """Otherwise a second grant silently extends the first, and the time box
    constrains nothing."""
    monkeypatch.setattr(jit, "current", lambda: _crb(expiry="2099-01-01T00:00:00Z"))
    with pytest.raises(SystemExit):
        jit.cmd_grant("brad", 30)


def test_grant_writes_an_expiry_and_binds_only_platform_admin(jit, monkeypatch):
    """Captures the object that would be applied. Two properties matter: the
    expiry annotation exists (or the grant never expires), and the roleRef is
    platform-admin — NOT cluster-admin, which would make the JIT path a
    privilege escalation rather than a scoped one."""
    monkeypatch.setattr(jit, "current", lambda: None)
    captured = {}

    def fake_sh(args, check=True, context=None, **kw):
        if "apply" in args:
            captured["obj"] = json.loads(kw.get("input", "{}"))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(jit, "sh", fake_sh)
    jit.cmd_grant("brad", 30)

    obj = captured.get("obj")
    assert obj, "no ClusterRoleBinding was applied"
    ann = obj["metadata"]["annotations"]
    assert jit.ANNOTATION in ann and ann[jit.ANNOTATION].endswith("Z")
    assert obj["roleRef"]["name"] == "platform-admin", obj["roleRef"]
    assert obj["subjects"][0]["name"] == "brad"


def test_grant_expiry_reflects_the_requested_window(jit, monkeypatch):
    monkeypatch.setattr(jit, "current", lambda: None)
    captured = {}
    monkeypatch.setattr(
        jit,
        "sh",
        lambda args, check=True, context=None, **kw: (
            captured.update(obj=json.loads(kw["input"])) if "apply" in args else None
        )
        or types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    jit.cmd_grant("brad", 45)
    exp = captured["obj"]["metadata"]["annotations"][jit.ANNOTATION]
    end = dt.datetime.fromisoformat(exp.replace("Z", "+00:00"))
    minutes = (end - dt.datetime.now(dt.timezone.utc)).total_seconds() / 60
    assert 43 < minutes < 46, f"expiry is {minutes:.1f}m away, expected ~45"


def test_sh_builds_a_context_scoped_command(jit, monkeypatch):
    """grant and revoke name the break-glass context explicitly: the scoped
    day-to-day identity deliberately cannot create a ClusterRoleBinding, or the
    time box would constrain nothing."""
    seen = {}
    monkeypatch.setattr(
        jit.subprocess,
        "run",
        lambda cmd, **kw: (
            seen.update(cmd=cmd)
            or types.SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    jit.sh(["kubectl", "get", "x"], context="break-glass")
    assert any("break-glass" in str(c) for c in seen["cmd"]), seen["cmd"]


def test_current_returns_none_when_no_binding_exists(jit, monkeypatch):
    monkeypatch.setattr(
        jit,
        "sh",
        lambda args, **kw: types.SimpleNamespace(
            returncode=1, stdout="", stderr="NotFound"
        ),
    )
    assert jit.current() is None


def test_current_parses_an_existing_binding(jit, monkeypatch):
    monkeypatch.setattr(
        jit,
        "sh",
        lambda args, **kw: types.SimpleNamespace(
            returncode=0, stdout=json.dumps({"metadata": {"name": "x"}}), stderr=""
        ),
    )
    assert jit.current()["metadata"]["name"] == "x"


def test_main_grant_requires_a_user(jit, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["jit-admin.py", "grant"])
    with pytest.raises(SystemExit):
        jit.main()


def test_main_dispatches_revoke(jit, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["jit-admin.py", "revoke"])
    monkeypatch.setattr(jit, "current", lambda: None)
    assert jit.main() == 0


def test_sh_exits_with_the_failing_command_when_checked(jit, monkeypatch):
    """SystemExit, not a bare exception: this is a CLI, so a failed kubectl must
    end the process with the command and stderr shown, not unwind a traceback at
    someone holding a break-glass credential."""
    monkeypatch.setattr(
        jit.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(
            returncode=1, stdout="", stderr="denied"
        ),
    )
    with pytest.raises(SystemExit) as e:
        jit.sh(["kubectl", "get", "x"], check=True)
    assert "kubectl get x" in str(e.value) and "denied" in str(e.value)


def test_main_grant_passes_the_requested_minutes(jit, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        sys, "argv", ["jit-admin.py", "grant", "brad", "--minutes", "15"]
    )
    monkeypatch.setattr(
        jit, "cmd_grant", lambda user, minutes: seen.update(u=user, m=minutes) or 0
    )
    assert jit.main() == 0
    assert seen == {"u": "brad", "m": 15}
