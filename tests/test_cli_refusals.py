"""The refusals in the privileged CLIs, exercised through main().

These scripts mint identities and reconfigure the control plane. What matters is
not that they work on the happy path — it is that they REFUSE the inputs that
would quietly create standing privilege or clobber something irreversible.
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


@pytest.fixture
def ccc():
    return _load("create-client-cert.py", "ccc_cli")


@pytest.fixture
def jit():
    return _load("jit-admin.py", "jit_cli")


@pytest.fixture
def cplb():
    return _load("deploy-cplb.py", "cplb_cli")


# ------------------------------------------------- create-client-cert refusals


@pytest.mark.parametrize(
    "group", ["system:masters", "system:nodes", "system:node-admins"]
)
def test_refuses_to_mint_a_forbidden_group(ccc, monkeypatch, tmp_path, group):
    """system:masters bypasses RBAC entirely, and a client certificate CANNOT be
    revoked — no CRL, no OCSP. Issuing one by accident is unfixable short of
    rotating the cluster CA."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "create-client-cert.py",
            "someone",
            "--groups",
            group,
            "--out-dir",
            str(tmp_path),
        ],
    )
    with pytest.raises(SystemExit) as e:
        ccc.main()
    assert "refusing" in str(e.value).lower()
    assert not list(tmp_path.iterdir()), "nothing should be written on refusal"


def test_refuses_to_overwrite_an_existing_certificate(ccc, monkeypatch, tmp_path):
    """The old certificate stays valid until it expires, so silently replacing
    the file would leave a live credential nobody is tracking."""
    (tmp_path / "brad.crt").write_text("existing")
    monkeypatch.setattr(
        sys, "argv", ["create-client-cert.py", "brad", "--out-dir", str(tmp_path)]
    )
    with pytest.raises(SystemExit) as e:
        ccc.main()
    assert "already exists" in str(e.value)


def test_a_permitted_group_is_not_refused(ccc, monkeypatch, tmp_path):
    """Guard against an over-broad refusal: `platform-viewer` must still mint.
    Stops at the CSR submission, which is where the cluster would be needed."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "create-client-cert.py",
            "reader",
            "--groups",
            "platform-viewer",
            "--out-dir",
            str(tmp_path),
        ],
    )
    monkeypatch.setattr(
        ccc.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(
            returncode=1, stdout="", stderr="no cluster"
        ),
    )
    with pytest.raises(SystemExit) as e:
        ccc.main()
    assert "refusing to issue" not in str(e.value)


# ----------------------------------------------------------- jit-admin revoke


def test_revoke_is_a_noop_when_nothing_is_granted(jit, monkeypatch, capsys):
    monkeypatch.setattr(jit, "current", lambda: None)
    assert jit.cmd_revoke() == 0
    assert "no" in capsys.readouterr().out.lower()


def test_revoke_deletes_the_binding_when_one_exists(jit, monkeypatch):
    monkeypatch.setattr(jit, "current", lambda: {"metadata": {"name": jit.BINDING}})
    seen = []
    monkeypatch.setattr(
        jit,
        "sh",
        lambda args, **kw: (
            seen.append(args)
            or types.SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    jit.cmd_revoke()
    assert any("delete" in " ".join(a) for a in seen), seen


def test_main_dispatches_status_without_touching_the_cluster(jit, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["jit-admin.py", "status"])
    monkeypatch.setattr(jit, "current", lambda: None)
    assert jit.main() == 0


def test_main_rejects_an_unknown_subcommand(jit, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["jit-admin.py", "escalate"])
    with pytest.raises(SystemExit):
        jit.main()


# ------------------------------------------------------------ deploy-cplb


def test_install_script_is_generated_per_host(cplb):
    import hosts

    names = [h.name for h in hosts.HOSTS]
    scripts = {n: cplb.install_script(n) for n in names}
    for n, sc in scripts.items():
        assert isinstance(sc, str) and len(sc) > 100
    if len(names) >= 2:
        assert (
            scripts[names[0]] != scripts[names[1]]
        ), "both hypervisors would get identical keepalived priorities"


def test_install_script_embeds_both_configs(cplb):
    import hosts

    sc = cplb.install_script(hosts.HOSTS[0].name)
    assert "haproxy" in sc.lower() and "keepalived" in sc.lower()


def test_remote_targets_the_named_host(cplb):
    import hosts

    remote = next(h for h in hosts.HOSTS if h.ssh_target)
    cmd = cplb.remote(remote.name)
    assert any(remote.ssh_target in str(part) for part in cmd), cmd
