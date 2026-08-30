"""deploy_updates.py — what the deploy PLANS to install, and how it escalates.

Mocked at the process boundary. The assertions are about decisions: which files
land where and with what mode, that privilege is taken exactly once, and that
the staging directory is cleaned up even when the installer fails.
"""

from __future__ import annotations

import io
import tarfile
import types

import pytest

import deploy_updates as du
import hosts


@pytest.fixture
def local_host():
    return next(h for h in hosts.HOSTS if h.ssh_target is None)


@pytest.fixture
def remote_host():
    return next(h for h in hosts.HOSTS if h.ssh_target is not None)


# --------------------------------------------------------------- command shape


def test_run_executes_directly_on_the_local_host(local_host, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: (
            seen.update(cmd=cmd)
            or types.SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    du.run(local_host, ["echo", "hi"])
    assert seen["cmd"][0] == "echo", seen["cmd"]


def test_run_wraps_remote_commands_in_ssh(remote_host, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: (
            seen.update(cmd=cmd)
            or types.SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    du.run(remote_host, ["echo", "hi"])
    assert seen["cmd"][0] == "ssh" and remote_host.ssh_target in seen["cmd"]


def test_run_raises_on_failure_when_checked(local_host, monkeypatch):
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="boom"),
    )
    with pytest.raises(RuntimeError):
        du.run(local_host, ["false"])


def test_run_tolerates_failure_when_unchecked(local_host, monkeypatch):
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="boom"),
    )
    assert du.run(local_host, ["false"], check=False).returncode == 1


# ---------------------------------------------------------------- the payload


def test_payload_contains_every_planned_file():
    files = [(b"a", "usr/local/bin/x.sh", 0o755), (b"b", "etc/homelab/y.env", 0o600)]
    with tarfile.open(fileobj=io.BytesIO(du.build_payload(files))) as tf:
        assert sorted(m.name for m in tf.getmembers()) == [
            "etc/homelab/y.env",
            "usr/local/bin/x.sh",
        ]


def test_installer_is_rendered_with_the_kubectl_url():
    script = du.INSTALLER.replace("__KUBECTL_URL__", du.KUBECTL_URL)
    assert "__KUBECTL_URL__" not in script
    assert du.KUBECTL_URL in script


def test_installer_extracts_preserving_modes():
    """-p is what carries 0600 onto the secrets; without it umask decides."""
    assert "-xzpf" in du.INSTALLER


# ------------------------------------------------------------------ escalation


def test_apply_takes_privilege_exactly_once(local_host, monkeypatch):
    """ADR-078: the old design made ~15 separate sudo calls, which cannot
    authenticate on a password-protected host. Staging is unprivileged; there
    must be exactly ONE privileged invocation."""
    privileged, staged = [], []

    monkeypatch.setattr(
        du,
        "run",
        lambda host, argv, check=True, input_text=None: types.SimpleNamespace(
            returncode=0, stdout="/tmp/stage\n", stderr=""
        ),
    )
    monkeypatch.setattr(
        du, "stage_bytes", lambda host, data, remote: staged.append(remote)
    )

    def fake_proc_run(cmd, **kw):
        if any("sudo" in str(c) for c in cmd):
            privileged.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(du.subprocess, "run", fake_proc_run)

    du.apply(local_host, [(b"x", "etc/thing", 0o644)])
    assert len(privileged) == 1, privileged
    assert any("payload.tar.gz" in s for s in staged), staged


def test_apply_cleans_up_staging_even_when_the_installer_fails(local_host, monkeypatch):
    cleaned = []

    def fake_run(host, argv, check=True, input_text=None):
        if argv and argv[0] == "rm":
            cleaned.append(argv)
        return types.SimpleNamespace(returncode=0, stdout="/tmp/stage\n", stderr="")

    monkeypatch.setattr(du, "run", fake_run)
    monkeypatch.setattr(du, "stage_bytes", lambda *a, **k: None)
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="fail"),
    )

    with pytest.raises(RuntimeError):
        du.apply(local_host, [(b"x", "etc/thing", 0o644)])
    assert cleaned, "staging directory was left behind on failure"


# ----------------------------------------------------------------- the plan


def test_deploy_plans_the_expected_file_set(local_host, monkeypatch):
    planned = {}
    monkeypatch.setattr(du, "apply", lambda host, files: planned.update(files=files))
    monkeypatch.setattr(du, "ntfy_topic", lambda: "fake-topic")
    du.deploy(local_host, "FAKE-KUBECONFIG")

    paths = {p for _, p, _ in planned["files"]}
    assert "etc/homelab/kubeconfig" in paths
    assert "etc/homelab/update.env" in paths
    assert "etc/homelab/notify.env" in paths
    assert "usr/local/bin/homelab-notify.sh" in paths
    assert any(p.endswith("hypervisor-update.service") for p in paths)


def test_deploy_marks_the_secrets_0600(local_host, monkeypatch):
    planned = {}
    monkeypatch.setattr(du, "apply", lambda host, files: planned.update(files=files))
    monkeypatch.setattr(du, "ntfy_topic", lambda: "fake-topic")
    du.deploy(local_host, "FAKE-KUBECONFIG")
    modes = {p: m for _, p, m in planned["files"]}
    assert modes["etc/homelab/kubeconfig"] == 0o600
    assert modes["etc/homelab/notify.env"] == 0o600


def test_deploy_still_installs_everything_without_an_ntfy_topic(
    local_host, monkeypatch, capsys
):
    """A missing topic must degrade to a loud warning, not skip the deploy."""
    planned = {}
    monkeypatch.setattr(du, "apply", lambda host, files: planned.update(files=files))
    monkeypatch.setattr(du, "ntfy_topic", lambda: None)
    du.deploy(local_host, "FAKE-KUBECONFIG")
    paths = {p for _, p, _ in planned["files"]}
    assert "etc/homelab/notify.env" not in paths
    assert "usr/local/bin/homelab-notify.sh" in paths
    assert "WARNING" in capsys.readouterr().out


def test_deploy_writes_ssh_user_into_the_env(local_host, monkeypatch):
    """Regression: hypervisor-update.sh guards on ${SSH_USER:?} and both hosts
    aborted at 03:30 when the deploy did not supply it."""
    planned = {}
    monkeypatch.setattr(du, "apply", lambda host, files: planned.update(files=files))
    monkeypatch.setattr(du, "ntfy_topic", lambda: "t")
    du.deploy(local_host, "K")
    env = next(
        c for c, p, _ in planned["files"] if p == "etc/homelab/update.env"
    ).decode()
    assert "SSH_USER=" in env and "PEER_HOST=" in env


# ------------------------------------------------------------- staging bytes


def test_stage_bytes_writes_directly_on_the_local_host(local_host, tmp_path):
    target = tmp_path / "payload.bin"
    du.stage_bytes(local_host, b"hello", str(target))
    assert target.read_bytes() == b"hello"


def test_stage_bytes_pipes_through_ssh_for_a_remote_host(remote_host, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: (
            seen.update(cmd=cmd, data=kw.get("input"))
            or types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        ),
    )
    du.stage_bytes(remote_host, b"hello", "/tmp/x")
    assert seen["cmd"][0] == "ssh" and seen["data"] == b"hello"


def test_stage_bytes_raises_when_the_remote_write_fails(remote_host, monkeypatch):
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"disk full"
        ),
    )
    with pytest.raises(RuntimeError):
        du.stage_bytes(remote_host, b"x", "/tmp/x")


# ------------------------------------------------------- topology and helpers


def test_peer_of_returns_the_other_hypervisor(local_host, remote_host):
    assert du.peer_of(local_host).name == remote_host.name
    assert du.peer_of(remote_host).name == local_host.name


def test_ntfy_topic_read_from_the_homelab_env(monkeypatch, tmp_path):
    home = tmp_path
    (home / "homelab").mkdir()
    (home / "homelab" / ".env").write_text("OTHER=1\nNTFY_TOPIC=from-file\n")
    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    monkeypatch.setattr(du.Path, "home", staticmethod(lambda: home))
    assert du.ntfy_topic() == "from-file"


def test_apply_uses_a_tty_for_a_remote_sudo(remote_host, monkeypatch):
    """`ssh -t`, so sudo can prompt on a real pty. Without it a
    password-protected host cannot authenticate at all (ADR-078)."""
    monkeypatch.setattr(
        du,
        "run",
        lambda host, argv, check=True, input_text=None: types.SimpleNamespace(
            returncode=0, stdout="/tmp/stage\n", stderr=""
        ),
    )
    monkeypatch.setattr(du, "stage_bytes", lambda *a, **k: None)
    seen = {}
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda cmd, **kw: (seen.update(cmd=cmd) or types.SimpleNamespace(returncode=0)),
    )
    du.apply(remote_host, [(b"x", "etc/thing", 0o644)])
    assert "-t" in seen["cmd"], seen["cmd"]


def test_main_deploys_to_every_host(monkeypatch):
    deployed = []
    monkeypatch.setattr(du, "fetch_kubeconfig", lambda: "FAKE")
    monkeypatch.setattr(du, "deploy", lambda host, kc: deployed.append(host.name))
    du.main()
    assert len(deployed) == len(hosts.HOSTS), deployed


# ------------------------------------------------------------ kubeconfig fetch


def test_bootstrap_ip_is_the_bootstrap_vms_address():
    ip = du.bootstrap_ip()
    expected = next(vm.static_ip for h in hosts.HOSTS for vm in h.vms if vm.bootstrap)
    assert ip == expected


def test_fetch_kubeconfig_returns_the_admin_config(monkeypatch):
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(
            returncode=0, stdout="apiVersion: v1\nserver: https://x\n", stderr=""
        ),
    )
    assert "server:" in du.fetch_kubeconfig()


def test_fetch_kubeconfig_refuses_output_that_is_not_a_kubeconfig(monkeypatch):
    """A zero exit with junk on stdout would otherwise be written to
    /etc/homelab/kubeconfig on both hypervisors, and the nightly health gate
    would fail every night with something unrelated-looking."""
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(
            returncode=0, stdout="not a kubeconfig", stderr=""
        ),
    )
    with pytest.raises(RuntimeError):
        du.fetch_kubeconfig()


def test_fetch_kubeconfig_raises_when_the_node_is_unreachable(monkeypatch):
    monkeypatch.setattr(
        du.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(
            returncode=255, stdout="", stderr="no route"
        ),
    )
    with pytest.raises(RuntimeError):
        du.fetch_kubeconfig()


def test_deploy_skips_a_host_with_no_peer(monkeypatch, capsys):
    """The reboot safety gate needs a peer to ask; without one the deploy must
    say so rather than install a gate that always passes."""
    lonely = hosts.Host(name="only", ssh_target=None, peer_target=None)
    monkeypatch.setattr(du, "peer_of", lambda h: None)
    called = []
    monkeypatch.setattr(du, "apply", lambda *a, **k: called.append(1))
    du.deploy(lonely, "K")
    assert called == []
    assert "SKIP" in capsys.readouterr().out
