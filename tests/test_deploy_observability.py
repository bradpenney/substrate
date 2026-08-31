"""What each hypervisor is told to install, and that it verifies what it fetches.

The installer is generated per host from typed config, so the interesting
failures are decisions, not bash: sending the metrics store to the wrong
machine, scraping a host that was never told to run node_exporter, or — the one
that matters most — fetching a binary without checking it.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(name="dobs")
def _dobs():
    """Import the hyphenated CLI by path, as the other tools are."""
    spec = importlib.util.spec_from_file_location(
        "deploy_observability", REPO / "deploy-observability.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_observability"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(name="cfg")
def _cfg():
    import siteconfig

    return siteconfig.load_model()


def test_only_the_nominated_host_carries_the_store(dobs, cfg):
    """The store is heavy and stateful; exactly one host runs it.

    Two would silently produce two half-populated metrics stores and a Grafana
    pointed at whichever answered — with no error anywhere.
    """
    carrying = [
        h for h in cfg.hypervisors if "victoria_metrics" in dobs.components_for(cfg, h)
    ]
    assert carrying == [cfg.observability.host]


def test_every_hypervisor_gets_node_exporter(dobs, cfg):
    """Node metrics are useful with or without a store to send them to, and a
    hypervisor missing its exporter shows up as a silent gap in a graph rather
    than as an error."""
    for name in cfg.hypervisors:
        assert "node_exporter" in dobs.components_for(cfg, name)


def test_every_scrape_target_is_a_host_that_installs_the_exporter(dobs, cfg):
    """A target nobody installs is a permanently-down scrape job.

    The reverse — an exporter nobody scrapes — is invisible, which is why the
    two lists are derived from the same source rather than maintained apart.
    """
    rendered = dobs.scrape_config(cfg).decode()
    # Match address:port specifically. A looser "starts with a dash" test also
    # matched `- targets:` and `- job_name:`, which are yaml structure rather
    # than scrape targets.
    targets = set(re.findall(r"^\s+- (\d+\.\d+\.\d+\.\d+):\d+\s*$", rendered, re.M))
    assert targets == set(dobs.peer_addresses(cfg))
    assert targets, "no scrape targets — the config would be silently empty"


def test_the_scrape_config_does_not_try_to_reach_the_cluster(dobs, cfg):
    """A host scraper can reach node IPs but NOT pod IPs (ADR-098).

    Adding cluster targets here would produce scrape jobs that fail forever and
    look like a broken cluster rather than a misplaced scraper. Cluster metrics
    arrive by remote_write from a vmagent running inside.
    """
    rendered = dobs.scrape_config(cfg).decode()
    node_ips = {n.ip for n in cfg.nodes.values()}
    for ip in node_ips:
        assert ip not in rendered, f"{ip} is a cluster node, not a hypervisor"


def test_every_fetched_binary_is_checksum_verified(dobs, cfg):
    """The whole reason binaries are fetched rather than pushed.

    A pinned URL says what was ASKED for; the checksum is what guarantees what
    arrives. An install_binary call missing its sha would download over the
    network and run whatever came back.
    """
    import siteconfig

    versions = siteconfig.load_versions()["observability"]
    for name in cfg.hypervisors:
        rendered = dobs.render_installer(cfg, name)
        assert "sha256sum -c -" in rendered
        for component in dobs.components_for(cfg, name):
            assert (
                versions[component]["sha256"] in rendered
            ), f"{name}: {component} is fetched without its pinned checksum"


def test_the_exporter_port_is_allow_listed_not_lan_wide(dobs, cfg):
    """The standing rule is allow-listing, never a range (ADR-070 reasoning).

    Only the hosts that actually scrape may reach 9100. A /24 would hand it to
    every device on the network, including ones nobody has thought about.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "/24" not in rendered and "0.0.0.0" not in rendered
    for address in dobs.peer_addresses(cfg):
        assert address in rendered


def test_it_does_not_need_an_admin_ssh_key(tmp_path):
    """Installing metrics agents has nothing to do with node identity.

    `hosts.py` used to resolve the admin SSH key at IMPORT, so every consumer of
    the topology required one. Running this tool produced
    "No SSH public key found at /root/.ssh/id_ed25519.pub" while installing
    node_exporter — a dependency that existed whether or not the value was used.
    """
    import subprocess as sp

    env = {
        k: v
        for k, v in __import__("os").environ.items()
        if k not in ("HOMELAB_SSH_PUBLIC_KEY", "HOMELAB_SSH_PUBLIC_KEY_FILE")
    }
    env["HOME"] = str(tmp_path)
    env["SUBSTRATE_SITE_FILE"] = str(REPO / "tests" / "fixtures" / "site.yml")

    proc = sp.run(
        [sys.executable, str(REPO / "deploy-observability.py"), "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "No SSH public key" not in proc.stderr + proc.stdout


def test_rendering_a_cloud_config_still_requires_the_key(tmp_path):
    """Guard the other side of the same change.

    Making the key lazy must not make it OPTIONAL. A node rendered without one
    is a node nobody can log into, discovered after it is built — so the
    renderer must still refuse rather than emit an empty authorized_keys.
    """
    import subprocess as sp

    env = {
        k: v
        for k, v in __import__("os").environ.items()
        if k not in ("HOMELAB_SSH_PUBLIC_KEY", "HOMELAB_SSH_PUBLIC_KEY_FILE")
    }
    env["HOME"] = str(tmp_path)
    env["SUBSTRATE_SITE_FILE"] = str(REPO / "tests" / "fixtures" / "site.yml")

    proc = sp.run(
        [
            sys.executable,
            str(REPO / "render-cloud-config.py"),
            "--name",
            "x",
            "--ip",
            "192.0.2.1",
            "--bootstrap",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    assert "No SSH public key" in proc.stderr + proc.stdout


def test_it_refuses_to_run_privileged(dobs):
    """`sudo ./deploy-observability.py` is the wrong invocation.

    It stages as the ordinary user and escalates once, for the installer alone
    (ADR-078). Run whole under sudo, $HOME resolves to /root and key and
    ssh-agent lookups break — which is exactly how this was first hit.
    """
    source = (REPO / "deploy-observability.py").read_text()
    assert "os.geteuid() == 0" in source
    assert "Do not run this under sudo" in source


def test_the_two_ports_have_different_allow_lists(dobs, cfg):
    """9100 is PULLED by the hypervisors; 9428 is PUSHED to from the cluster.

    Different callers, so different allow-lists. One combined list would open
    each port to callers with no business on it — the metrics port to every k0s
    node, and log ingest to the hypervisors. Allow-listing that is merely
    "everything we own" is a range with extra steps.
    """
    scrapers = set(dobs.peer_addresses(cfg))
    nodes = set(dobs.node_addresses(cfg))
    assert scrapers and nodes
    assert not scrapers & nodes, "a host is in both lists — check the topology"


def test_log_ingest_is_only_opened_on_the_store_host(dobs, cfg):
    """A host with no log store must not open its ingest port.

    An open port with nothing behind it is not harmless: it is a listening
    surface that no one is monitoring and that no test would notice closing.
    """
    for name in cfg.hypervisors:
        rendered = dobs.render_installer(cfg, name)
        if name == cfg.observability.host:
            assert "port=9428" in rendered
            continue
        # The block may be present but must be unreachable.
        if "port=9428" in rendered:
            assert (
                "if false; then" in rendered
            ), f"{name}: 9428 would be opened on a host with no log store"


def test_the_drift_check_reports_a_modified_file(dobs, cfg, monkeypatch):
    """The host tier has no reconciler, so drift must at least be VISIBLE.

    Flux reverts a hand-edited cluster object within ten minutes. Nothing does
    that for a unit file on a hypervisor — it persists silently and the next
    rebuild quietly produces a different machine. This check cannot fix drift;
    it exists so drift cannot be invisible (ADR-100).
    """
    import types

    import deploy_updates

    host = types.SimpleNamespace(name=cfg.observability.host, ssh_target=None)

    def fake_run(_host, argv, check=True):  # noqa: ARG001
        if argv[0] == "sha256sum":
            return types.SimpleNamespace(returncode=0, stdout="0" * 64 + "  x")
        return types.SimpleNamespace(returncode=0, stdout="v0.0.0-wrong")

    monkeypatch.setattr(deploy_updates, "run", fake_run)
    problems = dobs.check(host, cfg)

    assert any("differs from the repository" in p for p in problems)
    assert any("repository pins" in p for p in problems), (
        "a binary at the wrong version is drift too — the units would be right "
        "and the thing they start would not be"
    )


def test_the_drift_check_reports_a_missing_file(dobs, cfg, monkeypatch):
    """Absent is not the same as different, and the message must say which."""
    import types

    import deploy_updates

    host = types.SimpleNamespace(name=cfg.observability.host, ssh_target=None)
    monkeypatch.setattr(
        deploy_updates,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=1, stdout=""),
    )
    assert any("is MISSING" in p for p in dobs.check(host, cfg))
