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
            assert 'allow_from "$src" 9428' in rendered
            continue
        # The block may be present but must be unreachable.
        if 'allow_from "$src" 9428' in rendered:
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


def test_remote_write_port_is_opened_on_the_store_host(dobs, cfg):
    """vmagent's remote_write destination must actually be reachable.

    This is the defect that made ADR-098's whole cluster tier inert. The unit
    bound 127.0.0.1 and the installer opened nothing for 8428, under a comment
    asserting that a "separate remote-write listener" was opened to the cluster
    — a listener single-node VictoriaMetrics does not have. It read as correct
    for as long as nobody tried to push to it.
    """
    for name in cfg.hypervisors:
        rendered = dobs.render_installer(cfg, name)
        if name == cfg.observability.host:
            assert 'allow_from "$src" 8428' in rendered
            continue
        if 'allow_from "$src" 8428' in rendered:
            assert (
                "if false; then" in rendered
            ), f"{name}: 8428 would be opened on a host with no metrics store"


def test_the_cluster_write_ports_admit_only_node_addresses(dobs, cfg):
    """8428 carries the QUERY api as well as the write path.

    VictoriaMetrics has no per-path authorisation, so this allow-list is the
    only thing between a node address and the ability to read or delete series.
    A range here would hand that to every device on the LAN.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)

    loops = re.findall(r"for src in ([^;]+); do", rendered)
    assert loops, "no allow-list loop is rendered at all"
    cluster_loop = [l for l in loops if set(l.split()) == set(dobs.node_addresses(cfg))]
    assert cluster_loop, f"no loop iterates exactly the k0s nodes; got {loops}"

    # An accept WITHOUT a matching drop restricts nothing when the zone already
    # opens the port range — which is exactly how 9100 and 9428 came to be
    # reachable from the whole LAN under a comment saying otherwise.
    for port in ("8428", "9428"):
        assert f'allow_from "$src" {port}' in rendered, f"{port} is never allowed"
        assert f"deny_port {port}" in rendered, (
            f"{port} has an accept but no drop — an accept on top of the zone's "
            "open range restricts nothing"
        )

    assert "/24" not in rendered


def test_victoria_metrics_listens_beyond_loopback():
    """The unit must not go back to binding 127.0.0.1.

    Guarding the regression directly rather than only its firewall half: a
    loopback bind makes the store unreachable from the cluster no matter what
    firewalld allows, and the symptom is a vmagent that looks healthy while
    writing nowhere.
    """
    unit = (REPO / "systemd/observability/victoria-metrics.service").read_text()
    listen = re.search(r"-httpListenAddr=(\S+)", unit)
    assert listen, "victoria-metrics.service declares no -httpListenAddr"
    assert not listen.group(1).startswith(
        "127.0.0.1"
    ), "victoria-metrics is bound to loopback; the in-cluster vmagent cannot reach it"


def test_grafana_is_skipped_rather_than_looping_when_unconfigured():
    """An optional component must not page the operator forever.

    Grafana cannot start without /etc/grafana/grafana.env, and that file holds a
    secret so the deploy never creates it. Combined with Restart=always,
    RestartSec=5s, StartLimitIntervalSec=0 and an OnFailure notifier, that sent
    9 push notifications in 20 minutes and would not have stopped.

    ConditionPathExists makes systemd skip the unit instead: no start, no
    failure, no notification — and it starts normally once the file exists.
    """
    unit = (REPO / "systemd/observability/grafana.service").read_text()
    assert (
        "ConditionPathExists=/etc/grafana/grafana.env" in unit
    ), "grafana.service would crash-loop on a host where it is not configured"


def test_the_failure_notifier_is_rate_limited():
    """OnFailure fires on EVERY restart attempt, so the notifier needs a bound.

    Without one, any permanently-broken observability unit becomes an unbounded
    alert loop — and an alert repeating every five seconds is less informative
    than one arriving once, because it buries everything else.
    """
    unit = (REPO / "systemd/observability/observability-notify@.service").read_text()
    assert "ExecCondition=" in unit, "observability-notify@ has no rate limit"
    assert "-lt 900" in unit, "the rate-limit window is not the documented 15 minutes"


def test_a_changed_unit_is_actually_restarted(dobs, cfg):
    """Writing a unit file is not applying it.

    `enable --now` starts a stopped unit and does nothing to a running one, so a
    changed ExecStart reached disk, was loaded by daemon-reload, and never
    reached the running process. VictoriaMetrics stayed bound to 127.0.0.1
    through a deploy whose whole purpose was to rebind it, and
    substrate-reconcile.sh reported the host in sync because the FILE was
    correct.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "try-restart" in rendered, "the installer never restarts a changed unit"
    # try-restart specifically: `restart` would start a unit the operator had
    # deliberately stopped.
    assert "systemctl restart" not in rendered


def test_the_restart_list_comes_from_the_payload(dobs, cfg):
    """The units checked for change must be the units actually shipped.

    A separately maintained list is one that silently stops matching — the same
    failure as a lint glob that stops covering new directories.
    """
    for name in cfg.hypervisors:
        shipped = {
            Path(dest).name
            for _, dest, *_ in dobs.files_for(cfg, name)
            if dest.endswith((".service", ".timer"))
        }
        assert set(dobs.unit_files_for(cfg, name)) == shipped


def test_templates_are_not_restarted(dobs, cfg):
    """`systemctl try-restart foo@.service` on a template is an error.

    The notifier is a template and is never itself running; skipping it keeps a
    clean deploy from printing a spurious warning every time.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "*@*) continue" in rendered


def test_the_restart_check_is_content_based_not_mtime(dobs, cfg):
    """Restarting on mtime would restart the whole stack on every deploy.

    The payload rewrites every unit file each run, so mtime alone marks
    everything stale — gaps in the metrics store for no change. The stamp holds
    the file's sha256 as of the last (re)start, so only a real content change
    triggers a restart. mtime survives ONLY as the bootstrap fallback, for a host
    that has no stamp yet and may already be running a stale process.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "sha256sum" in rendered and "UNIT_STAMPS" in rendered
    # The fallback must be present too, or a host drifted before this shipped
    # never self-corrects.
    assert "ActiveEnterTimestamp" in rendered


def test_the_drift_check_notices_a_stale_process():
    """A correct file is not a correct process.

    substrate-reconcile.sh verified file checksums and reported the host in sync
    while VictoriaMetrics ran a command line its unit no longer contained.
    """
    script = (REPO / "substrate-reconcile.sh").read_text()
    assert "UNIT_STAMPS" in script, "the drift check still only looks at files"
    assert "older configuration than its unit file" in script


def test_every_restricted_port_has_a_drop(dobs, cfg):
    """The lesson of 2026-09-02, as an assertion.

    Fedora Workstation's default zone opens 1025-65535/tcp. A rich rule that
    ACCEPTS from an allow-listed source adds nothing on top of that: the port was
    already open to everyone. Only a drop, ordered ahead of the zone's own
    accept, actually restricts. Every port this installer claims to allow-list
    must therefore carry both halves.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    for port in ("9100", "9428", "8428"):
        assert f"deny_port {port}" in rendered, f"{port} is 'allow-listed' with no drop"
    # Ordering is the whole mechanism: the accept must outrank the drop, and both
    # must outrank the zone's port range.
    assert 'priority="-100"' in rendered and 'priority="-50"' in rendered


def test_the_rich_rules_keep_their_inner_quotes(dobs, cfg):
    """firewalld needs priority="-100"; priority=-100 is rejected.

    Written inline inside a double-quoted bash string the inner quotes collapse,
    and with --quiet and `|| true` the rejection is silent — a firewall full of
    rules that were never accepted. shellcheck caught this; printf fixes it.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "printf 'rule priority=" in rendered, "rules are not built with printf"
    assert 'priority="-100"' in rendered


def test_the_firewall_zone_is_the_lan_interfaces_own(dobs, cfg):
    """Rules written into the wrong zone filter nothing.

    The default zone is not necessarily the one holding the LAN interface, and
    a rule in the wrong zone is another way to look configured while allowing
    everything.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "get-zone-of-interface" in rendered
    assert dobs.host_address(cfg, cfg.observability.host) in rendered
