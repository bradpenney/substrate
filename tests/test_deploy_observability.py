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
    import yaml

    # PARSED, not pattern-matched. This assertion has now been broken twice by a
    # change to the config's LAYOUT rather than its meaning — first by a regex
    # that also matched `- targets:`, then by splitting one target block into one
    # per host so each could carry its own label. A test that reads the
    # generated YAML as YAML cannot be broken by reformatting it.
    parsed = yaml.safe_load(dobs.scrape_config(cfg).decode())
    targets = {
        target.rpartition(":")[0]
        for job in parsed["scrape_configs"]
        for block in job["static_configs"]
        for target in block["targets"]
    }
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


def test_an_extracted_tree_is_relabelled_and_owned_by_root(dobs, cfg):
    """`mv` preserves the SELinux context; the tree is built under /tmp.

    Grafana arrived at /usr/local/share/grafana wearing user_tmp_t and systemd
    refused to exec it with 203/EXEC. The mode was correct, the path was
    correct, and `ls -l` showed nothing wrong. install_binary was unaffected
    because `install` relabels — so this was the one component that could hit it.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    # Scoped to install_tree's own body, NOT the whole rendered script. This
    # assertion used to search the entire installer, and adding install_plugin
    # -- which relabels for the same reason -- silently disarmed it: deleting
    # install_tree's restorecon left the substring present elsewhere and the
    # test still passed. A whole-file `in` assertion stops testing the thing it
    # names as soon as a second component says the same words.
    fn = rendered.split("install_tree() {", 1)[1].split("\n}", 1)[0]
    assert "restorecon -R" in fn, "an extracted tree is never relabelled"
    assert "chown -R root:root" in fn, "an extracted tree keeps the archive's uid"
    # Guarded, because not every host runs SELinux.
    assert "command -v restorecon" in fn


# --- The VictoriaLogs datasource plugin -------------------------------------
#
# Grafana does not bundle it. Without it the provisioned VictoriaLogs datasource
# loads as an unknown type and every log panel fails, which is not visible from
# either end: VictoriaLogs keeps ingesting and Grafana keeps starting cleanly.


def test_the_logs_plugin_is_tied_to_grafana_not_to_the_log_store(dobs, cfg):
    """It is what lets GRAFANA read VictoriaLogs, so it follows Grafana.

    A host that stores logs but serves no dashboards has no use for a Grafana
    plugin, and installing one into a /var/lib/grafana that no Grafana reads
    would be 78 MB of cargo.
    """
    on_store = dobs.components_for(cfg, cfg.observability.host)
    assert "victoria_logs_datasource" in on_store
    assert "grafana" in on_store

    for name in cfg.hypervisors:
        which = dobs.components_for(cfg, name)
        assert ("victoria_logs_datasource" in which) == (
            "grafana" in which
        ), f"{name}: the plugin and Grafana must travel together"


def test_the_plugin_is_installed_as_a_plugin_not_a_program_tree(dobs, cfg):
    """Three install shapes exist and the plugin must dispatch to the third.

    install_tree would put it under /usr/local/share, which Grafana never scans
    and ProtectSystem=strict makes read-only anyway; install_binary would try to
    lift a single member out of a directory tree and fail outright.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    calls = [
        line
        for line in rendered.splitlines()
        if line.startswith(("install_binary ", "install_tree ", "install_plugin "))
    ]
    plugin_calls = [c for c in calls if "victoria_logs_datasource" in c]
    assert len(plugin_calls) == 1, "the plugin is installed exactly once"
    assert plugin_calls[0].startswith("install_plugin "), plugin_calls[0]


def test_the_plugin_lands_where_grafana_is_configured_to_look(dobs, cfg):
    """versions.yml and grafana.ini.template must agree on ONE directory.

    Grafana scans exactly the path in its `plugins` setting. If these two drift,
    the plugin installs successfully, verifies successfully, is reported by the
    drift check as present at the pinned version — and is never loaded, because
    Grafana is looking somewhere else. Nothing in the deploy would say so.
    """
    import siteconfig

    dest = siteconfig.load_versions()["observability"]["victoria_logs_datasource"][
        "install_to"
    ]
    template = (REPO / "observability-host/grafana.ini.template").read_text()
    configured = re.search(r"^plugins\s*=\s*(\S+)", template, re.M)
    assert configured, "grafana.ini.template declares no plugins directory"
    assert dest.startswith(
        configured.group(1).rstrip("/") + "/"
    ), f"plugin installs to {dest} but Grafana scans {configured.group(1)}"


def test_the_plugin_directory_name_matches_the_provisioned_datasource_type(cfg):
    """Grafana resolves a datasource `type` to a plugin id, which is the dirname.

    The provisioned datasource names `victoriametrics-logs-datasource`. If the
    installed tree is called anything else, Grafana provisions the datasource
    against a plugin that does not exist and reports it as an unknown type —
    the exact symptom this whole component was added to fix.
    """
    import siteconfig

    spec = siteconfig.load_versions()["observability"]["victoria_logs_datasource"]
    provisioned = (
        REPO / "observability-host/provisioning/datasources/victoria.yaml"
    ).read_text()
    declared = re.search(r"^\s*type:\s*(victoriametrics-\S+)", provisioned, re.M)
    assert declared, "no VictoriaLogs datasource type is provisioned"
    assert spec["plugin_root"] == declared.group(1)
    assert spec["install_to"].rsplit("/", 1)[-1] == declared.group(1)


def test_installing_the_plugin_restarts_grafana_to_load_it(dobs, cfg):
    """Grafana enumerates plugins ONCE, at startup.

    Installed-under-a-running-process is the same defect as a changed unit file
    that nothing restarts and a ConfigMap the pod never re-reads (ADR-116). The
    files are correct, every check passes, and the running process has never
    seen them.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "PLUGIN_INSTALLED=1" in rendered, "install_plugin records nothing"
    body = rendered.split('if [ "$PLUGIN_INSTALLED" -eq 1 ]; then', 1)
    assert len(body) == 2, "nothing acts on PLUGIN_INSTALLED"
    assert "try-restart grafana.service" in body[1]
    # And it must not restart a Grafana the unit loop already restarted, nor one
    # that ConditionPathExists is deliberately holding down.
    assert "$RESTARTED" in body[1]
    assert "is-active --quiet grafana.service" in body[1]


def test_the_plugin_tree_is_relabelled_and_root_owned(dobs, cfg):
    """The plugin declares `backend: true`, so Grafana EXECS a binary from it.

    That is the same exec that gave Grafana itself 203/EXEC: `mv` preserves the
    SELinux context, so a tree staged under mktemp -d arrives wearing
    user_tmp_t. Mode and path look correct; only the label is wrong.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    fn = rendered.split("install_plugin() {", 1)[1].split("\n}", 1)[0]
    assert "restorecon -R" in fn, "an unlabelled plugin binary cannot be exec'd"
    assert "chown -R root:root" in fn, "tar restores the upstream builder's uid"
    # Root-owned, not grafana-owned: Grafana only reads it, and a compromised
    # Grafana must not be able to rewrite the backend binary it then executes.
    assert "chown -R grafana" not in fn


def test_a_changed_grafana_ini_actually_restarts_grafana(dobs, cfg):
    """grafana.ini is not a unit file, and Grafana reads it once, at startup.

    The unit-file loop watches /etc/systemd/system. It cannot see this, so a
    changed grafana.ini shipped without this block is installed at the right
    path, with the right mode, and confirmed byte-identical to the repository by
    the drift check — while the running Grafana serves the configuration it was
    started with. Every report is about the file; none is about the process.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    assert "/etc/grafana/grafana.ini" in rendered
    assert (
        "restart_if_config_changed grafana.service /etc/grafana/grafana.ini" in rendered
    ), "no config file is watched for a restart"
    body = rendered.split("restart_if_config_changed() {", 1)[1].split("\n}", 1)[0]
    assert "try-restart" in body
    # Content, not mtime — the payload rewrites grafana.ini every deploy, so an
    # mtime test would restart Grafana on every run for nothing.
    assert "sha256sum" in body
    # And it must not restart a unit the unit-file loop already restarted.
    assert "$RESTARTED" in body


def test_victoria_metrics_is_not_restarted_for_a_config_change(dobs, cfg):
    """It re-reads its own scrape config; restarting would drop scrape state.

    The point of the config-restart list is that membership is a decision about
    each component's reload behaviour, not a blanket rule. VictoriaMetrics runs
    with -promscrape.configCheckInterval precisely so it does not need this.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    body = rendered.split("restart_if_config_changed() {", 1)[1].split("\n}", 1)[0]
    assert "victoria" not in body.lower()
    assert "promscrape.configCheckInterval" in rendered


# --- Telling the two tiers apart -------------------------------------------


def test_each_hypervisor_is_labelled_with_its_name(dobs, cfg):
    """A dashboard must be able to name a host without printing its address.

    The cluster tier gets a readable `node` label from the in-cluster vmagent.
    Without an equivalent here, `instance` is the only thing separating two
    hypervisors — and `instance` is an IP address, which cannot go into a
    committed dashboard.
    """
    rendered = dobs.scrape_config(cfg).decode()
    names = [name for name, _ in dobs.peer_targets_by_name(cfg)]
    assert len(names) == len(set(names)), "two hypervisors share a name"
    for name in names:
        assert f"host: {name}" in rendered, f"{name} is scraped without its name"
    # One static_config per host: a single block listing every target can only
    # carry one set of labels, so every host would get the same `host` value.
    assert rendered.count("tier: hypervisor") == len(names)


def test_the_dashboard_never_contains_an_address(cfg):
    """substrate is intended to go public; substrate_config stays private.

    Legends render from labels at query time, so nothing here needs an address —
    and a dashboard is exactly the kind of file where one gets pasted in during
    debugging and then committed.
    """
    board = (REPO / "observability-host/dashboards/fleet-overview.json").read_text()
    assert not re.search(
        r"\b\d{1,3}(\.\d{1,3}){3}\b", board
    ), "an IP is in the dashboard"
    for name, address in dobs_peer_targets(cfg):
        assert address not in board, f"{name}'s address is in the dashboard"


def dobs_peer_targets(cfg):
    """Helper: import the CLI once for the address check above."""
    spec = importlib.util.spec_from_file_location(
        "deploy_observability", REPO / "deploy-observability.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_observability"] = module
    spec.loader.exec_module(module)
    return module.peer_targets_by_name(cfg)


def test_no_dashboard_panel_mixes_the_hypervisors_with_the_cluster_nodes():
    """The panels claimed to be about hypervisors; the queries returned both.

    node_exporter runs on the hypervisors AND on the five k0s guests, and both
    write to the same store. An unfiltered `node_memory_*` therefore silently
    grew from two series to seven the day the in-cluster vmagent started, with
    the panel titles and descriptions still saying "hypervisor". Nothing broke;
    the chart just stopped meaning what it said.

    Comparing them on one axis is also wrong on its own terms: a hypervisor's
    numbers include the work of the guests plotted beside it.
    """
    import json

    board = json.loads(
        (REPO / "observability-host/dashboards/fleet-overview.json").read_text()
    )
    for panel in board["panels"]:
        for target in panel.get("targets", []):
            expr = target.get("expr", "")
            if "node_" not in expr:
                continue
            assert (
                'tier="hypervisor"' in expr or 'tier="cluster"' in expr
            ), f"panel {panel['title']!r} queries node_* across both tiers: {expr}"


def test_every_dashboard_grouping_uses_a_label_the_pipeline_produces(cfg):
    """`avg by (host)` over data with no `host` label MERGES every host silently.

    It does not error and it does not drop the series — it returns one line
    labelled with nothing, which reads as a single well-behaved machine. This
    was observed live: before the `host` label shipped, the hypervisor CPU panel
    returned 1 series for 2 hosts.
    """
    import json

    board = json.loads(
        (REPO / "observability-host/dashboards/fleet-overview.json").read_text()
    )
    scrape = dobs_peer_targets  # noqa: F841  (kept for symmetry with the import)
    produced = {"host", "node", "instance", "job", "tier", "cluster"}
    for panel in board["panels"]:
        for target in panel.get("targets", []):
            expr = target.get("expr", "")
            for label in re.findall(r"\bby\s*\(\s*([a-z_]+)\s*\)", expr):
                assert label in produced, (
                    f"panel {panel['title']!r} groups by {label!r}, "
                    "which nothing in the pipeline emits"
                )
            for label in re.findall(
                r"\{\{\s*([a-z_]+)\s*\}\}", target.get("legendFormat", "")
            ):
                assert label in produced, (
                    f"panel {panel['title']!r} legends on {label!r}, "
                    "which nothing in the pipeline emits"
                )


def test_grafana_gets_every_provisioning_directory_it_scans(dobs, cfg):
    """Grafana logs an error for each provisioning subdirectory that is missing.

    `plugins` and `alerting` hold nothing here, so they did not exist, so every
    start logged two errors that would never stop. A permanent expected error is
    worse than none: it teaches whoever reads this journal to skim red lines, on
    the host whose journal is read only when something is already wrong.
    """
    rendered = dobs.render_installer(cfg, cfg.observability.host)
    for directory in ("plugins", "alerting"):
        assert f"/etc/grafana/provisioning/{directory}" in rendered
