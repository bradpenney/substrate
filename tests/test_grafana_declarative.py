"""Grafana's configuration is code, and click-ops is disabled (ADR-102).

These assert the CONTROLS, not the intention. A convention that says "please
commit your dashboards" loses to a Save button; these check the settings that
make it impossible rather than impolite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
HOST = REPO / "observability-host"


@pytest.fixture(name="ini")
def _ini():
    """The RENDERED grafana.ini as {section: {key: value}}.

    Rendered, not the template: the template contains `__PLACEHOLDERS__`, and a
    test that asserted on those would pass while the deployed file said
    something else entirely. Not configparser — the file uses `;` comments and
    bare keys configparser handles differently.
    """
    import importlib.util
    import sys

    import siteconfig

    spec = importlib.util.spec_from_file_location(
        "dobs", REPO / "deploy-observability.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["dobs"] = module
    spec.loader.exec_module(module)
    cfg = siteconfig.load_model()
    cfg.observability.github_org = "example-org"

    out, current = {}, None
    for raw in module.grafana_ini(cfg).decode().splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            out.setdefault(current, {})
        elif "=" in line and current:
            k, _, v = line.partition("=")
            out[current][k.strip()] = v.strip()
    return out


def test_nobody_can_author_a_dashboard_in_the_ui(ini):
    """The load-bearing control.

    `allowUiUpdates: false` stops a provisioned dashboard being OVERWRITTEN. It
    does nothing about someone creating a NEW one beside it — only the Viewer
    role does that. Both are needed; the first without the second leaves the
    obvious workaround open.
    """
    assert ini["users"]["auto_assign_org_role"] == "Viewer"
    assert ini["users"]["viewers_can_edit"] == "false"
    assert ini["users"]["allow_sign_up"] == "false"


def test_provisioned_dashboards_cannot_be_saved_over(ini):  # noqa: ARG001
    """Enforced by Grafana: Save is disabled on anything loaded from disk."""
    provider = yaml.safe_load(
        (HOST / "provisioning/dashboards/repository.yaml").read_text()
    )
    for p in provider["providers"]:
        assert p["allowUiUpdates"] is False, (
            f"{p['name']}: allowUiUpdates true lets the UI overwrite a "
            f"dashboard that lives in git"
        )


def test_datasources_are_not_editable():
    """A datasource repointed in the UI is drift nobody can see in a diff."""
    ds = yaml.safe_load((HOST / "provisioning/datasources/victoria.yaml").read_text())
    for d in ds["datasources"]:
        assert d["editable"] is False, f"{d['name']} is editable from the UI"


def test_every_datasource_has_an_explicit_uid():
    """Without one Grafana generates a random uid at first start.

    A dashboard would then bind to whatever that host happened to generate, and
    REBUILDING THE HOST would silently orphan every panel — the dashboards
    would load, look right, and show nothing.
    """
    ds = yaml.safe_load((HOST / "provisioning/datasources/victoria.yaml").read_text())
    for d in ds["datasources"]:
        assert d.get("uid"), f"{d['name']} has no explicit uid"


def test_dashboards_only_reference_datasources_that_exist():
    """A panel pointing at a missing datasource renders empty, not broken.

    That is the failure worth catching here: nothing errors, the dashboard just
    quietly shows no data, and it looks like the metric is missing.
    """
    ds = yaml.safe_load((HOST / "provisioning/datasources/victoria.yaml").read_text())
    known = {d["uid"] for d in ds["datasources"]}
    boards = sorted((HOST / "dashboards").glob("*.json"))
    assert boards, "no dashboards — the home dashboard would 404"
    for board in boards:
        data = json.loads(board.read_text())
        for panel in data.get("panels", []):
            uid = (panel.get("datasource") or {}).get("uid")
            if uid:
                assert uid in known, f"{board.name}: panel '{panel['title']}' -> {uid}"


def test_the_home_dashboard_named_in_the_config_exists(ini):
    """Grafana falls back to a stock page if the path is wrong, so this fails
    silently and looks like a preference rather than a mistake."""
    path = ini["dashboards"]["default_home_dashboard_path"]
    assert path.startswith("/var/lib/grafana/dashboards/")
    assert (
        HOST / "dashboards" / Path(path).name
    ).is_file(), f"grafana.ini points at {path}, which this repository does not ship"


def test_grafana_binds_the_bridge_and_knows_its_public_url(ini):
    """Two settings that fail in confusing ways.

    Binding 0.0.0.0 would put Grafana on the LAN behind no TLS. And without
    root_url Grafana emits redirects to its bind address, so login breaks in a
    way that reads as a proxy fault.
    """
    import siteconfig

    cfg = siteconfig.load_model()
    assert ini["server"]["http_addr"] == "172.18.0.1"
    # Asserting the RELATIONSHIP, not a literal hostname. A hardcoded value here
    # would pass while the deployed file said something else — and the whole
    # reason this is a template is that the name is not the repository's to know.
    assert ini["server"]["root_url"] == f"https://{cfg.observability.hostname}/"


def test_the_admin_password_is_not_in_the_repository(ini):
    """It comes from a 0600 EnvironmentFile. The config file is committed."""
    assert "admin_password" not in ini["security"]
    # NAMING the environment variable in a comment is correct and useful — it
    # tells a reader where the secret comes from. What must not appear is an
    # assignment giving it a value.
    for raw in (HOST / "grafana.ini.template").read_text().splitlines():
        line = raw.strip()
        if line.startswith((";", "#")):
            continue
        assert (
            "GF_SECURITY_ADMIN_PASSWORD" not in line
        ), f"grafana.ini assigns the admin password: {line}"


def test_it_does_not_phone_home(ini):
    """An outbound call from the one host that can see everything is a call
    nobody is watching."""
    assert ini["analytics"]["reporting_enabled"] == "false"
    assert ini["analytics"]["check_for_updates"] == "false"
    assert ini["snapshots"]["external_enabled"] == "false"
    assert ini["auth.anonymous"]["enabled"] == "false"
    # check_for_updates covers Grafana's own version and nothing else. Plugin
    # update checks are a separate default-true setting, and this assertion
    # passed for the whole time Grafana was calling grafana.com every ten
    # minutes: the test asserted the setting that was named, not the behaviour
    # the docstring claims.
    assert ini["analytics"]["check_for_plugin_updates"] == "false"


def test_grafana_does_not_try_to_write_into_its_own_program_tree(ini):
    """Preinstalled plugins are installed into the homepath, which is read-only.

    ProtectSystem=strict is doing its job when this fails; the error is Grafana
    asking for something it should not have. Granting the write would be the
    wrong repair — the plugins involved (mysql, elasticsearch) are datasources
    nothing here provisions.
    """
    assert ini["plugins"]["preinstall_disabled"] == "true"


def test_github_auth_is_never_enabled_without_an_organisation():
    """Grafana's `allowed_organizations` FAILS OPEN.

    With `[auth.github] enabled = true` and no org, the default is not "nobody"
    — it is EVERYBODY with a GitHub account. A one-line difference between a
    private dashboard and a public one, in the direction that does not announce
    itself, so the renderer refuses the combination (ADR-103).
    """
    import importlib.util
    import sys

    import siteconfig

    spec = importlib.util.spec_from_file_location(
        "dobs2", REPO / "deploy-observability.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["dobs2"] = module
    spec.loader.exec_module(module)

    cfg = siteconfig.load_model()
    cfg.observability.github_org = ""
    rendered = module.grafana_ini(cfg).decode()

    section = rendered.split("[auth.github]", 1)[1]
    assert "enabled = false" in section, "GitHub auth on with no org lets anyone in"
    # And the substituted placeholder cannot match a real organisation, so a
    # template bug fails closed rather than admitting everyone.
    assert "allowed_organizations = !none" in section


def test_the_public_hostname_is_not_hardcoded_in_the_repository():
    """This repository is going public and the project is being RENAMED.

    A hostname or org name baked into a committed file is the same mistake
    ADR-094 caught in the cosign identity: one deployment's identity shipped to
    everyone who clones it.
    """
    template = (HOST / "grafana.ini.template").read_text()
    route = (HOST / "traefik/observe.yml.template").read_text()
    for name, text in (("grafana.ini.template", template), ("observe.yml", route)):
        assert "bradpenney" not in text, f"{name} hardcodes this estate's identity"
        assert "__HOSTNAME__" in text, f"{name} should template the hostname"


def test_grafana_keeps_its_data_outside_the_program_tree():
    """State must not live where an upgrade deletes it.

    Grafana defaults data, logs and plugins to $homepath — inside
    /usr/local/share/grafana. ProtectSystem=strict caught it as a read-only
    filesystem error on first start, but the real hazard is install_tree, which
    upgrades a component by `mv`ing the old tree aside and `rm -rf`ing it. A
    writable data directory there would have survived exactly until the next
    version bump, and taken every dashboard with it.
    """
    ini = (REPO / "observability-host" / "grafana.ini.template").read_text()
    assert "[paths]" in ini, "grafana.ini declares no paths; data defaults into /usr"
    assert "data = /var/lib/grafana" in ini
    assert "logs = /var/lib/grafana" in ini
    # Provisioning is configuration, not state: it belongs where the deploy
    # writes it and the drift check can checksum it.
    assert "provisioning = /etc/grafana/provisioning" in ini


def test_the_unit_creates_the_state_directory_it_points_at():
    """A path in grafana.ini that no one creates is a startup failure."""
    unit = (REPO / "systemd/observability/grafana.service").read_text()
    assert "StateDirectory=grafana" in unit
