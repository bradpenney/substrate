"""Static assertions over the systemd units this repo deploys fleet-wide.

Every rule here corresponds to a defect that actually shipped (ADR-077). They
are static because all four failure modes are invisible at runtime: the unit
loads, the timer is enabled, `systemctl status` is clean, and the thing simply
does not do what the file appears to say.
"""

from __future__ import annotations

import re

import pytest

UNIT_DIR_NAME = "systemd"


def _units(repo_root):
    d = repo_root / UNIT_DIR_NAME
    return sorted(p for p in d.iterdir() if p.suffix in (".service", ".timer"))


def _sections(path):
    """Parse a unit into {section: [(key, value)]}. Not configparser: systemd
    allows repeated keys, and which SECTION a key sits in is the whole point."""
    out, current = {}, None
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        if s.startswith("[") and s.endswith("]"):
            current = s[1:-1]
            out.setdefault(current, [])
        elif "=" in s and current:
            k, _, v = s.partition("=")
            out[current].append((k.strip(), v.strip()))
    return out


def test_units_exist(repo_root):
    assert _units(repo_root), "no unit files found — has the layout moved?"


def test_no_timer_requires_its_own_service(repo_root):
    """Regression bug-017. On a timer, `[Unit] Requires=<own>.service` is a START
    dependency: every boot, timers.target brings the timer up and systemd starts
    the service immediately, ignoring OnCalendar. Symptom is a scheduled job
    whose failures all land 15-20s after a boot. Use `[Timer] Unit=` instead."""
    for unit in _units(repo_root):
        if unit.suffix != ".timer":
            continue
        keys = _sections(unit).get("Unit", [])
        offenders = [v for k, v in keys if k == "Requires" and v.endswith(".service")]
        assert not offenders, (
            f"{unit.name}: [Unit] Requires={offenders} makes the service run at every "
            f"boot regardless of OnCalendar — declare [Timer] Unit= instead"
        )


def test_onfailure_is_declared_in_the_unit_section(repo_root):
    """Regression: `OnFailure=` in `[Service]` is SILENTLY ignored — systemctl
    show reports it empty and the alert never fires. Grepping the file is not a
    check; the section is."""
    for unit in _units(repo_root):
        secs = _sections(unit)
        in_service = [v for k, v in secs.get("Service", []) if k == "OnFailure"]
        assert (
            not in_service
        ), f"{unit.name}: OnFailure in [Service] is ignored by systemd — move it to [Unit]"


def test_onfailure_targets_are_shipped_by_this_repo(repo_root):
    """A dangling OnFailure surfaces only as a journal line at 3am, on the one
    night it was needed."""
    names = {p.name for p in _units(repo_root)}
    for unit in _units(repo_root):
        for key, value in _sections(unit).get("Unit", []):
            if key == "OnFailure":
                for target in value.split():
                    assert (
                        target in names
                    ), f"{unit.name}: OnFailure={target} is not shipped by this repo"


def test_fleet_wide_units_do_not_reference_the_homelab_checkout(repo_root):
    """Regression bug-019. These units are installed on EVERY hypervisor, and
    only one of them has a ~/homelab checkout — so a unit pointing there
    provides alerting that silently does not exist on the other host."""
    # Specifically the per-user CHECKOUT (/home/<someone>/homelab/...), not
    # /etc/homelab/, which is a root-owned config dir that does exist everywhere.
    checkout = re.compile(r"/home/[^/\s]+/homelab/")
    for unit in _units(repo_root):
        found = checkout.findall(unit.read_text())
        assert not found, (
            f"{unit.name} references {found[0]}; that checkout does not exist on every "
            f"hypervisor. Use /usr/local/bin/homelab-notify.sh."
        )


def test_admin_user_stays_a_placeholder(repo_root):
    """ADR-012: the repo carries no identity. deploy-auto-roll.sh substitutes the
    real user at install time, so a repo-vs-live diff here is CORRECT."""
    unit = repo_root / UNIT_DIR_NAME / "auto-roll.service"
    if not unit.exists():
        pytest.skip("auto-roll.service not present")
    body = unit.read_text()
    for key, value in _sections(unit).get("Service", []):
        if key in ("User", "Group"):
            assert (
                value == "__ADMIN_USER__"
            ), f"auto-roll.service {key}={value} — a real identity leaked into the repo"


def test_units_that_retry_also_bound_their_retries(repo_root):
    """`Restart=on-failure` without a start limit can loop indefinitely on a
    permanent fault, and each entry into the failed state fires OnFailure again."""
    for unit in _units(repo_root):
        secs = _sections(unit)
        restarts = [
            v for k, v in secs.get("Service", []) if k == "Restart" and v != "no"
        ]
        if not restarts:
            continue
        unit_keys = {k for k, _ in secs.get("Unit", [])}
        assert (
            "StartLimitBurst" in unit_keys
        ), f"{unit.name}: Restart={restarts[0]} without StartLimitBurst is unbounded"
