"""Static assertions over the systemd units this repo deploys fleet-wide.

Every rule here corresponds to a defect that actually shipped (ADR-077). They
are static because all four failure modes are invisible at runtime: the unit
loads, the timer is enabled, `systemctl status` is clean, and the thing simply
does not do what the file appears to say.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

UNIT_DIR_NAME = "systemd"


def _units(repo_root):
    """Every unit this repo ships, at any depth.

    RECURSIVE deliberately. `iterdir()` was not, so the moment units were
    grouped into `systemd/observability/` they became invisible to every
    assertion in this file — silently, while the suite stayed green. A test
    that stops covering new files is worse than no test, because it reports
    confidence it no longer has.
    """
    d = repo_root / UNIT_DIR_NAME
    return sorted(p for p in d.rglob("*") if p.suffix in (".service", ".timer"))


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
                    # A template instance `foo@%n.service` is shipped as the
                    # template `foo@.service`. Comparing the literal string
                    # would reject a correct reference.
                    if "@" in target:
                        prefix, _, suffix = target.partition("@")
                        target = f"{prefix}@{suffix[suffix.index('.'):]}"
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


def test_units_that_retry_declare_their_retry_policy(repo_root):
    """A restarting unit must say EXPLICITLY whether its retries are bounded.

    The original rule required `StartLimitBurst`, which is correct for the
    oneshot units — a permanent fault would otherwise loop forever, firing
    OnFailure on every entry into the failed state.

    It is wrong for a long-running daemon. Grafana and VictoriaMetrics should
    restart forever: giving up after five attempts leaves no observability at
    exactly the moment something is wrong. `StartLimitIntervalSec=0` is how you
    say "unbounded, deliberately".

    So the rule is not "bounded" but "not silently defaulted": one or the other
    must be present, in [Unit], and the choice is visible in the file.
    """
    for unit in _units(repo_root):
        secs = _sections(unit)
        restarts = [
            v for k, v in secs.get("Service", []) if k == "Restart" and v != "no"
        ]
        if not restarts:
            continue
        unit_keys = {k for k, _ in secs.get("Unit", [])}
        assert unit_keys & {"StartLimitBurst", "StartLimitIntervalSec"}, (
            f"{unit.name}: Restart={restarts[0]} with no retry policy. Declare "
            f"StartLimitBurst (bounded) or StartLimitIntervalSec=0 (deliberately "
            f"unbounded) in [Unit]."
        )


def test_start_limit_keys_are_in_the_unit_section(repo_root):
    """`StartLimitIntervalSec`/`StartLimitBurst` in [Service] are IGNORED.

    systemd moved them to [Unit] and says so only as
    `Unknown key 'StartLimitIntervalSec' in section [Service], ignoring.` —
    which nothing reads. The file then appears to configure a retry policy while
    the default ("give up after 5 restarts in 10s") silently remains in force.

    Same family as OnFailure-in-[Service], and made in this repo on 2026-08-30
    while writing the comment warning about OnFailure. Caught by
    `systemd-analyze verify`; asserted here so it cannot recur unnoticed.
    """
    for unit in _units(repo_root):
        misplaced = [
            k
            for k, _ in _sections(unit).get("Service", [])
            if k.startswith("StartLimit")
        ]
        assert not misplaced, (
            f"{unit.name}: {misplaced[0]} in [Service] is ignored by systemd — "
            f"move it to [Unit]"
        )


def test_systemd_itself_accepts_every_unit(repo_root):
    """Ask systemd, rather than only asserting what we remember about systemd.

    The static checks above encode specific traps this estate has hit. They
    cannot catch the next one. `systemd-analyze verify` parses a unit with the
    real parser and reports unknown keys, bad section names and malformed
    directives — which is how the misplaced StartLimitIntervalSec was found.

    Missing-binary warnings are expected and ignored: these units reference
    /usr/local/bin paths that exist on the hypervisors, not in a checkout or on
    a CI runner. Everything else is a failure.
    """
    if shutil.which("systemd-analyze") is None:
        pytest.skip("systemd-analyze not available")

    problems = []
    for unit in _units(repo_root):
        proc = subprocess.run(
            ["systemd-analyze", "verify", str(unit)],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in (proc.stderr + proc.stdout).splitlines():
            if not line.strip():
                continue
            # Not a defect in the unit: the binary lives on the target host.
            if "is not executable" in line or "does not exist" in line:
                continue
            problems.append(f"{unit.name}: {line.strip()}")

    assert not problems, "systemd rejected a unit:\n  " + "\n  ".join(problems)


def test_onfailure_instances_do_not_double_the_unit_suffix(repo_root):
    """`OnFailure=notify@%n.service` yields `notify@foo.service.service`.

    `%n` is the FULL unit name, suffix included, so appending `.service`
    duplicates it. systemd loads the doubled name without complaint, which is
    why this shipped: the alert works and reads wrong, and nothing fails. `%p`
    is the prefix without the suffix.
    """
    for unit in _units(repo_root):
        for key, value in _sections(unit).get("Unit", []):
            if key != "OnFailure":
                continue
            for target in value.split():
                assert "%n" not in target, (
                    f"{unit.name}: OnFailure={target} — %n includes the unit "
                    f"suffix, so this expands to a doubled '.service'. Use %p."
                )
