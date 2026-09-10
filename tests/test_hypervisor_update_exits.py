"""The two kinds of not-rebooting must stay distinguishable.

WHY THIS FILE EXISTS
`hypervisor-update.sh` has two outcomes where it correctly does NOT reboot:
"no reboot required" and "reboot needed but not safe right now". Until
2026-09-10 the first exited 0 and the second exited 1, so a safety gate WORKING
was indistinguishable from dnf breaking — and the consequences were not
cosmetic. On 2026-09-10 server1 correctly declined to reboot while server2 was
mid-reboot, which produced a failed unit, an ntfy page, a posture-check
reporting a BROKEN security invariant, and posture-check marking itself failed
as a result (ADR-165).

These tests read the SCRIPT and the UNIT as text. That is deliberate: running
the real thing means rebooting a hypervisor, and the property being protected is
structural — which conditions map to which exit status, and whether systemd is
told that 75 is a success.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = (REPO / "hypervisor-update.sh").read_text()
UNIT = (REPO / "systemd" / "hypervisor-update.service").read_text()

DEFERRED = "75"


def _exit_paths() -> list[tuple[str, str]]:
    """Every exit in the script, paired with the nearest preceding log message."""
    lines = SCRIPT.splitlines()
    out: list[tuple[str, str]] = []
    for i, line in enumerate(lines):
        m = re.match(r'\s*exit ("?\$?\w+"?)\s*$', line)
        if not m:
            continue
        # Strip quotes but KEEP the `$`: the script writes `exit "$DEFERRED"`,
        # and normalising that to a bare name would let a literal `exit 75`
        # pass this test while bypassing the single definition.
        code = m.group(1).strip('"')
        # ALL log lines in the preceding window, not just the nearest. The
        # non-Ready-nodes gate logs its explanation and THEN the node list, so
        # taking only the closest one finds `log "$not_ready"` and misses the
        # message that says what happened.
        context_lines = [
            lines[j].split('log "', 1)[1]
            for j in range(max(0, i - 6), i)
            if 'log "' in lines[j]
        ]
        out.append((code, " | ".join(context_lines)))
    return out


def test_the_unit_tells_systemd_that_75_is_a_success():
    """Without this the whole change is inert.

    The script would exit 75, systemd would still call it a failure, the unit
    would still go degraded, and OnFailure= would still page. The script and the
    unit are one change; either alone does nothing.
    """
    assert "SuccessExitStatus=75" in UNIT


def test_the_unit_still_has_an_OnFailure_so_real_faults_still_page():
    """Silencing deferrals must not silence everything.

    This unit failed five nights running with no OnFailure at all and nobody
    knew. Making refusals quiet is only safe while genuine faults stay loud.
    """
    assert re.search(r"^OnFailure=", UNIT, re.MULTILINE)
    # And in [Unit], not [Service], where systemd ignores it silently.
    unit_section = UNIT.split("[Service]")[0]
    assert "OnFailure=" in unit_section


def test_conditions_that_are_NORMAL_defer_rather_than_fail():
    """The gates are supposed to fire regularly.

    Two hypervisors on nightly timers collide as a matter of course, and one
    peer reboot trips three of these at once: its lock is present, its VMs are
    not running, and its cluster nodes are not Ready.
    """
    normal = ["mid-reboot", "VMs not running", "non-Ready nodes", "still running after"]
    paths = _exit_paths()
    for phrase in normal:
        matching = [(c, ctx) for c, ctx in paths if phrase in ctx]
        assert matching, f"no exit path found for {phrase!r} — did a gate move?"
        for code, ctx in matching:
            assert code == "$DEFERRED", (
                f"{phrase!r} exits {code}, not the deferral status. "
                f"A gate that refuses correctly must not report a fault: {ctx!r}"
            )


def test_conditions_that_are_genuine_FAULTS_still_exit_one():
    """A deferral is quiet. A fault must not be.

    `dnf` failing means this host is unpatched. An unreachable peer means a
    hypervisor may be down. A stale local lock means a previous run did not
    finish. None of those get better by being retried silently tomorrow.
    """
    faults = ["dnf upgrade failed", "unreachable", "local reboot lock present"]
    paths = _exit_paths()
    for phrase in faults:
        matching = [(c, ctx) for c, ctx in paths if phrase in ctx]
        assert matching, f"no exit path found for {phrase!r}"
        for code, ctx in matching:
            assert code == "1", (
                f"{phrase!r} exits {code}; a genuine fault must still fail "
                f"loudly: {ctx!r}"
            )


def test_the_deferred_status_is_defined_once_and_is_EX_TEMPFAIL():
    """75 is EX_TEMPFAIL from sysexits.h — 'transient, retry later'.

    Defined once so the script and this test cannot drift apart, and chosen
    rather than invented so a reader who looks it up finds the right meaning.
    """
    assert re.search(r"^DEFERRED=75\s*$", SCRIPT, re.MULTILINE)
    assert SCRIPT.count("DEFERRED=") == 1, "the status must be defined exactly once"


def test_no_exit_path_is_left_undocumented():
    """Every exit should be reachable from a log line explaining it.

    An exit with no nearby message is one nobody can diagnose from the journal,
    and this script's whole failure mode was being hard to interpret.
    """
    for code, ctx in _exit_paths():
        assert ctx, f"an `exit {code}` has no preceding log message"
