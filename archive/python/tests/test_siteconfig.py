"""site.yml shape checks: fail at parse time, not at 03:00 or mid-build.

Each of these corresponds to a failure that is cheap to catch here and
genuinely miserable to debug later — the comments in siteconfig.py say so, and
these tests make sure the checks survive a refactor.
"""

from __future__ import annotations

import copy

import pytest

import siteconfig


def _cfg(**over):
    """A minimal but genuinely VALID config, so each test fails for its own reason."""
    base = {
        "admin_user": "operator",
        "network": {"gateway": "10.99.0.1"},
        "hypervisors": {"hvA": {"ssh_target": "operator@10.99.0.11"}},
        "control_plane": {"vip": "10.99.0.99"},
        "nodes": {
            "n1": {"hypervisor": "hvA", "ip": "10.99.0.20", "bootstrap": True},
            "n2": {"hypervisor": "hvA", "ip": "10.99.0.21"},
        },
        "defaults": {},
        "k0s": {},
        "libvirt": {},
    }
    base.update(copy.deepcopy(over))
    return base


def test_the_valid_baseline_passes():
    """If this ever fails, every other test here is failing for the wrong reason."""
    siteconfig._validate(_cfg())


@pytest.mark.parametrize(
    "missing",
    ["admin_user", "network", "hypervisors", "nodes", "defaults", "k0s", "libvirt"],
)
def test_missing_top_level_section_fails_early(missing):
    """Rather than a KeyError after the ISO has downloaded and two VMs exist."""
    cfg = _cfg()
    del cfg[missing]
    with pytest.raises(SystemExit) as e:
        siteconfig._validate(cfg)
    assert missing in str(e.value)


def test_local_hypervisor_without_peer_target_is_rejected():
    """`ssh_target: null` means local, so nothing else carries an address the
    PEER could use — and the nightly reboot gate needs exactly that. Left
    unchecked it surfaces at 03:00 as a health check with no peer to ask."""
    with pytest.raises(SystemExit) as e:
        siteconfig._validate(_cfg(hypervisors={"hvA": {"ssh_target": None}}))
    assert "peer_target" in str(e.value)


def test_local_hypervisor_with_peer_target_is_accepted():
    siteconfig._validate(
        _cfg(
            hypervisors={
                "hvA": {"ssh_target": None, "peer_target": "operator@10.99.0.11"}
            }
        )
    )


def test_a_node_may_not_sit_on_the_control_plane_vip():
    """Caught during the ADR-046 retopology. Nothing fails at provisioning time:
    the VM boots fine, then keepalived ARPs for an address a live host already
    answers for, producing intermittent control-plane failures."""
    cfg = _cfg()
    cfg["nodes"]["n2"]["ip"] = cfg["control_plane"]["vip"]
    with pytest.raises(SystemExit) as e:
        siteconfig._validate(cfg)
    assert "10.99.0.99" in str(e.value)


def test_a_hypervisor_may_not_be_addressed_by_the_vip():
    """Same collision, other direction: SSHing to the VIP reaches whichever host
    currently holds it, so provisioning would target a moving address."""
    with pytest.raises(SystemExit) as e:
        siteconfig._validate(
            _cfg(hypervisors={"hvA": {"ssh_target": "operator@10.99.0.99"}})
        )
    assert "10.99.0.99" in str(e.value)


def test_exactly_one_bootstrap_node_is_required():
    """The bootstrap node comes up first and alone; every other node joins with a
    token minted from it."""
    cfg = _cfg()
    for node in cfg["nodes"].values():
        node.pop("bootstrap", None)
    with pytest.raises(SystemExit) as e:
        siteconfig._validate(cfg)
    assert "bootstrap" in str(e.value)

    cfg = _cfg()
    cfg["nodes"]["n2"]["bootstrap"] = True
    with pytest.raises(SystemExit) as e:
        siteconfig._validate(cfg)
    assert "bootstrap" in str(e.value)


def test_the_shipped_fixture_passes_its_own_validation():
    """Guards against the fixture drifting into a shape the real loader rejects."""
    siteconfig._validate(siteconfig.load())


def test_failure_prone_host_may_not_be_the_vrrp_preferred_one(tmp_path):
    """Two encodings of "which host is unreliable" must not disagree.

    `failure_prone` and `control_plane.priorities` state the same judgement.
    This project has been caught repeatedly by one fact written in two places
    and drifting, so the contradiction is rejected rather than believed.
    """
    cfg = siteconfig.load()
    # Move the flag rather than adding one: with BOTH hosts marked, the
    # "every hypervisor" branch fires first and this test would pass for
    # the wrong reason.
    cfg["hypervisors"]["hvA"]["failure_prone"] = False
    cfg["hypervisors"]["hvB"]["failure_prone"] = True
    with pytest.raises(SystemExit) as exc:
        siteconfig._validate_failure_domains(cfg)
    assert "highest VRRP priority" in str(exc.value)
    assert "hvB" in str(exc.value)


def test_marking_every_host_failure_prone_is_rejected(tmp_path):
    """If nowhere is safe the flag carries no information."""
    cfg = siteconfig.load()
    for hv in cfg["hypervisors"].values():
        hv["failure_prone"] = True
    with pytest.raises(SystemExit) as exc:
        siteconfig._validate_failure_domains(cfg)
    assert "every hypervisor" in str(exc.value)
