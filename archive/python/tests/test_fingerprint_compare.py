"""The end-state comparison is the payoff of building the platform twice.

ADR-020's premise is that a defect in one bootstrap implementation is caught by
disagreement with the other. That only holds if `compare` reports real
differences and only real ones — on 2026-08-28 it reported
`konnectivity-agent: python=4 vs ansible=5` for two clusters that were both
correct (ADR-080). The bug was upstream, in the readiness gate that let the
fingerprint be sampled mid-rollout; these tests pin the comparison itself so a
future fix cannot quietly weaken it into always agreeing.
"""

from __future__ import annotations

import gate


def test_identical_states_agree():
    a = {"nodes": ["x", "y"], "workloads": {"kube-system/daemonsets/ka": 5}}
    assert gate.compare_fingerprints(a, dict(a), "python", "ansible") is True


def test_differing_value_is_reported(capsys):
    a = {"workloads": {"kube-system/daemonsets/ka": 4}}
    b = {"workloads": {"kube-system/daemonsets/ka": 5}}
    assert gate.compare_fingerprints(a, b, "python", "ansible") is False
    out = capsys.readouterr().out
    assert "workloads.kube-system/daemonsets/ka" in out
    assert "python=4" in out and "ansible=5" in out


def test_key_present_on_only_one_side_is_reported(capsys):
    """A workload that exists after one method and not the other is the single
    most important thing this comparison can catch."""
    a = {"workloads": {"only-in-a": 1}}
    b = {"workloads": {}}
    assert gate.compare_fingerprints(a, b, "python", "ansible") is False
    assert "only-in-a" in capsys.readouterr().out


def test_nested_differences_are_found_not_just_top_level(capsys):
    a = {"platform": {"flux": {"source": "oci://example/one"}}}
    b = {"platform": {"flux": {"source": "oci://example/two"}}}
    assert gate.compare_fingerprints(a, b, "python", "ansible") is False
    assert "platform.flux.source" in capsys.readouterr().out


def test_every_difference_is_reported_not_just_the_first(capsys):
    """Stopping at the first difference would hide the rest behind one fix."""
    a = {"one": 1, "two": 2, "three": 3}
    b = {"one": 9, "two": 9, "three": 9}
    gate.compare_fingerprints(a, b, "python", "ansible")
    out = capsys.readouterr().out
    for key in ("one", "two", "three"):
        assert key in out


def test_empty_states_do_not_silently_agree(capsys):
    """Two empty fingerprints are equal, but that means the fingerprint collected
    nothing — which must not read as 'the methods agree'."""
    assert gate.compare_fingerprints({}, {}, "python", "ansible") is True
    # Documents current behaviour: emptiness is NOT distinguished from agreement.
    # If save_fingerprint ever silently produces {}, compare will bless it.
    assert "IDENTICAL" in capsys.readouterr().out
