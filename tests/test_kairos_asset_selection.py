"""The node-patching path's decision logic — previously untested.

`select_kairos_asset.py` picks which Kairos ISO the fleet rolls onto. It exists
as a file rather than inline shell precisely so it can be tested (ADR-032), and
it guards two mistakes that ALREADY happened:

  * Kairos ships a build MATRIX — v4.2.0 carried k0s 1.34.10, 1.35.7 and 1.36.3
    in one release — so `head -1` once selected a two-minor DOWNGRADE purely
    from asset ordering;
  * taking the highest blindly can skip a minor version, exceeding Kubernetes'
    supported upgrade skew.

Both failures would be applied by a bot, to every node, unattended. The refusals
are the safety property, so they are what is asserted here.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parent.parent / ".github/scripts/select_kairos_asset.py"
)


def iso(k0s: str, flavour: str = "kairos-hadron-v0.5.1-standard-amd64-generic") -> str:
    # `+` arrives URL-encoded as %2B from the GitHub API — the real-world form.
    return f"https://example.invalid/{flavour}-v4.2.0-k0sv{k0s}%2Bk0s.2.iso"


def run(assets, current_url):
    release = {"assets": [{"browser_download_url": u} for u in assets]}
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--current-url", current_url],
        input=json.dumps(release),
        capture_output=True,
        text=True,
        check=False,
    )


CURRENT = iso("1.36.3")


def test_picks_the_highest_k0s_from_a_build_matrix():
    """The real v4.2.0 shape: three k0s versions in one release, deliberately
    NOT in ascending order, so ordering alone cannot produce the right answer."""
    r = run([iso("1.34.10"), iso("1.36.4"), iso("1.35.7")], CURRENT)
    assert r.returncode == 0, r.stderr
    assert "k0sv1.36.4" in r.stdout


def test_refuses_a_downgrade():
    """Kubernetes has no supported downgrade path; a bot must not attempt one."""
    r = run([iso("1.35.7"), iso("1.34.10")], CURRENT)
    assert r.returncode == 1
    assert "REFUSING" in r.stderr and "older than" in r.stderr


def test_refuses_to_skip_a_minor():
    """At most +1 minor per upgrade — roll through the intermediate release."""
    r = run([iso("1.38.0")], CURRENT)
    assert r.returncode == 1
    assert "REFUSING" in r.stderr and "skips a minor" in r.stderr


def test_allows_exactly_one_minor():
    r = run([iso("1.37.1")], CURRENT)
    assert r.returncode == 0, r.stderr
    assert "MINOR upgrade" in r.stderr


def test_allows_a_patch_upgrade():
    r = run([iso("1.36.9")], CURRENT)
    assert r.returncode == 0, r.stderr
    assert "patch upgrade" in r.stderr


def test_holds_the_flavour_constant():
    """Switching flavour is an architectural change, not a version bump — a
    higher k0s in the wrong flavour must not be selected."""
    r = run([iso("1.37.0", "kairos-alpine-v0.5.1-standard-amd64-generic")], CURRENT)
    assert r.returncode == 1
    assert "no matching" in r.stderr


def test_refuses_when_the_current_version_is_unparseable():
    """Better to stop than to guess what the fleet is running."""
    r = run([iso("1.36.4")], "https://example.invalid/mystery.iso")
    assert r.returncode == 1
    assert "refusing to guess" in r.stderr


def test_ignores_non_iso_assets():
    release_assets = ["https://example.invalid/checksums.txt", iso("1.36.4")]
    r = run(release_assets, CURRENT)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().endswith(".iso")


def test_survives_control_characters_in_the_release_body():
    """GitHub release bodies contain raw control characters that Python's strict
    JSON parser rejects but jq tolerates — hence strict=False."""
    release = {
        "body": "notes\x07with\x01control chars",
        "assets": [{"browser_download_url": iso("1.36.4")}],
    }
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--current-url", CURRENT],
        input=json.dumps(release),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
