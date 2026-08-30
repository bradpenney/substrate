"""The two bootstrap implementations must stay interchangeable.

These wrap the repo's existing standalone checkers so they run in CI on every
push rather than only when someone remembers. They are the highest-value tests
here: ADR-020's whole premise is that a defect in one implementation is caught
by disagreement with the other, and that only holds if the two are continuously
compared.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

CHECKERS = [
    ("ansible/check_render.py", "cloud-config renderers must agree byte-for-byte"),
    ("ansible/check_drift.py", "both implementations must read site.yml identically"),
]


@pytest.mark.parametrize("script,why", CHECKERS, ids=[c[0] for c in CHECKERS])
def test_implementations_agree(repo_root, script, why):
    path = repo_root / script
    if not path.exists():
        pytest.skip(f"{script} not present")
    result = subprocess.run(
        [sys.executable, str(path)],
        cwd=repo_root, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(repo_root)},
    )
    assert result.returncode == 0, f"{why}\n{result.stdout}\n{result.stderr}"


def test_ansible_template_covers_every_hardening_feature(repo_root):
    """A feature added to provision.py but not the Jinja template would build two
    different clusters while both runs reported success. check_render.py catches
    this for the fixture's shape; this catches a feature that is conditional and
    therefore absent from the rendered sample entirely."""
    py = (repo_root / "provision.py").read_text()
    j2 = (repo_root / "ansible/roles/k0s_node/templates/cloud-config.yaml.j2").read_text()
    features = [
        "workerProfiles", "systemReserved", "kubeReserved", "evictionHard",
        "encryption-provider-config", "audit-policy-file", "matchOIDCIdentity",
    ]
    missing = [f for f in features if f in py and f not in j2]
    assert not missing, f"present in provision.py but absent from the Ansible template: {missing}"
