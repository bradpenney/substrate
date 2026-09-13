"""Every variable the shipped scripts REQUIRE must be written by the deploy.

Regression, 2026-08-29. `deploy_updates.py` shipped a newer
`hypervisor-update.sh` than its own `update.env` writer knew about. The script
guards its inputs with `${VAR:?message}`, so the missing one aborted the nightly
update on BOTH hypervisors at 03:30:

    SSH_USER: SSH_USER must be set — the unprivileged account used for peer
    health checks

Nothing catches this at deploy time: the files copy fine, systemd loads the unit
fine, and the failure only appears the next time the timer fires. It is an
integration gap between two files in the same repo — exactly the seam a unit test
can cover cheaply.
"""

from __future__ import annotations

import re

import pytest

# Scripts installed by deploy_updates.py, and the env file it writes for them.
DEPLOYED_SCRIPTS = ["hypervisor-update.sh", "hypervisor-uncordon.sh"]

# `${NAME:?...}` and `${NAME?...}` — the shell's "required or abort" forms.
REQUIRED = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\??:?\?")


def _required_vars(path):
    return set(REQUIRED.findall(path.read_text()))


def _written_vars(repo_root):
    """Variables deploy_updates.py writes into /etc/homelab/update.env."""
    src = (repo_root / "deploy_updates.py").read_text()
    # The env block is built as f-string lines of the form  f"NAME={...}\n"
    return set(re.findall(r'f"([A-Z_][A-Z0-9_]*)=', src))


@pytest.mark.parametrize("script", DEPLOYED_SCRIPTS)
def test_every_required_var_is_supplied_by_the_deploy(repo_root, script):
    path = repo_root / script
    if not path.exists():
        pytest.skip(f"{script} not present")
    required = _required_vars(path)
    if not required:
        pytest.skip(f"{script} declares no required variables")
    missing = required - _written_vars(repo_root)
    assert not missing, (
        f"{script} requires {sorted(missing)} via ${{VAR:?}}, but deploy_updates.py "
        f"never writes it to /etc/homelab/update.env — the unit will abort the "
        f"next time its timer fires, not at deploy time"
    )


def test_ssh_user_specifically_is_written(repo_root):
    """The one that actually broke, pinned by name so a refactor cannot drop it.

    root under systemd has no SSH key and should not have one; peer health checks
    run as the unprivileged admin user instead.
    """
    assert "SSH_USER" in _written_vars(repo_root)


def test_the_regex_actually_matches_the_shell_form(repo_root):
    """Guards the guard: if this pattern stopped matching, the test above would
    pass vacuously by finding nothing to require."""
    path = repo_root / "hypervisor-update.sh"
    if not path.exists():
        pytest.skip("hypervisor-update.sh not present")
    assert "SSH_USER" in _required_vars(
        path
    ), "the ${VAR:?} detector matched nothing — this suite would silently stop checking"
