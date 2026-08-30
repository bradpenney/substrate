"""Point every test at the synthetic site config, before anything imports it.

`siteconfig.SITE_FILE` is resolved at IMPORT time from $SUBSTRATE_SITE_FILE, so
this has to happen before the first `import hosts` anywhere in the suite —
pytest imports conftest first, which is exactly the hook needed. Nothing here
may import hosts/provision/gate at module scope, or the override comes too late.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SITE = REPO_ROOT / "tests" / "fixtures" / "site.yml"

# setdefault, not assignment: an explicit $SUBSTRATE_SITE_FILE must win, so the
# suite can be pointed at the REAL site.yml on a configured machine to check the
# fixture has not drifted from the live schema. CI has no site.yml, so it always
# gets the fixture.
os.environ.setdefault("SUBSTRATE_SITE_FILE", str(FIXTURE_SITE))
# A real key here would make render_cloud_config emit a real pull secret.
os.environ.setdefault(
    "HOMELAB_SSH_PUBLIC_KEY", "ssh-ed25519 AAAATESTKEYONLY test@fixture"
)

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


import pytest  # noqa: E402


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def joining_vm():
    import hosts

    return next(v for h in hosts.HOSTS for v in h.vms if not v.bootstrap)


@pytest.fixture(scope="session")
def bootstrap_vm():
    import hosts

    return next(v for h in hosts.HOSTS for v in h.vms if v.bootstrap)
