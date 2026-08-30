"""Regression tests for the single-sudo deploy payload (ADR-078, bug-020)."""

from __future__ import annotations

import io
import os
import subprocess
import tarfile
import tempfile
import time

import deploy_updates


FILES = [
    (b"#!/bin/bash\necho hi\n", "usr/local/bin/thing.sh", 0o755),
    (b"NTFY_TOPIC=fake\n", "etc/homelab/notify.env", 0o600),
    (b"[Unit]\n", "etc/systemd/system/thing.service", 0o644),
]


def _members():
    blob = deploy_updates.build_payload(FILES)
    with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
        return {m.name: m for m in tf.getmembers()}


def test_mtime_is_stamped_not_epoch_zero():
    """Regression bug-020: TarInfo defaults mtime to 0.

    Every deployed file landed dated 1969-12-31, which silently defeats
    `ls -lt`, `find -newer`, incremental backups, and any "what changed on this
    host recently" question — the exact forensics used to find other defects.
    """
    now = time.time()
    for name, m in _members().items():
        assert m.mtime > now - 300, f"{name} has a stale/zero mtime ({m.mtime})"


def test_modes_travel_in_the_archive():
    """Modes must be carried by the tar, not chmod'd afterwards, so a secret is
    never briefly world-readable at its destination."""
    members = _members()
    for _, arcname, mode in FILES:
        assert members[arcname].mode == mode


def test_everything_is_root_owned():
    for name, m in _members().items():
        assert m.uid == 0 and m.gid == 0, f"{name} not root-owned in the archive"
        assert m.uname == "root" and m.gname == "root"


def test_no_absolute_paths_or_traversal():
    """The installer extracts with `-C /` as root; a rogue entry would escape."""
    for name in _members():
        assert not name.startswith("/"), name
        assert ".." not in name.split("/"), name


def test_modes_survive_a_real_extraction():
    blob = deploy_updates.build_payload(FILES)
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["tar", "-xzpf", "-", "-C", d], input=blob, check=True)
        for _, arcname, mode in FILES:
            actual = os.stat(os.path.join(d, arcname)).st_mode & 0o777
            assert actual == mode, f"{arcname}: extracted {oct(actual)}, expected {oct(mode)}"


def test_ntfy_topic_prefers_the_environment(monkeypatch):
    monkeypatch.setenv("NTFY_TOPIC", "  from-env  ")
    assert deploy_updates.ntfy_topic() == "from-env"


def test_ntfy_topic_absent_is_none_not_crash(monkeypatch, tmp_path):
    """A missing topic must degrade to a loud warning, not an exception —
    the deploy still has to install everything else."""
    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    monkeypatch.setattr(deploy_updates.Path, "home", staticmethod(lambda: tmp_path))
    assert deploy_updates.ntfy_topic() is None
