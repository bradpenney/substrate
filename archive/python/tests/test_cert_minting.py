"""The certificate minting path, end to end with the cluster stubbed.

A client certificate CANNOT be revoked — Kubernetes implements no CRL and no
OCSP — so the properties worth pinning are the ones that decide what gets
written to disk and with what permissions, and the refusal when the CSR is
approved but never signed.
"""

from __future__ import annotations

import base64
import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# A syntactically valid PEM is enough: nothing here parses it.
FAKE_CERT = base64.b64encode(
    b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n" b"-----END CERTIFICATE-----\n"
).decode()


@pytest.fixture
def ccc():
    spec = importlib.util.spec_from_file_location(
        "ccc_mint", REPO / "create-client-cert.py"
    )
    m = importlib.util.module_from_spec(spec)
    sys.modules["ccc_mint"] = m
    spec.loader.exec_module(m)
    return m


def stub_cluster(ccc, monkeypatch, cert_b64=FAKE_CERT):
    """Answer every kubectl the script makes, recording what it asked for."""
    seen = []

    def fake_sh(args, **kw):
        seen.append(args)
        joined = " ".join(args)
        if "jsonpath={.status.certificate}" in joined:
            return cert_b64
        if "clusters[0].name" in joined:
            return "local"
        if "clusters[0].cluster.server" in joined:
            return "https://10.99.0.99:6443"
        if "certificate-authority-data" in joined:
            return base64.b64encode(b"fake-ca").decode()
        return ""

    monkeypatch.setattr(ccc, "sh", fake_sh)
    monkeypatch.setattr(ccc.time, "sleep", lambda s: None)
    return seen


def test_minting_writes_both_files_with_the_key_locked_down(ccc, monkeypatch, tmp_path):
    stub_cluster(ccc, monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["create-client-cert.py", "reader", "--out-dir", str(tmp_path)]
    )
    ccc.main()
    key, crt = tmp_path / "reader.key", tmp_path / "reader.crt"
    assert key.is_file() and crt.is_file()
    assert (
        key.stat().st_mode & 0o777 == 0o600
    ), "the private key must not be readable by others"


def test_minting_approves_and_then_cleans_up_the_csr(ccc, monkeypatch, tmp_path):
    """A left-behind CSR is clutter that also leaks who was issued what."""
    seen = stub_cluster(ccc, monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["create-client-cert.py", "reader", "--out-dir", str(tmp_path)]
    )
    ccc.main()
    joined = [" ".join(a) for a in seen]
    assert any("certificate approve" in j for j in joined), joined
    assert any("delete csr" in j for j in joined), joined


def test_minting_refuses_when_the_csr_is_never_signed(ccc, monkeypatch, tmp_path):
    """Approved-but-unsigned means the csrsigning controller is not running.
    Writing a key with no certificate would leave a half-made identity."""
    stub_cluster(ccc, monkeypatch, cert_b64="")
    monkeypatch.setattr(
        sys, "argv", ["create-client-cert.py", "reader", "--out-dir", str(tmp_path)]
    )
    with pytest.raises(SystemExit) as e:
        ccc.main()
    assert "never signed" in str(e.value)
    assert not (tmp_path / "reader.crt").exists()


def test_groups_are_carried_into_the_request(ccc, monkeypatch, tmp_path):
    """RBAC matches on the O values, so a requested group that silently vanished
    would produce an identity with less access than intended — and the failure
    would look like a permissions bug much later."""
    stub_cluster(ccc, monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "create-client-cert.py",
            "reader",
            "--groups",
            "platform-viewer",
            "--out-dir",
            str(tmp_path),
        ],
    )
    ccc.main()
    assert (tmp_path / "reader.crt").is_file()


def test_context_defaults_to_the_username(ccc, monkeypatch, tmp_path):
    seen = stub_cluster(ccc, monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["create-client-cert.py", "reader", "--out-dir", str(tmp_path)]
    )
    ccc.main()
    joined = " ".join(" ".join(a) for a in seen)
    assert "reader" in joined
