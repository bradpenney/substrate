"""The cloud-config is where every Kairos trap lives, and they all fail SILENTLY.

A wrong permission means the file is simply not written and the node comes up
with no network and no error anywhere. These assertions encode the traps that
have actually bitten, each one documented in provision.py at the site of the fix.
"""

from __future__ import annotations

import yaml

import provision


def test_renders_valid_yaml(joining_vm):
    r"""Regression: an f-string collapsed `\\.` to `\.`, an invalid YAML escape.

    The renderer builds YAML with f-strings, so a backslash that survives one
    level of escaping too few produces output that only fails when something
    tries to parse it — which, for a seed ISO, is the node at first boot.
    """
    yaml.safe_load(provision.render_cloud_config(joining_vm, "TEST-TOKEN"))


def test_cosign_identity_regex_keeps_its_double_backslashes(joining_vm):
    r"""`\\.` in the source must reach the output as `\.` inside the YAML string.

    Under-escaped, the regex stops anchoring the dots and the OIDC identity
    match silently widens — a supply-chain control that still reports healthy.
    """
    out = provision.render_cloud_config(joining_vm, "TEST-TOKEN")
    identity_lines = [
        l for l in out.splitlines() if "matchOIDCIdentity" in l or "issuer:" in l
    ]
    assert identity_lines, "no OIDC identity pinning found in the rendered config"
    assert any(
        "\\." in l for l in identity_lines
    ), "issuer regex lost its escaped dots — the identity match has widened"


def test_join_token_is_written_via_stages_not_write_files(joining_vm):
    """Regression, verified by mounting an installed image offline.

    Kairos copies the cloud-config to /oem/90_custom.yaml and re-runs its
    `stages` on every boot. `write_files` is plain cloud-init syntax that Kairos
    honours ONLY in the live installer, so a token written that way exists
    during install and then vanishes, leaving a node that cannot join.
    """
    out = provision.render_cloud_config(joining_vm, "TEST-TOKEN")
    assert "write_files" not in out, "write_files does not survive Kairos install"
    doc = yaml.safe_load(out)
    assert "stages" in doc
    assert "/etc/k0s/join-token" in out


def test_bootstrap_node_gets_no_join_token(bootstrap_vm):
    """The bootstrap node forms the cluster; a token would mean joining itself."""
    out = provision.render_cloud_config(bootstrap_vm, None)
    assert "/etc/k0s/join-token" not in out
    assert "--token-file" not in out


def test_stages_permissions_are_unquoted_octal(joining_vm):
    """Regression: quoting these makes the file silently NOT get written.

    In a `stages` block Kairos wants a YAML integer (it stores 0644 as decimal
    420). This is the OPPOSITE of cloud-init `write_files`, where an unquoted
    value fails the install outright. Same-looking field, two parsers,
    contradictory rules — so assert the one this file actually uses.
    """
    out = provision.render_cloud_config(joining_vm, "TEST-TOKEN")
    perms = [
        l.strip() for l in out.splitlines() if l.strip().startswith("permissions:")
    ]
    assert perms, "no permissions entries rendered"
    for line in perms:
        value = line.split("permissions:", 1)[1].strip()
        assert not value.startswith(
            ('"', "'")
        ), f"quoted permission would be ignored: {line}"


def test_secret_files_are_not_world_readable(joining_vm):
    """The join token and the encryption key must never render as 0644."""
    out = provision.render_cloud_config(joining_vm, "TEST-TOKEN")
    doc = yaml.safe_load(out)
    secrets = {"/etc/k0s/join-token", "/etc/k0s/encryption.yaml"}
    seen = {}
    for stage_entries in doc.get("stages", {}).values():
        for entry in stage_entries:
            for f in entry.get("files", []) or []:
                if f.get("path") in secrets:
                    seen[f["path"]] = f.get("permissions")
    assert seen, "expected at least one secret file in the rendered stages"
    for path, mode in seen.items():
        assert mode == 0o600, f"{path} rendered mode {mode!r}, expected 0600"


def test_static_network_uses_name_match(joining_vm):
    """`Type=ether` matched every interface and produced pod networking that

    passed a node-level DNS check while being completely broken. Match on the
    specific NIC name instead.
    """
    out = provision.render_cloud_config(joining_vm, "TEST-TOKEN")
    assert "/etc/systemd/network/10-static.network" in out
    assert "Type=ether" not in out, "Type=ether matches every interface"
    assert "Name=" in out


def test_k0s_autopilot_pod_security_is_declared_in_the_k0s_stack(joining_vm):
    """Regression: k0s-autopilot came up with NO Pod Security enforcement after
    three consecutive rebuilds.

    Flux must not own this namespace — k0s creates it (ADR-063, one object one
    owner) — but nothing owned its LABELS either, so they were hand-applied and
    silently did not survive. Declaring them in k0s's own manifest deployer puts
    them under the same owner that creates the namespace.
    """
    import yaml as _yaml

    out = provision.render_cloud_config(joining_vm, "TEST-TOKEN")
    assert "/var/lib/k0s/manifests/namespace-labels/k0s-autopilot.yaml" in out

    doc = _yaml.safe_load(out)
    body = None
    for entries in doc.get("stages", {}).values():
        for entry in entries:
            for f in entry.get("files", []) or []:
                if f.get("path", "").endswith("namespace-labels/k0s-autopilot.yaml"):
                    body = _yaml.safe_load(f["content"])
    assert body is not None, "the namespace-labels stack was not rendered"
    labels = body["metadata"]["labels"]
    assert body["kind"] == "Namespace" and body["metadata"]["name"] == "k0s-autopilot"
    assert (
        labels["pod-security.kubernetes.io/enforce"] == "privileged"
    ), "autopilot updates node binaries and needs host access, like kube-system"
    assert labels["pod-security.kubernetes.io/warn"] == "baseline"
    assert labels["pod-security.kubernetes.io/audit"] == "baseline"
