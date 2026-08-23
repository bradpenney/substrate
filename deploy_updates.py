#!/usr/bin/env python3
"""
Deploy the nightly-update machinery to every hypervisor.

Idempotent — safe to re-run; it overwrites the scripts/units and re-enables the
timer each time, which is what you want when the repo is the source of truth.

Installs per host:
  /usr/local/bin/hypervisor-update.sh     nightly updates + gated reboot
  /usr/local/bin/hypervisor-uncordon.sh   un-cordon nodes after a reboot
  /etc/homelab/update.env                 PEER_HOST + KUBECONFIG_PATH
  /etc/homelab/kubeconfig                 cluster access for the health gate
  systemd: hypervisor-update.{service,timer}, hypervisor-uncordon.service
  kubectl (from the upstream k8s release, needed by both scripts)

Run from server1: `python3 deploy_updates.py`
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from hosts import HOSTS, Host, ADMIN_USER

REPO = Path(__file__).resolve().parent
KUBECTL_URL = "https://dl.k8s.io/release/v1.36.1/bin/linux/amd64/kubectl"


def run(host: Host, argv: list[str], check: bool = True, input_text: str | None = None):
    import shlex
    if host.ssh_target is None:
        cmd = argv
    else:
        cmd = ["ssh", "-o", "BatchMode=yes", host.ssh_target, shlex.join(argv)]
    result = subprocess.run(cmd, capture_output=True, text=True, input=input_text)
    if check and result.returncode != 0:
        raise RuntimeError(f"[{host.name}] {argv} failed:\n{result.stderr}")
    return result


def put_file_text(host: Host, content: str, remote: str, mode: str) -> None:
    """Write text to a root-owned path on the host."""
    import shlex
    inner = f"sudo tee {shlex.quote(remote)} >/dev/null && sudo chmod {mode} {shlex.quote(remote)}"
    if host.ssh_target is None:
        cmd = ["bash", "-c", inner]
    else:
        cmd = ["ssh", "-o", "BatchMode=yes", host.ssh_target, inner]
    result = subprocess.run(cmd, capture_output=True, text=True, input=content)
    if result.returncode != 0:
        raise RuntimeError(f"[{host.name}] writing {remote} failed:\n{result.stderr}")


def put_file(host: Host, local: Path, remote: str, mode: str) -> None:
    """Copy a local repo file to a root-owned path on the host."""
    put_file_text(host, local.read_text(), remote, mode)


def peer_of(host: Host) -> Host | None:
    others = [h for h in HOSTS if h.name != host.name]
    return others[0] if others else None


def peer_ssh_target(host: Host, peer: Host) -> str:
    """SSH target string the HOST will use to reach its PEER.

    Note this can't just be peer.ssh_target: that's written from server1's
    point of view, and is None for server1 itself (meaning "local"). From
    another host, server1 is a real remote.
    """
    if peer.ssh_target is not None:
        return peer.ssh_target
    if peer.peer_target:
        return peer.peer_target
    raise RuntimeError(
        f"{peer.name} runs locally (ssh_target: null) and has no `peer_target` "
        f"in site.yml, so {host.name} has no way to reach it")


def bootstrap_ip() -> str:
    for h in HOSTS:
        for vm in h.vms:
            if vm.bootstrap:
                return vm.static_ip
    raise RuntimeError("no bootstrap VM defined in hosts.py")


def fetch_kubeconfig() -> str:
    ip = bootstrap_ip()
    result = subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{ip}", "sudo k0s kubeconfig admin",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or "server:" not in result.stdout:
        raise RuntimeError(f"could not fetch kubeconfig from {ip}: {result.stderr}")
    return result.stdout


def deploy(host: Host, kubeconfig: str) -> None:
    peer = peer_of(host)
    if peer is None:
        print(f"[{host.name}] SKIP: no peer hypervisor — the reboot safety gate needs one")
        return

    print(f"=== {host.name} (peer: {peer.name}) ===")

    run(host, ["sudo", "mkdir", "-p", "/etc/homelab"])

    # kubectl — both scripts need it for the health gate and cordon/uncordon.
    if run(host, ["which", "kubectl"], check=False).returncode != 0:
        print(f"[{host.name}] installing kubectl...")
        run(host, ["sudo", "curl", "-fsSL", "-o", "/usr/local/bin/kubectl", KUBECTL_URL])
        run(host, ["sudo", "chmod", "0755", "/usr/local/bin/kubectl"])
    else:
        print(f"[{host.name}] kubectl already present")

    put_file(host, REPO / "hypervisor-update.sh", "/usr/local/bin/hypervisor-update.sh", "0755")
    put_file(host, REPO / "hypervisor-uncordon.sh", "/usr/local/bin/hypervisor-uncordon.sh", "0755")

    # Cluster credentials for the health gate. Root-only: it's cluster-admin.
    put_file_text(host, kubeconfig, "/etc/homelab/kubeconfig", "0600")

    env = (
        f"PEER_HOST={peer_ssh_target(host, peer)}\n"
        f"KUBECONFIG_PATH=/etc/homelab/kubeconfig\n"
    )
    put_file_text(host, env, "/etc/homelab/update.env", "0644")

    for unit in ("hypervisor-update.service", "hypervisor-update.timer",
                 "hypervisor-uncordon.service"):
        put_file(host, REPO / "systemd" / unit, f"/etc/systemd/system/{unit}", "0644")

    run(host, ["sudo", "systemctl", "daemon-reload"])
    run(host, ["sudo", "systemctl", "enable", "--now", "hypervisor-update.timer"])
    run(host, ["sudo", "systemctl", "enable", "hypervisor-uncordon.service"])
    print(f"[{host.name}] deployed")


def main() -> None:
    kubeconfig = fetch_kubeconfig()
    for host in HOSTS:
        deploy(host, kubeconfig)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
