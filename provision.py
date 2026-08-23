#!/bin/sh
"exec" "$(cd $(dirname $0); pwd)/.venv/bin/python3" "-u" "$0" "$@"
"""
Idempotent k0s VM fleet provisioner.

Shells out to real `virt-install` rather than declaring libvirt domain XML
directly. That's deliberate: virt-install consults libosinfo for a long list
of OS-profile-aware defaults (ACPI/APIC, power-management settings, clock
timer policy, disk cache/IO mode, USB controller model), and an earlier
OpenTofu-based attempt at this build failed precisely because its
from-scratch XML silently omitted several of them.

Two lifecycle ordering rules are load-bearing here, both learned the hard
way (each is explained inline where it matters):

  1. Do NOT set "boot from disk first" until the OS is actually installed.
     On a blank disk, SeaBIOS halts outright instead of falling through to
     the install CD.
  2. SSH reachability does NOT mean the install finished — Kairos's live
     installer environment brings up sshd well before the disk is written.
     Check /proc/cmdline for COS_ACTIVE instead.

Run from server1, which acts as controller for the whole fleet:
`python3 provision.py`
"""

import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

from hosts import (
    FLUX as _CFG_FLUX,
    PRIMARY_NIC,
    K0S_TOKEN_EXPIRY,
    HOSTS,
    GATEWAY,
    DNS_SERVERS,
    SSH_PUBLIC_KEY,
    KAIROS_ISO_URL,
    KAIROS_ISO_SHA256,
    K0S_ARGS,
    VM_MEMORY_MIB,
    VM_VCPU,
    VM_DISK_GB,
    NETWORK_BRIDGE,
    ISO_POOL,
    ISO_POOL_PATH,
    ADMIN_USER,
    Host,
    VM,
)

CREATE_RETRIES = 3
SSH_WAIT_TIMEOUT = 300
INSTALL_WAIT_TIMEOUT = 900  # install + self-reboot takes materially longer
SSH_WAIT_INTERVAL = 10
# A node registers with the API server ~45-60s after its VM boots the installed
# system. This is the budget for the LAST node to appear and go Ready, generous
# enough to absorb a slow etcd join without hanging an unattended run forever.
NODE_READY_TIMEOUT = 600


def run(host: Host, argv: list[str], check: bool = True, input_text: str | None = None):
    """Execute argv on `host` — locally if host.ssh_target is None, else
    over SSH. Building commands as argv lists (not shell strings) and using
    shlex.join() only at the SSH boundary avoids the exact class of
    quoting/heredoc bugs hit repeatedly earlier in this build with both HCL
    and Ansible YAML."""
    if host.ssh_target is None:
        result = subprocess.run(argv, capture_output=True, text=True, input=input_text)
    else:
        remote_cmd = shlex.join(argv)
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", host.ssh_target, remote_cmd],
            capture_output=True,
            text=True,
            input=input_text,
        )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"[{host.name}] command failed: {argv}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def write_file(host: Host, path: str, content: str) -> None:
    if host.ssh_target is None:
        with open(path, "w") as f:
            f.write(content)
        return
    # Deliberately NOT going through run()'s shlex.join() here: that
    # function exists specifically to make argv survive a shell round-trip
    # as LITERAL characters, so it would escape ">" into a plain character
    # instead of a redirect operator — the opposite of what's needed. Build
    # the raw command string directly instead, quoting only the path.
    remote_cmd = f"cat > {shlex.quote(path)}"
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", host.ssh_target, remote_cmd],
        capture_output=True,
        text=True,
        input=content,
    )
    if result.returncode != 0:
        raise RuntimeError(f"[{host.name}] write_file failed for {path}\nstderr: {result.stderr}")


def vm_exists(host: Host, vm: VM) -> bool:
    result = run(host, ["virsh", "-c", "qemu:///system", "dominfo", vm.name], check=False)
    return result.returncode == 0


REQUIRED_TOOLS = ["virsh", "virt-install", "virt-xml", "mkisofs", "curl", "sha256sum"]


def preflight(host: Host) -> None:
    """Fail fast, with a useful message, if a host is missing tooling.

    Learned the hard way: server1 had `virsh` and `qemu-kvm` (from desktop /
    Docker use) but never `virt-install`, because it had never been a
    hypervisor. Without this check that surfaces ~2 minutes into a run as a
    bare `FileNotFoundError: 'virt-install'` traceback, after the ISO has
    already been downloaded. Another case of hosts differing in ways uniform
    infrastructure never exposes.
    """
    missing = [
        t for t in REQUIRED_TOOLS
        if run(host, ["sh", "-c", f"command -v {t} >/dev/null"], check=False).returncode != 0
    ]
    if missing:
        raise RuntimeError(
            f"[{host.name}] missing required tools: {', '.join(missing)}\n"
            f"  install with: sudo dnf install -y virt-install libvirt-client genisoimage"
        )


def ensure_disk_pool(host: Host) -> None:
    """Make sure the VM-disk pool exists and is fit for VM images.

    Pools differ per host by necessity: server2 has an LVM pool ('vmpool',
    raw LVs) carved from spare VG space; server1 has no LVM at all (single
    btrfs NVMe) so it uses the stock dir pool.
    """
    result = run(host, ["virsh", "-c", "qemu:///system", "pool-info", host.disk_pool], check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"[{host.name}] disk pool {host.disk_pool!r} does not exist — create it before provisioning"
        )

    if not host.pool_needs_nocow:
        return

    # btrfs is copy-on-write; VM images on CoW fragment badly and slow to a
    # crawl. `chattr +C` only affects files created AFTER it's set, so this has
    # to happen before the first disk is provisioned — hence doing it here
    # rather than as a manual afterthought.
    path = run(
        host,
        ["sh", "-c", f"virsh -c qemu:///system pool-dumpxml {host.disk_pool} | sed -n 's:.*<path>\\(.*\\)</path>.*:\\1:p'"],
        check=False,
    ).stdout.strip()
    if not path:
        print(f"[{host.name}] WARNING: could not determine pool path; skipping no-CoW setup")
        return
    # `sudo` is required for BOTH the check and the change: the pool dir is
    # root-owned 0711, so an unprivileged `lsattr` returns "Permission denied"
    # rather than the flags. Without sudo here the check silently never
    # matches and chattr is re-run on every single provisioning pass.
    already = run(
        host, ["sh", "-c", f"sudo lsattr -d {path} 2>/dev/null | cut -d' ' -f1"], check=False
    ).stdout
    if "C" in already:
        print(f"[{host.name}] {path} already no-CoW")
        return
    print(f"[{host.name}] setting no-CoW (chattr +C) on {path} — btrfs pool")
    res = run(host, ["sudo", "chattr", "+C", path], check=False)
    if res.returncode != 0:
        # Not fatal — VMs will still work, just with CoW fragmentation — but
        # it must be visible rather than swallowed.
        print(f"[{host.name}] WARNING: chattr +C failed on {path}: {res.stderr.strip()}")


def ensure_iso_pool(host: Host) -> None:
    result = run(host, ["virsh", "-c", "qemu:///system", "pool-info", ISO_POOL], check=False)
    if result.returncode == 0:
        return
    print(f"[{host.name}] defining ISO pool {ISO_POOL!r}...")
    run(host, ["virsh", "-c", "qemu:///system", "pool-define-as", ISO_POOL, "dir", "--target", ISO_POOL_PATH])
    run(host, ["virsh", "-c", "qemu:///system", "pool-build", ISO_POOL])
    run(host, ["virsh", "-c", "qemu:///system", "pool-start", ISO_POOL])
    run(host, ["virsh", "-c", "qemu:///system", "pool-autostart", ISO_POOL])


def ensure_kairos_iso(host: Host) -> None:
    dest = f"{ISO_POOL_PATH}/kairos-hadron-k0s.iso"
    result = run(host, ["sha256sum", dest], check=False)
    if result.returncode == 0 and result.stdout.split()[0] == KAIROS_ISO_SHA256:
        print(f"[{host.name}] Kairos ISO already present and verified")
        return
    print(f"[{host.name}] downloading Kairos ISO (~500MB)...")
    run(host, ["curl", "-fL", "-o", dest, KAIROS_ISO_URL])
    result = run(host, ["sha256sum", dest])
    actual = result.stdout.split()[0]
    if actual != KAIROS_ISO_SHA256:
        raise RuntimeError(
            f"[{host.name}] Kairos ISO checksum mismatch: expected {KAIROS_ISO_SHA256}, got {actual}"
        )
    # Non-fatal: libvirt chowns attached ISOs to qemu, so a pre-existing file
    # may not be ours to chmod. mkisofs/curl already create it readable.
    run(host, ["chmod", "0644", dest], check=False)


def render_cloud_config(vm: VM, join_token: str | None = None) -> str:
    # Deliberately flush-left (not indented to match this function's own
    # Python indentation) — a triple-quoted string reproduces exactly what's
    # between the quotes, with no dedent magic. Writing this indented to
    # "look nice" next to the surrounding code would silently break the
    # cloud-config, the exact bug hit earlier with an HCL heredoc.
    args = list(K0S_ARGS)
    token_file_yaml = ""
    if join_token is not None:
        # Every non-bootstrap node joins the existing cluster as a further
        # controller using a token generated on the bootstrap node. Baked
        # into the seed ISO at build time so the node joins on FIRST BOOT —
        # deliberately avoiding any post-provisioning SSH step, since the
        # goal is for these nodes to eventually have no SSH access at all.
        args.append("--token-file /etc/k0s/join-token")
        # The token is written via a `stages` entry, NOT cloud-init's
        # `write_files`. This is load-bearing: Kairos copies the whole
        # cloud-config to /oem/90_custom.yaml on the PERSISTENT partition
        # during install and re-runs its `stages` on every boot, which is how
        # config survives into the installed (immutable, ephemeral-rootfs)
        # system. `write_files` is plain cloud-init syntax that Kairos only
        # honours in the live installer environment — a token written that
        # way exists during install and then silently vanishes, leaving the
        # node unable to join. Verified directly by mounting the installed
        # image offline: /etc/k0s/join-token did not exist, while the
        # stages-written /etc/systemd/network/10-static.network did.
        # UNQUOTED octal — matching the network file below. In a `stages`
        # block Kairos wants a YAML integer here (it stores 0644 as decimal
        # 420 in /oem/90_custom.yaml). Quoting it makes the file silently
        # NOT get written, which on the network config manifests as a node
        # with no IP at all. Note this is the OPPOSITE of what cloud-init's
        # `write_files` requires, where an unquoted value fails the install
        # with `strconv.ParseUint: parsing "384"`. Same-looking field, two
        # different parsers, contradictory rules — hence both bugs.
        token_file_yaml = f"""        - path: /etc/k0s/join-token
          permissions: 0600
          content: |
            {join_token}
"""
    # --- GitOps bootstrap (ADR-018) --------------------------------------
    #
    # Two stacks under k0s's OWN manifest deployer (/var/lib/k0s/manifests),
    # which is how k0s installs CoreDNS, kube-router and konnectivity — this
    # uses the same door rather than bolting on a foreign mechanism.
    #
    # SEPARATE DIRECTORIES ON PURPOSE: k0s treats each subdirectory as an
    # independent stack and retries it. The FluxInstance references a CRD that
    # does not exist until the operator has been applied, so putting both in
    # one directory would make a single apply fail as a unit. Split, the
    # instance simply retries until its CRD is established.
    #
    # The 97KB operator manifest is FETCHED at first boot rather than embedded:
    # inlining it would bloat the cloud-config past the point of being
    # reviewable. Pinned by version AND verified by checksum, so it is still
    # reproducible — the checksum is what guarantees that, not the tag.
    flux = _CFG_FLUX
    registry = flux["oci_repository"].split("/")[0]
    pull_secret_yaml = ""
    sync_pull_secret = ""
    if flux.get("ghcr_token"):
        # The ONE irreducible bootstrap credential (ADR-019): Flux needs it to
        # pull the private config artifact, before External Secrets exists.
        import base64 as _b64, json as _json
        docker_cfg = _json.dumps({"auths": {registry: {"auth": _b64.b64encode(
            f"{flux['ghcr_username']}:{flux['ghcr_token']}".encode()).decode()}}})
        b64 = _b64.b64encode(docker_cfg.encode()).decode()
        # 16 spaces: pullSecret is a SIBLING of kind/url/ref/path under `sync:`.
        # At 12 it lands outside the sync block and the FluxInstance is
        # malformed — which check_render.py caught, on the private path only.
        sync_pull_secret = "\n                pullSecret: ghcr-auth"
        pull_secret_yaml = f"""            ---
            apiVersion: v1
            kind: Secret
            metadata:
              name: ghcr-auth
              namespace: flux-system
            type: kubernetes.io/dockerconfigjson
            data:
              .dockerconfigjson: {b64}
"""

    k0s_args_yaml = "\n".join(f"    - {arg}" for arg in args)
    dns_yaml = "\n".join(f"            DNS={d}" for d in DNS_SERVERS)
    return f"""#cloud-config
hostname: {vm.name}
users:
- name: {ADMIN_USER}
  groups:
    - admin
  ssh_authorized_keys:
    - {SSH_PUBLIC_KEY}
install:
  device: /dev/vda
  reboot: true
  auto: true
k0s:
  enabled: true
  args:
{k0s_args_yaml}
stages:
  initramfs:
    - files:
        - path: /etc/systemd/network/10-static.network
          permissions: 0644
          content: |
            [Match]
            Name={PRIMARY_NIC}
            [Network]
            Address={vm.static_ip}/24
            Gateway={GATEWAY}
{dns_yaml}
{token_file_yaml}        - path: /etc/ssh/sshd_config.d/99-hardening.conf
          permissions: 0644
          content: |
            # Key-only auth. Kairos's example cloud-config sets a guessable
            # password (`passwd: kairos`); this build sets no password at all,
            # and this makes password auth unusable regardless.
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PermitRootLogin prohibit-password
        - path: /var/lib/k0s/manifests/flux-instance/instance.yaml
          permissions: 0644
          content: |
            ---
            apiVersion: v1
            kind: Namespace
            metadata:
              name: flux-system
{pull_secret_yaml}            ---
            apiVersion: fluxcd.controlplane.io/v1
            kind: FluxInstance
            metadata:
              name: flux
              namespace: flux-system
            spec:
              distribution:
                version: {flux["distribution_version"]}
                registry: ghcr.io/fluxcd
              sync:
                kind: OCIRepository
                url: oci://{flux["oci_repository"]}
                ref: {flux["oci_tag"]}
                path: clusters/homelab{sync_pull_secret}
  network:
    - name: fetch the pinned flux-operator manifest
      commands:
        - |
          set -e
          D=/var/lib/k0s/manifests/flux-operator
          # Guard: Kairos re-runs stages on EVERY boot, so without this each
          # reboot would re-download 97KB for no reason.
          [ -f "$D/install.yaml" ] && exit 0
          mkdir -p "$D"
          curl -fsSL -o /tmp/flux-operator.yaml {flux["operator_url"]}
          echo "{flux["operator_sha256"]}  /tmp/flux-operator.yaml" | sha256sum -c -
          mv /tmp/flux-operator.yaml "$D/install.yaml"
"""


def build_seed_iso(host: Host, vm: VM, join_token: str | None = None) -> None:
    user_data = render_cloud_config(vm, join_token)
    write_file(host, f"/tmp/{vm.name}-user-data", user_data)
    write_file(host, f"/tmp/{vm.name}-meta-data", "")
    run(
        host,
        [
            "mkisofs",
            "-output", f"{ISO_POOL_PATH}/{vm.name}-cloudinit.iso",
            "-volid", "cidata", "-joliet", "-rock", "-graft-points",
            f"user-data=/tmp/{vm.name}-user-data",
            f"meta-data=/tmp/{vm.name}-meta-data",
        ],
    )
    run(host, ["chmod", "0644", f"{ISO_POOL_PATH}/{vm.name}-cloudinit.iso"], check=False)


def booted_from_disk(ip: str) -> bool:
    """True only if the VM is running the INSTALLED system, not live media.

    SSH reachability alone is NOT a valid "install finished" signal: Kairos's
    live installer environment brings up networking and sshd (it applies the
    cloud-config's network/user stages early), so the VM answers on port 22
    while the install is still running and the disk is still blank. Acting on
    SSH-alone caused a real bug here — the post-install boot-order change got
    applied to a VM that hadn't finished installing, leaving it pointed at an
    unbootable disk and halting SeaBIOS.

    The reliable discriminator is the kernel command line:
      live media : root=live:CDLABEL=COS_LIVE
      installed  : root=LABEL=COS_ACTIVE
    """
    result = subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{ip}", "cat /proc/cmdline",
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and "COS_ACTIVE" in result.stdout


def wait_for_install(ip: str, timeout: int = INSTALL_WAIT_TIMEOUT, interval: int = SSH_WAIT_INTERVAL) -> bool:
    """Wait for the VM to be running the installed system (not live media)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if booted_from_disk(ip):
            return True
        time.sleep(interval)
    return False


def domain_state(host: Host, vm: VM) -> str:
    result = run(host, ["virsh", "-c", "qemu:///system", "domstate", vm.name], check=False)
    return result.stdout.strip()


def wait_for_installer_finish(host: Host, vm: VM, timeout: int = INSTALL_WAIT_TIMEOUT,
                              interval: int = SSH_WAIT_INTERVAL) -> bool:
    """Wait for the Kairos installer to finish, which it signals by POWERING
    THE VM OFF — not by rebooting into the installed system.

    With CD-first boot order (which is correct during install), Kairos
    detects that rebooting would land it right back in the installer, so it
    deliberately powers off instead of looping. The domain therefore goes to
    `shut off` and stays there. Waiting on SSH/IP here would hang forever.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if domain_state(host, vm) == "shut off":
            return True
        time.sleep(interval)
    return False


def set_boot_disk_first(host: Host, vm: VM) -> None:
    """Switch to disk-first boot and start the installed system.

    Called only once the installer has finished and powered the VM off, so
    there is genuinely something bootable on the disk. The domain is already
    off at this point (that's how Kairos signals completion), so no power
    cycle is needed — virt-xml's edits apply to the powered-off definition
    and take effect on the next start.
    """
    print(f"[{host.name}] setting {vm.name} to boot from disk first (post-install)...")
    run(host, ["virt-xml", "-c", "qemu:///system", vm.name, "--edit", "--boot", "hd,cdrom,menu=off"])
    # Survive a hypervisor reboot. Without this a host restart (including the
    # nightly-update reboots) silently leaves the cluster down — libvirtd
    # comes back but the domains don't.
    run(host, ["virsh", "-c", "qemu:///system", "autostart", vm.name])
    run(host, ["virsh", "-c", "qemu:///system", "start", vm.name])
    if not wait_for_install(vm.static_ip, timeout=SSH_WAIT_TIMEOUT):
        raise RuntimeError(f"[{host.name}] {vm.name} did not come up from disk after boot-order change")
    print(f"[{host.name}] {vm.name} booted into the installed system")


def etcd_prune(bootstrap_host: Host, bootstrap_vm: VM, dead_vm: VM) -> None:
    """Remove a dead node's etcd member entry from the cluster.

    LOAD-BEARING for retries. A joining node registers itself in etcd early,
    potentially BEFORE it finishes coming up. If it's then destroyed (a failed
    attempt, a rebuild), its etcd member entry survives as a ghost. With 2
    members and one of them a ghost, etcd can never reach a majority — the
    surviving node loops elections forever, the API server wedges, and etcd
    can't even remove the ghost because *removal itself requires quorum*.
    That deadlock bricked the cluster once during this build and needed a
    full wipe to recover.

    So: always prune before recreating a node. Best-effort — if the cluster
    is already healthy and has no such member, this is a harmless no-op.
    """
    result = subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}", "sudo k0s etcd member-list",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or dead_vm.static_ip not in result.stdout:
        return
    print(f"[{bootstrap_host.name}] pruning stale etcd member for {dead_vm.name}...")
    subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}",
            f"sudo k0s etcd leave --peer-address {dead_vm.static_ip}",
        ],
        capture_output=True, text=True,
    )


def disk_volume_paths(host: Host, vm: VM) -> list[str]:
    """Source paths of the domain's real disks — CDROMs deliberately excluded.

    `virsh domblklist --details` output looks like:

         Type    Device   Target   Source
         block   disk     vda      /dev/<vg>/<node>
         file    cdrom    hda      -
         file    cdrom    sda      /var/lib/libvirt/isos/<node>-cloudinit.iso

    Only `disk` rows are the VM's own storage. The cdrom rows are shared or
    separately-managed media and must never be deleted as part of tearing down
    one VM.
    """
    result = run(host, ["virsh", "-c", "qemu:///system", "domblklist", vm.name, "--details"],
                 check=False)
    paths = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "disk" and fields[3] != "-":
            paths.append(fields[3])
    return paths


def destroy_and_undefine(host: Host, vm: VM) -> None:
    """Tear down one VM and delete its own disk — nothing else.

    Deliberately NOT `undefine --remove-all-storage`. That flag deletes every
    *pool-managed* volume attached to the domain, and read-only CDROMs are not
    exempt — verified experimentally, not assumed. Since the seed ISOs and the
    Kairos ISO all live in the `isos` POOL, the flag's blast radius includes
    the SHARED Kairos ISO whenever it's still attached.

    In practice that meant a real latent bug on the retry path: virt-install
    detaches the install media from a *successfully* installed domain (its
    `hda` cdrom ends up with no source), so a normal teardown looked safe —
    but a FAILED install still has the Kairos ISO attached, so retrying an
    install would delete the shared ISO out from under every subsequent VM.
    It self-healed via ensure_kairos_iso()'s checksum re-download, which is
    exactly why it could go unnoticed: a silent 500MB re-download per retry.

    Deleting the disk explicitly by path is also the only approach that works
    across both hosts, since server1's volumes are files in a dir pool and
    server2's are LVs.

    ⚠️ NEVER delete pool-wide. An LVM pool may be defined over the SAME volume
    group that holds the hypervisor's own root LV, in which case `vol-list`
    lists the HOST'S ROOT FILESYSTEM alongside the VM disks. Only ever delete volumes resolved from a
    specific domain's disk list, as done here.
    """
    # Read the disk list BEFORE undefining — once the domain is gone there is
    # nothing left to ask which volumes were its own.
    disks = disk_volume_paths(host, vm)
    run(host, ["virsh", "-c", "qemu:///system", "destroy", vm.name], check=False)
    run(host, ["virsh", "-c", "qemu:///system", "undefine", vm.name], check=False)
    for path in disks:
        run(host, ["virsh", "-c", "qemu:///system", "vol-delete", "--pool", host.disk_pool, path],
            check=False)


def reconcile_existing(host: Host, vm: VM) -> None:
    """Bring an already-existing VM back to the desired state.

    Idempotent re-runs shouldn't just skip existing VMs — they should correct
    drift. Two things matter for a cluster that must survive host reboots:
    autostart being set, and the VM actually running.
    """
    info = run(host, ["virsh", "-c", "qemu:///system", "dominfo", vm.name], check=False).stdout
    if "Autostart:" in info and "disable" in info.split("Autostart:")[1].split("\n")[0]:
        print(f"[{host.name}] {vm.name}: enabling autostart (was disabled)")
        run(host, ["virsh", "-c", "qemu:///system", "autostart", vm.name], check=False)

    state = domain_state(host, vm)
    if state != "running":
        print(f"[{host.name}] {vm.name}: state is {state!r} — starting it")
        run(host, ["virsh", "-c", "qemu:///system", "start", vm.name], check=False)
        if wait_for_install(vm.static_ip, timeout=SSH_WAIT_TIMEOUT):
            print(f"[{host.name}] {vm.name} is up")
        else:
            print(f"[{host.name}] WARNING: {vm.name} started but did not become reachable")
    else:
        print(f"[{host.name}] {vm.name} already running")


def create_vm(host: Host, vm: VM, join_token: str | None = None,
              bootstrap_pair: tuple[Host, VM] | None = None) -> None:
    if vm_exists(host, vm):
        reconcile_existing(host, vm)
        return

    for attempt in range(1, CREATE_RETRIES + 1):
        print(f"[{host.name}] creating {vm.name} (attempt {attempt}/{CREATE_RETRIES})...")
        build_seed_iso(host, vm, join_token)
        run(
            host,
            [
                "virt-install",
                "--connect", "qemu:///system",
                "--name", vm.name,
                "--memory", str(vm.memory_mib or VM_MEMORY_MIB),
                "--vcpus", str(vm.vcpu or VM_VCPU),
                "--cpu", "host-passthrough",
                "--disk", f"pool={host.disk_pool},size={VM_DISK_GB},bus=virtio",
                "--cdrom", f"{ISO_POOL_PATH}/kairos-hadron-k0s.iso",
                "--disk", f"device=cdrom,bus=sata,path={ISO_POOL_PATH}/{vm.name}-cloudinit.iso",
                "--network", f"bridge={NETWORK_BRIDGE},model=virtio",
                "--os-variant", "generic",
                "--graphics", "none",
                "--console", "pty,target_type=serial",
                "--noautoconsole",
            ],
        )
        # Boot order is deliberately NOT touched here. virt-install already
        # sets the correct order for a FRESH install (CD bootindex=1, disk
        # bootindex=2), and the disk at this point is a blank, never-written
        # 20GB LV. Forcing "hd first" before anything is installed makes
        # SeaBIOS try to boot an empty disk and halt outright (observed as a
        # frozen vCPU at EIP=0xb78c, HLT=1) rather than falling through to
        # the CD. That misplaced "fix" — correct in itself, but applied at
        # the wrong point in the VM lifecycle — was the real cause of what
        # looked for a long time like intermittent/tool-specific flakiness.
        # The disk-first ordering is applied AFTER install completes, below.
        print(f"[{host.name}] waiting for {vm.name} installer to finish (VM powers itself off)...")
        if wait_for_installer_finish(host, vm):
            print(f"[{host.name}] {vm.name} install complete")
            set_boot_disk_first(host, vm)
            return

        print(f"[{host.name}] {vm.name} install did not complete within {INSTALL_WAIT_TIMEOUT}s — destroying and retrying")
        destroy_and_undefine(host, vm)
        # A failed joining node may already have registered itself in etcd
        # before dying. Left behind, that ghost member permanently breaks
        # quorum — see etcd_prune()'s docstring.
        if bootstrap_pair is not None:
            etcd_prune(bootstrap_pair[0], bootstrap_pair[1], vm)

    raise RuntimeError(f"[{host.name}] {vm.name} failed to come up after {CREATE_RETRIES} attempts")


def node_ready_states(bootstrap_vm: VM) -> dict[str, bool] | None:
    """Map node name -> Ready, as the cluster currently sees it.

    Queried through `k0s kubectl` on the bootstrap node rather than a local
    kubectl, deliberately: after a full teardown there is no local kubeconfig
    (and a stale one points at a node that no longer exists), so depending on
    one would make this check fail for reasons unrelated to cluster health.

    Returns None if the API server can't be reached or its answer can't be
    parsed — a transient state during a rebuild, not an error. Callers should
    keep polling rather than treating it as failure.
    """
    result = subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}", "sudo k0s kubectl get nodes -o json",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    states = {}
    for node in payload.get("items", []):
        name = node.get("metadata", {}).get("name")
        if not name:
            continue
        conditions = node.get("status", {}).get("conditions", [])
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
        states[name] = ready
    return states


def wait_for_nodes_ready(bootstrap_vm: VM, expected: list[str],
                         timeout: int = NODE_READY_TIMEOUT,
                         interval: int = SSH_WAIT_INTERVAL) -> None:
    """Block until every expected node is registered AND Ready.

    Why this exists: create_vm() returns as soon as a VM is running its
    installed system, but k0s then takes roughly another 45-60s to register
    that node with the API server. Without this poll the script exits while
    the cluster is still converging, so an immediate `kubectl get nodes`
    shows fewer nodes than were built — which looks exactly like a failed
    build. The destroy-and-rebuild gate has to distinguish "still coming up"
    from "genuinely broken", and only a poll can do that.

    Raises RuntimeError on timeout, naming what was missing or NotReady, so
    an unattended run fails loudly instead of reporting a false success.
    """
    print(f"=== waiting for {len(expected)} nodes to be Ready ===")
    deadline = time.time() + timeout
    last_report = None
    while time.time() < deadline:
        states = node_ready_states(bootstrap_vm)
        if states is not None:
            missing = [n for n in expected if n not in states]
            not_ready = [n for n in expected if states.get(n) is False]
            if not missing and not not_ready:
                print(f"all {len(expected)} nodes Ready")
                return
            # Only print when the picture changes, so a long wait doesn't
            # bury the real output in identical status lines.
            report = (tuple(missing), tuple(not_ready))
            if report != last_report:
                pending = [f"{n} (unregistered)" for n in missing]
                pending += [f"{n} (NotReady)" for n in not_ready]
                print("  waiting on: " + ", ".join(pending))
                last_report = report
        time.sleep(interval)

    states = node_ready_states(bootstrap_vm) or {}
    missing = [n for n in expected if n not in states]
    not_ready = [n for n in expected if states.get(n) is False]
    raise RuntimeError(
        f"nodes did not all become Ready within {timeout}s — "
        f"unregistered: {missing or 'none'}, NotReady: {not_ready or 'none'}"
    )


def refresh_client_access(bootstrap_vm: VM, node_ips: list[str]) -> None:
    """Make the OPERATOR'S OWN tooling work again after a rebuild.

    A rebuild leaves two pieces of stale client-side state, and both bit
    repeatedly before this was automated:

    1. **known_hosts** — rebuilt VMs present new SSH host keys at the same IPs,
       so any later `ssh` fails with a host-key mismatch. The provisioner's own
       probes pass `StrictHostKeyChecking=no`, so they never notice; it's the
       human who hits it afterwards.

    2. **kubeconfig** — the new cluster has a new CA at the same IP, so an
       existing ~/.kube/config fails with:
           x509: certificate signed by unknown authority ... "kubernetes-ca"

    Neither is cluster state, which is exactly why they kept getting forgotten:
    the cluster is genuinely fine and only the workstation is wrong. But
    "reproducible" has to mean the environment works after a rebuild, not just
    that the pods are Running — so this runs as the last step of every build.
    """
    print("=== refreshing client access (known_hosts + kubeconfig) ===")

    for ip in node_ips:
        subprocess.run(["ssh-keygen", "-R", ip], capture_output=True, text=True)
        scan = subprocess.run(["ssh-keyscan", "-t", "ed25519", ip],
                              capture_output=True, text=True)
        if scan.returncode == 0 and scan.stdout.strip():
            known_hosts = Path.home() / ".ssh" / "known_hosts"
            known_hosts.parent.mkdir(mode=0o700, exist_ok=True)
            with known_hosts.open("a") as fh:
                fh.write(scan.stdout)
    print(f"  known_hosts refreshed for {len(node_ips)} nodes")

    result = subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}", "sudo k0s kubeconfig admin",
        ],
        capture_output=True, text=True,
    )
    # Validate before overwriting: clobbering a working kubeconfig with an
    # error message would turn a transient fetch failure into a broken
    # workstation.
    if result.returncode != 0 or "client-certificate-data" not in result.stdout:
        print("  WARNING: could not fetch a valid kubeconfig — leaving the existing one alone")
        print(f"  fix manually: ssh {ADMIN_USER}@{bootstrap_vm.static_ip} 'sudo k0s kubeconfig admin' > ~/.kube/config")
        return

    kube_config = Path.home() / ".kube" / "config"
    kube_config.parent.mkdir(mode=0o700, exist_ok=True)
    if kube_config.exists():
        backup = kube_config.with_suffix(f".bak.{time.strftime('%Y%m%d-%H%M%S')}")
        backup.write_text(kube_config.read_text())
    kube_config.write_text(result.stdout)
    kube_config.chmod(0o600)
    print(f"  kubeconfig refreshed: {kube_config}")

    # Prove it actually works rather than assuming. A kubeconfig that parses
    # but can't authenticate looks identical to a good one on disk.
    check = subprocess.run(["kubectl", "get", "nodes", "--no-headers"],
                           capture_output=True, text=True)
    if check.returncode == 0:
        print(f"  kubectl verified: {len(check.stdout.strip().splitlines())} nodes visible")
    else:
        print(f"  WARNING: kubectl still failing: {check.stderr.strip()[:200]}")


def wait_for_k0s_ready(vm: VM, timeout: int = SSH_WAIT_TIMEOUT,
                       interval: int = SSH_WAIT_INTERVAL) -> bool:
    """Wait until k0s on the bootstrap node can actually serve requests.

    COS_ACTIVE in /proc/cmdline proves the INSTALLED OS is running. It says
    nothing about k0s, which takes appreciably longer to come up — so minting a
    join token immediately after the bootstrap VM boots is a race:

        Error: failed to get k0s status: ... dial unix /run/k0s/status.sock:
        connect: no such file or directory

    Both implementations had this gap; Python happened to win the race and
    Ansible's tighter sequencing lost it. "The OS is up" is not "the service is
    up" — the same class of mistake as treating SSH reachability as proof the
    install had finished.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            [
                "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                f"{ADMIN_USER}@{vm.static_ip}", "sudo k0s status",
            ],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return True
        time.sleep(interval)
    return False


def find_bootstrap() -> tuple[Host, VM]:
    matches = [(h, v) for h in HOSTS for v in h.vms if v.bootstrap]
    if len(matches) != 1:
        raise RuntimeError(
            f"exactly one VM must have bootstrap=True, found {len(matches)} — check hosts.py"
        )
    return matches[0]


def generate_join_token(host: Host, vm: VM) -> str:
    """Generate a CONTROLLER-role join token on the bootstrap node.

    Every node in this cluster is a controller (all-controllers design, for
    resiliency — any node can be lost without losing the control plane), so
    --role controller, not the more commonly documented worker role.
    """
    print(f"[{host.name}] generating controller join token on {vm.name}...")
    result = subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{vm.static_ip}",
            f"sudo k0s token create --role controller --expiry {K0S_TOKEN_EXPIRY}",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to generate join token on {vm.name}: {result.stderr}")
    token = result.stdout.strip().splitlines()[-1].strip()
    if not token:
        raise RuntimeError(f"got an empty join token from {vm.name}")
    return token


def main() -> None:
    bootstrap_host, bootstrap_vm = find_bootstrap()

    # Phase 1: the bootstrap controller must be fully up BEFORE any other
    # node is created, because their join tokens are generated from it and
    # baked into their seed ISOs. This ordering constraint applies only to
    # the initial build — once formed, every node is an equal controller and
    # the bootstrap node holds no special status.
    print(f"=== bootstrap: {bootstrap_vm.name} on {bootstrap_host.name} ===")
    preflight(bootstrap_host)
    ensure_disk_pool(bootstrap_host)
    ensure_iso_pool(bootstrap_host)
    ensure_kairos_iso(bootstrap_host)
    create_vm(bootstrap_host, bootstrap_vm)

    # The bootstrap VM booting is NOT the same as k0s being ready to mint join
    # tokens. Without this, the first joiner races the control plane's startup.
    print(f"[{bootstrap_host.name}] waiting for k0s to be ready on {bootstrap_vm.name}...")
    if not wait_for_k0s_ready(bootstrap_vm):
        raise RuntimeError(
            f"k0s did not become ready on {bootstrap_vm.name} within {SSH_WAIT_TIMEOUT}s"
        )

    # Node names are the VM names (cloud-config sets `hostname: {vm.name}`),
    # so the fleet definition is also the list of nodes the cluster must end
    # up with.
    expected_nodes = [v.name for h in HOSTS for v in h.vms]

    joining = [(h, v) for h in HOSTS for v in h.vms if not v.bootstrap]
    if not joining:
        print("no joining nodes defined — cluster is a single bootstrap node")
        wait_for_nodes_ready(bootstrap_vm, expected_nodes)
        refresh_client_access(bootstrap_vm, [v.static_ip for h in HOSTS for v in h.vms])
        return

    # Phase 2: one token per joining node, generated fresh from the running
    # bootstrap controller.
    print(f"=== joining nodes ({len(joining)}) ===")
    for host, vm in joining:
        # Existing VMs get reconciled (autostart, running state) rather than
        # skipped — and crucially we do NOT mint a join token for them, since
        # generating one is pointless work for a node that's already a member.
        if vm_exists(host, vm):
            reconcile_existing(host, vm)
            continue
        preflight(host)
        ensure_disk_pool(host)
        ensure_iso_pool(host)
        ensure_kairos_iso(host)
        token = generate_join_token(bootstrap_host, bootstrap_vm)
        create_vm(host, vm, join_token=token,
                  bootstrap_pair=(bootstrap_host, bootstrap_vm))

    # Phase 3: don't exit until the cluster actually reflects what was built.
    # create_vm() returns when a VM is running, which is ~45-60s before its
    # node registers — so without this, a successful exit does not mean a
    # usable cluster.
    wait_for_nodes_ready(bootstrap_vm, expected_nodes)

    # Phase 4: leave the OPERATOR'S environment working too. A rebuild that
    # produces a healthy cluster you can't talk to isn't reproducible in any
    # useful sense.
    refresh_client_access(bootstrap_vm, [v.static_ip for h in HOSTS for v in h.vms])


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
