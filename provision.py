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

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

import hosts
import siteconfig
from hosts import (
    FLUX as _CFG_FLUX,
    PRIMARY_NIC,
    K0S_TOKEN_EXPIRY,
    HOSTS,
    GATEWAY,
    DNS_SERVERS,
    KAIROS_ISO_URL,
    KAIROS_ISO_SHA256,
    HYPERVISOR_LABEL,
    K0S_ARGS,
    CONTROL_PLANE_VIP,
    EXTERNAL_SECRETS,
    API_HARDENING,
    VM_MEMORY_MIB,
    VM_VCPU,
    VM_DISK_GB,
    VM_STORAGE_DISK_GB,
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
        result = subprocess.run(
            argv, capture_output=True, text=True, input=input_text, check=False
        )
    else:
        remote_cmd = shlex.join(argv)
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", host.ssh_target, remote_cmd],
            capture_output=True,
            text=True,
            input=input_text,
            check=False,
        )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"[{host.name}] command failed: {argv}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def write_file(host: Host, path: str, content: str) -> None:
    """Write text to a path on the host, creating parent directories.

    Goes through run() so the local and remote cases stay identical — the
    provisioner drives one hypervisor it runs on and one it reaches by SSH, and
    every place those diverge has been a bug."""
    if host.ssh_target is None:
        with open(path, "w", encoding="utf-8") as f:
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
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"[{host.name}] write_file failed for {path}\nstderr: {result.stderr}"
        )


def vm_exists(host: Host, vm: VM) -> bool:
    """Whether libvirt already knows about this domain.

    Distinct from "is it running": a defined-but-off domain still owns its name
    and disks, so creating over it fails in a confusing way."""
    result = run(
        host, ["virsh", "-c", "qemu:///system", "dominfo", vm.name], check=False
    )
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
        t
        for t in REQUIRED_TOOLS
        if run(host, ["sh", "-c", f"command -v {t} >/dev/null"], check=False).returncode
        != 0
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
    result = run(
        host,
        ["virsh", "-c", "qemu:///system", "pool-info", host.disk_pool],
        check=False,
    )
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
        [
            "sh",
            "-c",
            f"virsh -c qemu:///system pool-dumpxml {host.disk_pool} | sed -n 's:.*<path>\\(.*\\)</path>.*:\\1:p'",
        ],
        check=False,
    ).stdout.strip()
    if not path:
        print(
            f"[{host.name}] WARNING: could not determine pool path; skipping no-CoW setup"
        )
        return
    # `sudo` is required for BOTH the check and the change: the pool dir is
    # root-owned 0711, so an unprivileged `lsattr` returns "Permission denied"
    # rather than the flags. Without sudo here the check silently never
    # matches and chattr is re-run on every single provisioning pass.
    already = run(
        host,
        ["sh", "-c", f"sudo lsattr -d {path} 2>/dev/null | cut -d' ' -f1"],
        check=False,
    ).stdout
    if "C" in already:
        print(f"[{host.name}] {path} already no-CoW")
        return
    print(f"[{host.name}] setting no-CoW (chattr +C) on {path} — btrfs pool")
    res = run(host, ["sudo", "chattr", "+C", path], check=False)
    if res.returncode != 0:
        # Not fatal — VMs will still work, just with CoW fragmentation — but
        # it must be visible rather than swallowed.
        print(
            f"[{host.name}] WARNING: chattr +C failed on {path}: {res.stderr.strip()}"
        )


def ensure_iso_pool(host: Host) -> None:
    """Make sure the ISO pool exists and is started.

    Separate from the disk pool because the two differ per host — the disk pool
    may be LVM or a directory, while ISOs are always a plain directory that
    qemu must be able to read."""
    result = run(
        host, ["virsh", "-c", "qemu:///system", "pool-info", ISO_POOL], check=False
    )
    if result.returncode == 0:
        return
    print(f"[{host.name}] defining ISO pool {ISO_POOL!r}...")
    run(
        host,
        [
            "virsh",
            "-c",
            "qemu:///system",
            "pool-define-as",
            ISO_POOL,
            "dir",
            "--target",
            ISO_POOL_PATH,
        ],
    )
    run(host, ["virsh", "-c", "qemu:///system", "pool-build", ISO_POOL])
    run(host, ["virsh", "-c", "qemu:///system", "pool-start", ISO_POOL])
    run(host, ["virsh", "-c", "qemu:///system", "pool-autostart", ISO_POOL])


def ensure_kairos_iso(host: Host) -> None:
    """Download the pinned Kairos ISO if absent, and verify its checksum.

    The tag makes it readable; the CHECKSUM is what makes a rebuild months from
    now install the same bytes."""
    dest = f"{ISO_POOL_PATH}/kairos-hadron-k0s.iso"
    result = run(host, ["sha256sum", dest], check=False)
    if result.returncode == 0 and result.stdout.split()[0] == KAIROS_ISO_SHA256:
        print(f"[{host.name}] Kairos ISO already present and verified")
        return
    print(f"[{host.name}] downloading Kairos ISO (~500MB)...")
    # Download to a TEMP name, verify, then rename into place. Two reasons:
    #
    # 1. PERMISSIONS. libvirt chowns an attached ISO to `qemu:qemu`, so the
    #    admin user cannot overwrite it in place — `curl -o` fails with
    #    "Permission denied" even though the pool directory is group-writable.
    #    Creating a new file and renaming needs only DIRECTORY write, which we
    #    have. This is what lets image refresh work without any sudo.
    #
    # 2. ATOMICITY. Writing straight to the canonical path leaves a truncated
    #    ISO there if the download dies partway — and a half-downloaded image
    #    that merely *exists* is exactly the kind of thing a later run treats as
    #    "present". Verify first, publish second.
    tmp = f"{dest}.tmp"
    run(host, ["rm", "-f", tmp], check=False)
    run(host, ["curl", "-fL", "-o", tmp, KAIROS_ISO_URL])
    result = run(host, ["sha256sum", tmp])
    actual = result.stdout.split()[0]
    if actual != KAIROS_ISO_SHA256:
        run(host, ["rm", "-f", tmp], check=False)
        raise RuntimeError(
            f"[{host.name}] Kairos ISO checksum mismatch: expected {KAIROS_ISO_SHA256}, got {actual}"
        )
    # Unlinking needs write on the DIRECTORY, not the file — so this works even
    # though the old ISO is owned by qemu.
    run(host, ["rm", "-f", dest], check=False)
    run(host, ["mv", tmp, dest])
    # Non-fatal: libvirt chowns attached ISOs to qemu, so a pre-existing file
    # may not be ours to chmod. mkisofs/curl already create it readable.
    run(host, ["chmod", "0644", dest], check=False)


def render_cloud_config(vm: VM, join_token: str | None = None) -> str:
    """Build the Kairos cloud-config for one VM.

    Every Kairos trap lives here and they all fail SILENTLY -- see the comments
    at each site. ansible/check_render.py asserts this stays byte-identical to
    the Jinja template used by the other bootstrap implementation."""
    # Deliberately flush-left (not indented to match this function's own
    # Python indentation) — a triple-quoted string reproduces exactly what's
    # between the quotes, with no dedent magic. Writing this indented to
    # "look nice" next to the surrounding code would silently break the
    # cloud-config, the exact bug hit earlier with an HCL heredoc.
    args = list(K0S_ARGS)

    # --- failure-domain label (ADR-139 follow-up) ---
    #
    # Appended HERE, immediately after the configured args and before the
    # --config/--token-file appends below, because the Jinja template emits it
    # in exactly that position and check_render.py compares the two renderers
    # byte-for-byte. Moving this line is a silent divergence.
    #
    # Not folded into site.yml's `k0s.args`: that list is fleet-wide, and this
    # value differs per node. See HYPERVISOR_LABEL in hosts.py for why the
    # cluster needs it at all and why it only takes effect at registration.
    args.append(f"--labels={HYPERVISOR_LABEL}={vm.hypervisor}")

    storage_gb = (
        vm.storage_disk_gb if vm.storage_disk_gb is not None else VM_STORAGE_DISK_GB
    )

    # --- control-plane load balancer (ADR-045) ---
    #
    # `externalAddress` does two load-bearing things: it puts the VIP into the
    # API server certificate's SANs (without which every client hitting the VIP
    # gets a TLS name mismatch), and it makes k0s hand out the VIP — not the
    # generating node's own address — in join tokens and in the konnectivity
    # agent DaemonSet.
    #
    # That second effect is the actual fix for ADR-044: the agents' single
    # `--proxy-server-host` becomes the VIP, and HAProxy then spreads their
    # connections across every konnectivity server instead of pinning all of
    # them to whichever controller happened to write the DaemonSet last.
    # --- API server hardening (ADR-066) ---
    #
    # Two controls that both live on kube-apiserver flags, and both fail
    # SILENTLY when misconfigured: a bad encryption config means Secrets keep
    # being written in plaintext, and a bad audit path means no log appears.
    # Neither surfaces as an error in `kubectl`.
    _ah = API_HARDENING
    api_extra_args = {}
    hardening_files = ""

    _enc_key = (_ah.secrets_encryption_key or "").strip()
    if _enc_key:
        api_extra_args["encryption-provider-config"] = "/etc/k0s/encryption.yaml"
        # `secretbox` (XSalsa20-Poly1305) rather than aescbc, whose CBC padding
        # makes it the weaker choice, or aesgcm, which requires rotation every
        # ~200k writes to stay safe with a static key.
        #
        # `identity` LAST is what lets the API server still read Secrets that
        # were written before encryption existed. Putting it first would silently
        # disable encryption while looking configured.
        hardening_files += f"""        - path: /etc/k0s/encryption.yaml
          permissions: 0600
          content: |
            apiVersion: apiserver.config.k8s.io/v1
            kind: EncryptionConfiguration
            resources:
              - resources:
                  - secrets
                providers:
                  - secretbox:
                      keys:
                        - name: key1
                          secret: {_enc_key}
                  - identity: {{}}
"""

    _audit_path = (_ah.audit_log_path or "").strip()
    if _audit_path:
        api_extra_args["audit-policy-file"] = "/etc/k0s/audit-policy.yaml"
        api_extra_args["audit-log-path"] = _audit_path
        api_extra_args["audit-log-maxage"] = str(_ah.audit_log_maxage or "30")
        # Levels, from the top down. Order matters: the FIRST matching rule wins,
        # so the noise-suppression rules have to come before the catch-all.
        hardening_files += """        - path: /etc/k0s/audit-policy.yaml
          permissions: 0644
          content: |
            apiVersion: audit.k8s.io/v1
            kind: Policy
            # Never log request or response BODIES for these: the body is the
            # secret. Metadata still records who touched what, and when.
            omitStages:
              - RequestReceived
            rules:
              - level: Metadata
                resources:
                  - group: ""
                    resources: ["secrets", "configmaps"]
                  - group: "authentication.k8s.io"
                    resources: ["tokenreviews"]
              # Anything that changes who can do what, in full. This is the
              # record that answers "how did they get that access".
              - level: RequestResponse
                resources:
                  - group: "rbac.authorization.k8s.io"
                    resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
                  - group: "certificates.k8s.io"
                    resources: ["certificatesigningrequests"]
              # Code execution inside the cluster.
              - level: RequestResponse
                resources:
                  - group: ""
                    resources: ["pods/exec", "pods/attach", "pods/portforward"]
              # Drop the constant read chatter from the control plane itself,
              # which would otherwise bury everything above it.
              - level: None
                users: ["system:kube-scheduler", "system:kube-controller-manager", "system:apiserver"]
                verbs: ["get", "list", "watch"]
              - level: None
                userGroups: ["system:nodes"]
                verbs: ["get", "list", "watch"]
              - level: None
                nonResourceURLs: ["/healthz*", "/readyz*", "/livez*", "/version", "/metrics"]
              # Everything that changes state.
              - level: RequestResponse
                verbs: ["create", "update", "patch", "delete", "deletecollection"]
              # Everything else: who, what, when -- but not the payload.
              - level: Metadata
"""

    extra_args_yaml = ""
    if api_extra_args:
        extra_args_yaml = "\n                extraArgs:\n" + "\n".join(
            f'                  {k}: "{v}"' for k, v in sorted(api_extra_args.items())
        )

    k0s_config_yaml = ""
    if CONTROL_PLANE_VIP:
        args.append("--config /etc/k0s/k0s.yaml")
        # UNQUOTED octal permissions — `stages` wants a YAML integer here.
        # The opposite of `write_files`, which wants it quoted. Getting this
        # backwards is a silent no-op, not an error.
        k0s_config_yaml = f"""        - path: /etc/k0s/k0s.yaml
          permissions: 0644
          content: |
            apiVersion: k0s.k0sproject.io/v1beta1
            kind: ClusterConfig
            metadata:
              name: k0s
            spec:
              api:
                externalAddress: {CONTROL_PLANE_VIP}
                sans:
                  - {CONTROL_PLANE_VIP}{extra_args_yaml}
              # --- node resource reservation (ADR-064) ---
              #
              # Every node here is controller AND worker, so kube-apiserver,
              # etcd, the scheduler and the controller-manager all run as HOST
              # PROCESSES. The kubelet does not account for them, so without a
              # reservation the scheduler believes the whole machine is
              # available for pods.
              #
              # Measured on s2-vm3 (a 3.9Gi node) before this existed:
              #   node working set   2333Mi
              #   sum of pod working sets  482Mi
              #   -> 1850Mi of host processes, against 100Mi reserved.
              #
              # The scheduler saw 3808Mi of allocatable memory on a node with
              # roughly 1958Mi genuinely free. Filling that gap means an OOM,
              # and on this topology etcd is one of the processes competing for
              # the last page — a scheduling decision becomes a quorum event.
              #
              # 2048Mi total reservation, a little above the 1850Mi measured,
              # rounded rather than fitted. These are deliberately SANE
              # DEFAULTS, not tuned figures: revisit once metrics are being
              # collected and the real high-water mark across all five nodes is
              # known, rather than the single sample above.
              #
              # evictionHard gives the kubelet room to act before the kernel
              # OOM killer does, which picks its victim by score, not by
              # importance.
              workerProfiles:
                - name: homelab
                  values:
                    systemReserved:
                      cpu: 200m
                      memory: 768Mi
                    kubeReserved:
                      cpu: 300m
                      memory: 1280Mi
                    evictionHard:
                      memory.available: 300Mi
                      nodefs.available: 10%
"""

    # --- dedicated Longhorn disk (ADR-050) ---
    #
    # Mounted at /usr/local/longhorn, NOT the upstream default
    # /var/lib/longhorn. On Kairos the rootfs is read-only ext2 and only
    # specific paths are bind-mounted from COS_PERSISTENT; /var/lib is not
    # writable, so the default path would either fail or land somewhere
    # ephemeral and lose every replica on reboot. /usr/local IS persistent and
    # writable, so it can host the mountpoint.
    #
    # /etc/systemd is persistent too, which is why a .mount unit written here
    # survives reboots on an immutable OS.
    #
    # The format is deliberately one-shot and conditional: `blkid` succeeds only
    # once a filesystem exists, so a node that is rebooted (rather than rebuilt)
    # keeps its data. A rebuilt node gets a brand-new blank disk and formats it,
    # which is correct — Longhorn will rebuild its replicas from peers.
    storage_disk_yaml = ""
    storage_prepare_yaml = ""
    if storage_gb:
        storage_prepare_yaml = """    - name: prepare the Longhorn data disk
      commands:
        - |
          set -e
          /usr/local/bin/prepare-longhorn-disk.sh
"""
    if storage_gb:
        storage_disk_yaml = """        - path: /etc/systemd/system/usr-local-longhorn.mount
          permissions: 0644
          content: |
            [Unit]
            Description=Longhorn data disk
            After=local-fs.target
            [Mount]
            What=/dev/vdb
            Where=/usr/local/longhorn
            Type=ext4
            Options=defaults,noatime
            [Install]
            WantedBy=local-fs.target
        - path: /usr/local/bin/prepare-longhorn-disk.sh
          permissions: 0755
          content: |
            #!/bin/sh
            # Format ONCE. blkid succeeds only if a filesystem already exists,
            # so a reboot preserves data and a rebuild starts clean.
            set -e
            [ -b /dev/vdb ] || exit 0
            if ! blkid /dev/vdb >/dev/null 2>&1; then
                mkfs.ext4 -F -L longhorn /dev/vdb
            fi
            mkdir -p /usr/local/longhorn
            systemctl enable --now usr-local-longhorn.mount
"""

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
    registry = flux.oci_repository.split("/")[0]
    pull_secret_yaml = ""
    sync_pull_secret = ""
    if flux.ghcr_token:
        # The ONE irreducible bootstrap credential (ADR-019): Flux needs it to
        # pull the private config artifact, before External Secrets exists.
        import base64 as _b64

        docker_cfg = json.dumps(
            {
                "auths": {
                    registry: {
                        "auth": _b64.b64encode(
                            f"{flux.ghcr_username}:{flux.ghcr_token}".encode()
                        ).decode()
                    }
                }
            }
        )
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

    # --- External Secrets bootstrap credential (ADR-055) ---
    #
    # Rendered as a k0s manifest so it lands BEFORE anything needs it, on a
    # freshly rebuilt cluster, with no human step. This is the credential whose
    # absence made two rebuilds silently produce clusters that could not issue
    # certificates or take backups.
    #
    # The namespace is created here too: a Secret cannot be applied into a
    # namespace that does not exist, and k0s applies manifests in filename
    # order within a directory, not dependency order.
    eso_yaml = ""
    _eso = EXTERNAL_SECRETS
    if _eso.client_id and _eso.client_secret:
        eso_yaml = f"""        - path: /var/lib/k0s/manifests/external-secrets-bootstrap/creds.yaml
          permissions: 0600
          content: |
            apiVersion: v1
            kind: Namespace
            metadata:
              name: external-secrets
            ---
            apiVersion: v1
            kind: Secret
            metadata:
              name: infisical-credentials
              namespace: external-secrets
            type: Opaque
            stringData:
              clientId: {_eso.client_id}
              clientSecret: {_eso.client_secret}
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
    - {hosts.SSH_PUBLIC_KEY}
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
{k0s_config_yaml}{hardening_files}{storage_disk_yaml}{eso_yaml}{token_file_yaml}        - path: /etc/ssh/sshd_config.d/99-hardening.conf
          permissions: 0644
          content: |
            # Key-only auth. Kairos's example cloud-config sets a guessable
            # password (`passwd: kairos`); this build sets no password at all,
            # and this makes password auth unusable regardless.
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PermitRootLogin prohibit-password
        - path: /var/lib/k0s/manifests/namespace-labels/k0s-autopilot.yaml
          permissions: 0644
          content: |
            ---
            # k0s creates this namespace itself, so Flux must not own it
            # (ADR-063, one object one owner) -- but until now nothing owned its
            # Pod Security labels either. They were hand-applied, and silently
            # did not survive a rebuild: three rebuilds in a row came up with
            # k0s-autopilot unenforced, found each time only afterwards by
            # posture-check. infrastructure-config/pod-security.yaml has carried
            # a comment tracking this as a follow-up; this is that fix.
            #
            # Declaring it in k0s's OWN manifest deployer puts the labels under
            # the same owner that creates the namespace, so they are reapplied
            # on every boot instead of being remembered by a human.
            #
            # privileged/baseline mirrors kube-system: autopilot updates node
            # binaries and legitimately needs host access.
            apiVersion: v1
            kind: Namespace
            metadata:
              name: k0s-autopilot
              labels:
                kubernetes.io/metadata.name: k0s-autopilot
                pod-security.kubernetes.io/enforce: privileged
                pod-security.kubernetes.io/enforce-version: latest
                pod-security.kubernetes.io/warn: baseline
                pod-security.kubernetes.io/audit: baseline
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
                version: {flux.distribution_version}
                registry: ghcr.io/fluxcd
              # EXPLICIT component set. Left unset, flux-operator installs its
              # default four, which includes helm-controller.
              #
              # helm-controller is deliberately absent. Nothing here uses Helm
              # at runtime — every component is vendored upstream YAML — so it
              # reconciled nothing (`helmreleases` = 0) while holding
              # cluster-admin through the cluster-reconciler-flux-system
              # binding. Dropping it removes a cluster-admin subject and a
              # running Deployment for no loss of function.
              #
              # notification-controller is kept: flux-operator writes FluxReport
              # through it. It is the next candidate if that stops being true —
              # Alerts, Providers and Receivers are all currently zero.
              components:
                - source-controller
                - kustomize-controller
                - notification-controller
              # flux-operator OWNS the flux-system Namespace and sets only
              # `warn`, never `enforce` -- so after ADR-063 removed our
              # duplicate declaration, the namespace was left with no Pod
              # Security enforcement at all. This patch is how the owner is
              # asked to set it, rather than fighting it for the object.
              kustomize:
                patches:
                  - target:
                      kind: Namespace
                      name: flux-system
                    patch: |
                      apiVersion: v1
                      kind: Namespace
                      metadata:
                        name: flux-system
                        labels:
                          pod-security.kubernetes.io/enforce: baseline
                          pod-security.kubernetes.io/enforce-version: latest
                  # Verify the config artifact's cosign signature before Flux
                  # will reconcile it (ADR-069). `spec.verify` belongs on the
                  # OCIRepository, which flux-operator generates from
                  # `spec.sync` -- and `sync` has no verify field, so it is
                  # patched in here.
                  #
                  # ⚠️ matchOIDCIdentity is the load-bearing part. `provider:
                  # cosign` ALONE accepts any valid Sigstore signature, including
                  # one an attacker produced with their own GitHub account.
                  # Pinning the issuer AND the subject is what ties the artifact
                  # to this repository's workflow on this branch.
                  #
                  # ⚠️ ORDERING ON A REBUILD: this makes Flux refuse an unsigned
                  # artifact. The publish workflow must be signing before a
                  # rebuild runs, or the new cluster will never reconcile
                  # anything and the cause will look like a registry problem.
                  - target:
                      kind: OCIRepository
                      name: flux-system
                    patch: |
                      apiVersion: source.toolkit.fluxcd.io/v1
                      kind: OCIRepository
                      metadata:
                        name: flux-system
                        namespace: flux-system
                      spec:
                        verify:
                          provider: cosign
                          matchOIDCIdentity:
                            - issuer: "{flux.cosign_issuer}"
                              subject: "{flux.cosign_subject}"
              sync:
                kind: OCIRepository
                url: oci://{flux.oci_repository}
                ref: {flux.oci_tag}
                path: clusters/homelab{sync_pull_secret}
  network:
{storage_prepare_yaml}    - name: fetch the pinned flux-operator manifest
      commands:
        - |
          set -e
          D=/var/lib/k0s/manifests/flux-operator
          # Guard: Kairos re-runs stages on EVERY boot, so without this each
          # reboot would re-download 97KB for no reason.
          [ -f "$D/install.yaml" ] && exit 0
          mkdir -p "$D"
          curl -fsSL -o /tmp/flux-operator.yaml {flux.operator_url}
          echo "{flux.operator_sha256}  /tmp/flux-operator.yaml" | sha256sum -c -
          mv /tmp/flux-operator.yaml "$D/install.yaml"
"""


def build_seed_iso(host: Host, vm: VM, join_token: str | None = None) -> None:
    """Render the cloud-config and build the seed ISO for one VM.

    The ISO is the ONLY channel into a Kairos node: the installed system has no
    SSH management path by design (ADR-025), so anything the node needs to know
    has to be on this disk before it first boots."""
    user_data = render_cloud_config(vm, join_token)
    write_file(host, f"/tmp/{vm.name}-user-data", user_data)
    write_file(host, f"/tmp/{vm.name}-meta-data", "")
    run(
        host,
        [
            "mkisofs",
            "-output",
            f"{ISO_POOL_PATH}/{vm.name}-cloudinit.iso",
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            "-graft-points",
            f"user-data=/tmp/{vm.name}-user-data",
            f"meta-data=/tmp/{vm.name}-meta-data",
        ],
    )
    run(
        host, ["chmod", "0644", f"{ISO_POOL_PATH}/{vm.name}-cloudinit.iso"], check=False
    )


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
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{ip}",
            "cat /proc/cmdline",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and "COS_ACTIVE" in result.stdout


def wait_for_install(
    ip: str, timeout: int = INSTALL_WAIT_TIMEOUT, interval: int = SSH_WAIT_INTERVAL
) -> bool:
    """Block until the installer finishes.

    Kairos POWERS OFF when the install completes; it does not reboot. Waiting
    for a reboot that never comes is a hang with no error, which is why this
    watches for the domain to stop rather than for the node to answer."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if booted_from_disk(ip):
            return True
        time.sleep(interval)
    return False


def domain_state(host: Host, vm: VM) -> str:
    """libvirt's state string for a domain, or empty if it does not exist.

    Empty rather than raising: callers use this to decide whether to create,
    and "not there" is the normal case on a fresh build."""
    result = run(
        host, ["virsh", "-c", "qemu:///system", "domstate", vm.name], check=False
    )
    return result.stdout.strip()


def wait_for_installer_finish(
    host: Host,
    vm: VM,
    timeout: int = INSTALL_WAIT_TIMEOUT,
    interval: int = SSH_WAIT_INTERVAL,
) -> bool:
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
    run(
        host,
        [
            "virt-xml",
            "-c",
            "qemu:///system",
            vm.name,
            "--edit",
            "--boot",
            "hd,cdrom,menu=off",
        ],
    )
    # Survive a hypervisor reboot. Without this a host restart (including the
    # nightly-update reboots) silently leaves the cluster down — libvirtd
    # comes back but the domains don't.
    run(host, ["virsh", "-c", "qemu:///system", "autostart", vm.name])
    run(host, ["virsh", "-c", "qemu:///system", "start", vm.name])
    if not wait_for_install(vm.static_ip, timeout=SSH_WAIT_TIMEOUT):
        raise RuntimeError(
            f"[{host.name}] {vm.name} did not come up from disk after boot-order change"
        )
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
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}",
            "sudo k0s etcd member-list",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or dead_vm.static_ip not in result.stdout:
        return
    print(f"[{bootstrap_host.name}] pruning stale etcd member for {dead_vm.name}...")
    subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}",
            f"sudo k0s etcd leave --peer-address {dead_vm.static_ip}",
        ],
        capture_output=True,
        text=True,
        check=False,
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
    result = run(
        host,
        ["virsh", "-c", "qemu:///system", "domblklist", vm.name, "--details"],
        check=False,
    )
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
        run(
            host,
            [
                "virsh",
                "-c",
                "qemu:///system",
                "vol-delete",
                "--pool",
                host.disk_pool,
                path,
            ],
            check=False,
        )


def reconcile_existing(host: Host, vm: VM) -> None:
    """Bring an already-existing VM back to the desired state.

    Idempotent re-runs shouldn't just skip existing VMs — they should correct
    drift. Two things matter for a cluster that must survive host reboots:
    autostart being set, and the VM actually running.
    """
    info = run(
        host, ["virsh", "-c", "qemu:///system", "dominfo", vm.name], check=False
    ).stdout
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
            print(
                f"[{host.name}] WARNING: {vm.name} started but did not become reachable"
            )
    else:
        print(f"[{host.name}] {vm.name} already running")


def create_vm(
    host: Host,
    vm: VM,
    join_token: str | None = None,
    bootstrap_pair: tuple[Host, VM] | None = None,
) -> None:
    """Create, install and boot one VM, retrying a failed install.

    Retries because the Kairos installer is not perfectly reliable — a failed
    attempt leaves a defined domain and its disks behind, so each retry cleans
    up first. Boot order is flipped to disk-first only AFTER something is
    installed, or the node would boot the installer again forever."""
    if vm_exists(host, vm):
        reconcile_existing(host, vm)
        return

    # Per-VM override, else the fleet default. 0 means no second disk at all.
    storage_gb = (
        vm.storage_disk_gb if vm.storage_disk_gb is not None else VM_STORAGE_DISK_GB
    )

    for attempt in range(1, CREATE_RETRIES + 1):
        print(
            f"[{host.name}] creating {vm.name} (attempt {attempt}/{CREATE_RETRIES})"
            + (f" with a {storage_gb}GB storage disk" if storage_gb else "")
            + "..."
        )
        build_seed_iso(host, vm, join_token)
        run(
            host,
            [
                "virt-install",
                "--connect",
                "qemu:///system",
                "--name",
                vm.name,
                "--memory",
                str(vm.memory_mib or VM_MEMORY_MIB),
                "--vcpus",
                str(vm.vcpu or VM_VCPU),
                "--cpu",
                "host-passthrough",
                "--disk",
                f"pool={host.disk_pool},size={VM_DISK_GB},bus=virtio",
                # Dedicated Longhorn disk (ADR-050), attached as vdb when sized.
                # Omitted entirely when 0, so this is inert until storage rolls
                # out — and a node built without it is not silently different,
                # because Longhorn simply finds no disk to claim.
                *(
                    ["--disk", f"pool={host.disk_pool},size={storage_gb},bus=virtio"]
                    if storage_gb
                    else []
                ),
                "--cdrom",
                f"{ISO_POOL_PATH}/kairos-hadron-k0s.iso",
                "--disk",
                f"device=cdrom,bus=sata,path={ISO_POOL_PATH}/{vm.name}-cloudinit.iso",
                "--network",
                f"bridge={NETWORK_BRIDGE},model=virtio",
                "--os-variant",
                "generic",
                "--graphics",
                "none",
                "--console",
                "pty,target_type=serial",
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
        print(
            f"[{host.name}] waiting for {vm.name} installer to finish (VM powers itself off)..."
        )
        if wait_for_installer_finish(host, vm):
            print(f"[{host.name}] {vm.name} install complete")
            set_boot_disk_first(host, vm)
            return

        print(
            f"[{host.name}] {vm.name} install did not complete within {INSTALL_WAIT_TIMEOUT}s — destroying and retrying"
        )
        destroy_and_undefine(host, vm)
        # A failed joining node may already have registered itself in etcd
        # before dying. Left behind, that ghost member permanently breaks
        # quorum — see etcd_prune()'s docstring.
        if bootstrap_pair is not None:
            etcd_prune(bootstrap_pair[0], bootstrap_pair[1], vm)

    raise RuntimeError(
        f"[{host.name}] {vm.name} failed to come up after {CREATE_RETRIES} attempts"
    )


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
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}",
            "sudo k0s kubectl get nodes -o json",
        ],
        capture_output=True,
        text=True,
        check=False,
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
        ready = any(
            c.get("type") == "Ready" and c.get("status") == "True" for c in conditions
        )
        states[name] = ready
    return states


def wait_for_nodes_ready(
    bootstrap_vm: VM,
    expected: list[str],
    timeout: int = NODE_READY_TIMEOUT,
    interval: int = SSH_WAIT_INTERVAL,
) -> None:
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
        subprocess.run(
            ["ssh-keygen", "-R", ip], capture_output=True, text=True, check=False
        )
        scan = subprocess.run(
            ["ssh-keyscan", "-t", "ed25519", ip],
            capture_output=True,
            text=True,
            check=False,
        )
        if scan.returncode == 0 and scan.stdout.strip():
            known_hosts = Path.home() / ".ssh" / "known_hosts"
            known_hosts.parent.mkdir(mode=0o700, exist_ok=True)
            with known_hosts.open("a") as fh:
                fh.write(scan.stdout)
    print(f"  known_hosts refreshed for {len(node_ips)} nodes")

    result = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{bootstrap_vm.static_ip}",
            "sudo k0s kubeconfig admin",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # Validate before overwriting: clobbering a working kubeconfig with an
    # error message would turn a transient fetch failure into a broken
    # workstation.
    if result.returncode != 0 or "client-certificate-data" not in result.stdout:
        print(
            "  WARNING: could not fetch a valid kubeconfig — leaving the existing one alone"
        )
        print(
            f"  fix manually: ssh {ADMIN_USER}@{bootstrap_vm.static_ip} 'sudo k0s kubeconfig admin' > ~/.kube/config"
        )
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
    check = subprocess.run(
        ["kubectl", "get", "nodes", "--no-headers"],
        capture_output=True,
        text=True,
        check=False,
    )
    if check.returncode == 0:
        print(
            f"  kubectl verified: {len(check.stdout.strip().splitlines())} nodes visible"
        )
    else:
        print(f"  WARNING: kubectl still failing: {check.stderr.strip()[:200]}")


def wait_for_k0s_ready(
    vm: VM, timeout: int = SSH_WAIT_TIMEOUT, interval: int = SSH_WAIT_INTERVAL
) -> bool:
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
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"{ADMIN_USER}@{vm.static_ip}",
                "sudo k0s status",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return True
        time.sleep(interval)
    return False


def find_bootstrap() -> tuple[Host, VM]:
    """The bootstrap VM and the host carrying it.

    site.yml must mark exactly one; siteconfig validates that up front, because
    discovering it here would mean failing after the ISO has downloaded."""
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
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{ADMIN_USER}@{vm.static_ip}",
            f"sudo k0s token create --role controller --expiry {K0S_TOKEN_EXPIRY}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"failed to generate join token on {vm.name}: {result.stderr}"
        )
    token = result.stdout.strip().splitlines()[-1].strip()
    if not token:
        raise RuntimeError(f"got an empty join token from {vm.name}")
    return token


def main() -> None:
    """Provision the whole fleet: bootstrap first, then every joining node.

    Strictly ordered. The joining nodes need a token minted from the bootstrap
    node, so parallelising this would only race for something that does not
    exist yet."""
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
    print(
        f"[{bootstrap_host.name}] waiting for k0s to be ready on {bootstrap_vm.name}..."
    )
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
        create_vm(
            host, vm, join_token=token, bootstrap_pair=(bootstrap_host, bootstrap_vm)
        )

    # Phase 3: don't exit until the cluster actually reflects what was built.
    # create_vm() returns when a VM is running, which is ~45-60s before its
    # node registers — so without this, a successful exit does not mean a
    # usable cluster.
    wait_for_nodes_ready(bootstrap_vm, expected_nodes)

    # Phase 4: leave the OPERATOR'S environment working too. A rebuild that
    # produces a healthy cluster you can't talk to isn't reproducible in any
    # useful sense.
    refresh_client_access(bootstrap_vm, [v.static_ip for h in HOSTS for v in h.vms])


def plan() -> None:
    """Print what a provision WOULD build, and touch nothing.

    Every destructive action in this file is downstream of the same two facts:
    which VM is the bootstrap, and what the fleet looks like. Printing those is
    a faithful preview rather than a summary of one — there is no branch below
    that could still surprise a reader who has seen this output.
    """
    # The host is unused here but find_bootstrap() is called for its VALIDATION:
    # it raises if the fleet declares zero or several bootstrap nodes, and a
    # dry run that stayed silent about that would preview a plan that cannot
    # actually be executed.
    _bootstrap_host, bootstrap_vm = find_bootstrap()
    total = sum(len(h.vms) for h in HOSTS)
    print(f"=== DRY RUN — would provision {total} VM(s) ===")
    for host in HOSTS:
        print(f"  {host.name} ({host.ssh_target or 'local'})")
        for vm in host.vms:
            role = "BOOTSTRAP" if vm.name == bootstrap_vm.name else "joiner"
            state = "EXISTS, would reconcile" if vm_exists(host, vm) else "would CREATE"
            disk = f", {vm.storage_disk_gb}G longhorn" if vm.storage_disk_gb else ""
            print(
                f"    {vm.name:<8} {role:<9} {vm.static_ip:<15} "
                f"{vm.memory_mib}MiB / {vm.vcpu} vCPU{disk}  [{state}]"
            )
    print("\nDRY RUN — nothing was created, started, joined, or written.")


if __name__ == "__main__":
    # ⚠️ WHY THIS PARSES ARGUMENTS AT ALL.
    # It did not until 2026-09-10: every argument, INCLUDING `--help`, was
    # silently ignored while the fleet was provisioned. This script creates
    # VMs, mints join tokens and rewrites the operator's kubeconfig, so
    # `--help` being indistinguishable from running it was the worst instance
    # of that defect in this repository.
    #
    # argparse also REJECTS unknown arguments, which is the half that matters
    # most: a mistyped flag now fails instead of building a cluster.
    #
    # description= is EXPLICIT rather than `__doc__`, because the
    # `"exec" "$(...)"` shebang line above is a run of adjacent string literals
    # that Python concatenates into the module docstring.
    _parser = argparse.ArgumentParser(
        description="Idempotent k0s VM fleet provisioner."
    )
    _parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the fleet plan and create nothing",
    )
    _args = _parser.parse_args()
    siteconfig.refuse_if_root("./provision.py")
    try:
        if _args.dry_run:
            plan()
            sys.exit(0)
        main()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
