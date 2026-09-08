#!/bin/sh
"exec" "$(cd $(dirname $0); pwd)/.venv/bin/python3" "-u" "$0" "$@"
"""
Destroy-and-rebuild gate — parts 1 (wipe) and 2 (verify).

THE REQUIREMENT this exists to satisfy (Brad, verbatim):

    "Before we start adding workloads on this (migrating them from docker
    compose) I want to prove that I can fully destroy/rebuild the cluster with
    both the python script and ansible. This means it gets fully wiped, yet
    comes back with all components live and ready with either bootstrap
    method."

So the gate has to answer one question with an exit code: *does this cluster
genuinely rebuild from nothing, or does it merely happen to be working?*

WHY THIS IS A SEPARATE TOOL FROM provision.py
The provisioner's job is to build a cluster. It should not know how to destroy
one, and it must not be the thing that decides whether its own output is
healthy — if provision.py held a wrong idea of "healthy" it would happily
validate itself. Keeping verification here means the tool being proven and the
tool doing the proving are different code.

It imports provision.py only for genuinely shared primitives (`run`, the
node-readiness poll, host/VM shapes). The health criteria live here.

  ./gate.py verify                              # non-destructive health check
  ./gate.py fingerprint                         # non-destructive end-state snapshot
  ./gate.py wipe --dry-run                      # show what would be destroyed
  ./gate.py wipe --yes                          # DESTRUCTIVE
  ./gate.py rebuild --yes --method python       # ONE wipe, one rebuild, verify, save fingerprint
  ./gate.py rebuild --yes --method ansible      # same, via the playbook
  ./gate.py compare python ansible              # non-destructive; the actual proof
  ./gate.py roll --yes [--node s1-vm2]          # DESTRUCTIVE: rebuild nodes on the pinned image

HOW THE HARD GATE IS RUN — and why there is no single "do it all" command:

An earlier version had a `full-gate` subcommand that wiped, rebuilt with
Python, wiped AGAIN, rebuilt with Ansible, and compared. It worked, but it was
the wrong shape: one command destroyed the cluster twice, unattended, with no
decision point in between. If the second rebuild failed you were left with
nothing, having thrown away a cluster that had just been verified healthy.

So each pass is now its own deliberate command, and each SAVES its fingerprint.
Run them whenever suits — hours or days apart — then `compare`. The proof is
identical; the blast radius per command is halved, and you choose when each
teardown happens.

Note that the BUILD tools never destroy anything: provision.py and site.yml
only create and reconcile. Every destructive operation lives in this file.

Exit code 0 means the assertion held. Anything else means it did not.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import provision
import hosts as hosts_module
from hosts import HOSTS, ISO_POOL_PATH

# A rebuilt cluster needs a moment after nodes go Ready before every system pod
# has been rescheduled and settled. Separate from NODE_READY_TIMEOUT because
# it's a different failure mode: nodes Ready but workloads not converging.
PODS_READY_TIMEOUT = 600
PODS_POLL_INTERVAL = 10
DNS_TIMEOUT = 120

# Namespaces whose pods must all be healthy for the cluster to count as "live
# and ready". k0s puts everything it manages in these.
SYSTEM_NAMESPACES = ["kube-system"]

# No single hypervisor may hold more than this share of the schedulable pods
# (ADR-097). With a 2/3 node split an even spread already puts 60% on server2,
# so the bar is deliberately loose — it exists to catch CONCENTRATION, not to
# enforce balance. The runs it is meant to fail measured 95% and 93%.
MAX_HYPERVISOR_POD_SHARE = 0.80

# A host marked `failure_prone` in site.yml gets a stricter bar: it may not
# hold the MAJORITY of the platform. Same reasoning that keeps the etcd
# majority and the VRRP VIP off it (ADR-046), applied to workloads. It exists
# because the looser cap above does not catch the OPPOSITE failure: remediating
# a pile on the small host by restarting everything moved 74% of the platform
# onto the host that does not power itself back on after an outage — and the
# symmetric 80% cap passed that. Spread is the goal; relocation is not.
MAX_FAILURE_PRONE_POD_SHARE = 0.50

# Workloads whose replicas MUST land in different failure domains, checked by
# name rather than in aggregate.
#
# WHY AGGREGATE SHARE IS NOT ENOUGH. On 2026-09-07 the placement check passed
# all evening — 24%/76%, inside the 80% limit — while BOTH BIND primaries sat
# on s2-vm1 and the LAN had a single-domain resolver. Neither number was wrong.
# They measure different properties: "the platform is not piled on one host" is
# not "these two replicas are in different failure domains", and a fleet can
# satisfy the first while completely failing the second. The gate reported the
# health of a property nobody was worried about.
#
# Deliberately a NAMED LIST and not a heuristic. There is no general rule for
# which workloads are critical — it is a judgement about what the site cannot
# lose, so it is written down, per workload, and reviewed when one is added.
#
# `min_replicas` is load-bearing: without it a selector typo, or a workload
# that is scaled to zero, finds no pods and the "are they spread?" question is
# vacuously satisfied. A check that passes because it found nothing is the
# failure mode this whole file exists to close.
# The node label naming a node's hypervisor, rendered into every node's
# cloud-config by the substrate build (ADR-144). Restated here rather than
# imported from `hosts` because this is the value the gate ASSERTS against; a
# gate that read the same constant the renderer writes would agree with itself
# and could never report that the two had diverged.
HYPERVISOR_LABEL = "invariant-platform.io/hypervisor"

CRITICAL_PAIRS = [
    {
        "name": "BIND primaries (LAN DNS)",
        "namespace": "bindy-system",
        # Matches both `homelab-primary-0` and `homelab-primary-1`, which are
        # separate single-replica Deployments and so cannot be spread by any
        # constraint that reasons about one workload's own replicas.
        "selector": {
            "bindy.firestoned.io/role": "primary",
            "app.kubernetes.io/part-of": "bindy",
        },
        "min_replicas": 2,
        "why": "a single-domain resolver takes the LAN offline with one host",
    },
]


# ---------------------------------------------------------------- utilities


def all_vms() -> list[tuple[provision.Host, provision.VM]]:
    """Every (host, vm) pair in the fleet, flattened.

    Most gate operations act on VMs but need the host to reach them — libvirt
    lives on the hypervisor, not the node. Returning pairs keeps that
    association explicit rather than looking the host up again at each call
    site and getting it wrong once."""
    return [(h, v) for h in HOSTS for v in h.vms]


def bootstrap_vm() -> provision.VM:
    """The VM that forms the cluster.

    It comes up first and alone; every other node joins using a token minted
    from it. This matters only during the INITIAL build — once the cluster is
    formed all five are equal controllers, and losing the bootstrap node is no
    different from losing any other."""
    return provision.find_bootstrap()[1]


def kubectl(args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run kubectl against the cluster via the bootstrap node's `k0s kubectl`.

    Deliberately not a local kubectl: after a wipe there is no local
    kubeconfig, and a stale one points at a node that no longer exists — so
    depending on one would make the gate fail for reasons unrelated to whether
    the cluster rebuilt correctly.
    """
    return subprocess.run(
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
            f"{provision.ADMIN_USER}@{bootstrap_vm().static_ip}",
            f"sudo k0s kubectl {args}",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


# ------------------------------------------------------------- part 1: wipe


def orphaned_vms() -> list:
    """VMs present on a hypervisor that site.yml no longer declares.

    `wipe` iterates site.yml, so a node REMOVED from site.yml is never
    destroyed — it just keeps running. That is genuinely dangerous rather than
    untidy: the orphan still holds the old cluster's PKI and an etcd
    membership, still answers on the LAN, and will happily try to participate
    in a cluster that has been rebuilt underneath it.

    Found during the ADR-046 retopology, where s1-vm3 stopped being declared
    and would otherwise have survived a full wipe-and-rebuild.

    Returns [(host, domain_name)].
    """
    declared = {v.name for _, v in all_vms()}
    found = []
    for host in provision.HOSTS:
        res = provision.run(
            host,
            ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
            check=False,
        )
        for line in (getattr(res, "stdout", "") or "").splitlines():
            name = line.strip()
            # Only ever consider names this tooling could have created; never
            # offer to destroy something unrelated running on a hypervisor.
            if name and name not in declared and re.match(r"^s\d+-vm\d+$", name):
                found.append((host, name))
    return found


def wipe(dry_run: bool = False) -> None:
    """Destroy the entire fleet, leaving nothing that a rebuild could inherit.

    "Fully wiped" means more than deleting VMs. Three kinds of leftover state
    have each caused real problems in this build:

      - **Seed ISOs.** Each carries a baked-in join token. A stale one lets a
        node rejoin a cluster that no longer exists.
      - **known_hosts entries.** Rebuilt VMs get new SSH host keys at the same
        IPs, so stale entries make later SSH fail with a host-key mismatch.
        Local drifted state is still drifted state.

    NOT wiped, deliberately, and both cases are worth understanding:

      - **The pinned Kairos ISO.** An immutable artifact verified by checksum
        on every run, not cluster state. Re-downloading ~500MB per rebuild
        would slow the gate while proving nothing.

      - **etcd membership — no explicit prune here.** This looks like an
        omission given that a ghost etcd member bricked this cluster once, so
        to be explicit: etcd's data lives in each node's own disk, and
        `undefine --remove-all-storage` destroys those disks. A *full* wipe
        therefore clears etcd membership by construction; there is nothing
        left to be a ghost of. Pruning matters only for *partial* teardowns —
        destroying one VM while the cluster survives — which is exactly the
        case provision.py already handles via etcd_prune() on retry.

        Actively pruning here would also be harmful: `k0s etcd leave` against
        a live cluster has no timeout in etcd_prune(), so a wedged control
        plane would hang an unattended gate run indefinitely — and pruning
        members out from under still-running nodes invites them to crash or
        re-add themselves mid-wipe. Destroying storage is both simpler and
        strictly more thorough.
    """
    label = "DRY RUN — would destroy" if dry_run else "DESTROYING"
    print(f"=== {label} {len(all_vms())} VMs ===")

    orphans = orphaned_vms()
    if orphans:
        print(f"\n  {len(orphans)} ORPHAN(S) — on a hypervisor but not in site.yml:")
        for host, name in orphans:
            print(f"    {host.name}: {name}")
        print("  These hold the old cluster's PKI and etcd membership. Leaving")
        print("  them running while rebuilding produces a node that believes it")
        print("  belongs to a cluster that no longer exists.")
        if not dry_run:
            for host, name in orphans:
                print(f"  destroying orphan {name} on {host.name}...")
                provision.run(
                    host,
                    ["virsh", "-c", "qemu:///system", "destroy", name],
                    check=False,
                )
                provision.run(
                    host,
                    ["virsh", "-c", "qemu:///system", "undefine", name, "--nvram"],
                    check=False,
                )
        print()

    for host, vm in all_vms():
        exists = provision.vm_exists(host, vm)
        state = provision.domain_state(host, vm) if exists else "absent"
        print(f"  [{host.name}] {vm.name} ({state})")
        if not exists:
            continue
        # Show the exact volumes that will be deleted. An LVM pool may be
        # defined over the same volume group that holds the hypervisor's own
        # root LV, so "which volumes exactly" is a question worth being able
        # to answer before pressing go, not after.
        for path in provision.disk_volume_paths(host, vm):
            print(f"      {'would delete' if dry_run else 'deleting'} volume {path}")
        if dry_run:
            continue
        provision.destroy_and_undefine(host, vm)

    print("=== removing seed ISOs and cloud-config scratch files ===")
    for host, vm in all_vms():
        paths = [
            f"{ISO_POOL_PATH}/{vm.name}-cloudinit.iso",
            f"/tmp/{vm.name}-user-data",
            f"/tmp/{vm.name}-meta-data",
        ]
        for path in paths:
            print(f"  [{host.name}] {'would remove' if dry_run else 'removing'} {path}")
            if not dry_run:
                provision.run(host, ["rm", "-f", path], check=False)

    print("=== clearing local known_hosts entries (rebuilt VMs get new keys) ===")
    for _, vm in all_vms():
        print(f"  {'would clear' if dry_run else 'clearing'} {vm.static_ip}")
        if not dry_run:
            subprocess.run(
                ["ssh-keygen", "-R", vm.static_ip],
                capture_output=True,
                text=True,
                check=False,
            )

    if dry_run:
        print("\nDRY RUN — nothing was changed.")
    else:
        print("\nwipe complete — no VMs, no seed ISOs, no etcd members, no host keys")


# ----------------------------------------------------------- part 2: verify


def verify() -> bool:
    """Assert the documented gate criteria. Returns True only if all pass.

    Every check runs even if an earlier one fails, so a single run reports the
    full picture rather than making the operator fix-and-rerun to discover the
    next problem.
    """
    print("=== verifying cluster health ===")
    results = {
        "nodes Ready": _check_nodes(),
        "system pods healthy": _check_system_pods(),
        "cluster DNS resolving": _check_dns(),
        # Added after a passing run left Flux unverified — see _check_flux().
        "flux reconciling": _check_flux(),
        # Fifth criterion (ADR-044). The other four all passed on a cluster
        # whose admission webhooks were entirely non-functional.
        "api-server -> pod tunnel": _check_apiserver_tunnel(),
        # Sixth criterion (ADR-055). Two rebuilds shipped clusters that could
        # not issue certificates or take backups while every other check passed.
        "required secrets present": _check_required_secrets(),
        # Seventh criterion (ADR-097). Five rebuilds passed every check above
        # while the entire platform sat on one hypervisor: readiness was
        # asserted, placement never was.
        "platform spread across fleet": _check_pod_distribution(),
        # Eighth criterion. The seventh measures aggregate share and PASSED on
        # 2026-09-07 while both LAN DNS replicas sat on one node. Aggregate
        # spread and per-workload redundancy are different properties.
        "critical workloads spread": _check_critical_pairs(),
        # Ninth criterion (ADR-144). The label above is what every spread
        # constraint reasons about, and PARTIAL labelling satisfies a spread
        # vacuously rather than failing — nothing else verifies it.
        "hypervisor labels match site.yml": _check_node_labels(),
    }
    print("\n=== gate results ===")
    for name, ok in results.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    return all(results.values())


def _check_apiserver_tunnel() -> bool:
    """Every API server must be able to reach the pod network — not just one.

    THE CHECK THAT WAS MISSING. Four criteria passed on a cluster where no
    admission webhook worked, `kubectl logs` failed, `exec` failed, and
    `port-forward` failed. Nodes were Ready, system pods healthy, DNS resolving,
    Flux reconciling — because none of those traverse the API-server-to-pod
    tunnel. See ADR-044.

    Testing through the load-balanced VIP is NOT sufficient: it round-robins, so
    a single probe may land on a healthy controller and report success while the
    other four are broken. That is precisely how this hid for weeks. Each API
    server is therefore addressed DIRECTLY, one at a time.

    Reading a pod's logs is the cheapest operation that actually crosses the
    tunnel, so it is the probe.
    """
    print("--- api-server -> pod tunnel (every controller) ---")
    pod = subprocess.run(
        [
            "kubectl",
            "-n",
            "kube-system",
            "get",
            "pods",
            "-l",
            "k8s-app=kube-dns",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    ).stdout.strip()
    if not pod:
        pod = subprocess.run(
            [
                "kubectl",
                "-n",
                "kube-system",
                "get",
                "pods",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        ).stdout.strip()
    if not pod:
        print("  no kube-system pod to probe with")
        return False

    ok = True
    for _, vm in sorted(all_vms(), key=lambda x: x[1].static_ip):
        r = subprocess.run(
            [
                "kubectl",
                f"--server=https://{vm.static_ip}:6443",
                "-n",
                "kube-system",
                "logs",
                pod,
                "--tail=1",
                "--limit-bytes=256",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if r.returncode == 0:
            print(f"  [ok  ] {vm.name:<8} {vm.static_ip}")
        else:
            ok = False
            err = (r.stderr or "").strip().splitlines()
            hint = err[-1][:90] if err else "unknown error"
            print(f"  [FAIL] {vm.name:<8} {vm.static_ip}  {hint}")
            if "No agent available" in (r.stderr or ""):
                print("         konnectivity agents are not registered with this")
                print("         controller — the ADR-044 failure. Check that the")
                print("         load balancer DISTRIBUTES across all controllers.")
    return ok


# Credentials the platform cannot function without, checked through the
# ExternalSecret that produces each one rather than by reading the Secret.
#
# Keep this list SHORT and only for things whose absence breaks the platform —
# it is a gate, not an inventory.
REQUIRED_EXTERNAL_SECRETS = [
    (
        "cert-manager",
        "cloudflare-api-token",
        "cert-manager cannot solve DNS-01 — NO certificate will ever issue",
    ),
    (
        "pv-backup",
        "rclone-config",
        "the PV backup CronJobs cannot reach the remote — NO backup will run",
    ),
]


def _check_required_secrets() -> bool:
    """Assert the credentials the platform depends on are being delivered.

    WHY THIS EXISTS
    Two rebuilds on 2026-08-25 produced clusters that could not issue
    certificates and could not take backups, and EVERY other criterion passed.
    Nodes Ready, pods healthy, DNS resolving, Flux reconciling, tunnel working —
    all green, on a cluster that was quietly broken.

    Nothing surfaced it because the failure is silent by construction:
    cert-manager retries forever rather than erroring, and a backup that never
    runs produces no signal at all.

    WHY THIS READS THE EXTERNALSECRET AND NOT THE SECRET (ADR-071)
    Two reasons, and the second is the better one.

    1. The gate no longer needs permission to read Secrets, so it runs under the
       scoped `platform-viewer` identity instead of requiring cluster-admin.
       A check that demands the most dangerous credential on the cluster in
       order to run is a check that will be run as root forever.

    2. It is a STRONGER assertion. A Secret is a snapshot: once written it stays
       readable even if the pipeline that produced it has been broken for weeks —
       a revoked Infisical credential leaves the old Secret sitting there,
       looking perfectly healthy. `Ready=True` on the ExternalSecret means the
       operator authenticated and refreshed it, which is the thing actually
       required for the NEXT rebuild to work.
    """
    print("--- required credentials ---")
    ok = True
    for ns, name, why in REQUIRED_EXTERNAL_SECRETS:
        r = subprocess.run(
            ["kubectl", "-n", ns, "get", "externalsecret", name, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if r.returncode != 0:
            ok = False
            print(f"  [MISSING] {ns}/{name} — no ExternalSecret")
            print(f"            {why}")
            continue
        try:
            status = json.loads(r.stdout).get("status") or {}
        except Exception:
            status = {}
        ready = next(
            (c for c in (status.get("conditions") or []) if c.get("type") == "Ready"),
            None,
        )
        if not ready or ready.get("status") != "True":
            ok = False
            reason = (ready or {}).get("reason", "no Ready condition")
            print(f"  [STALE  ] {ns}/{name} is not syncing ({reason})")
            print(f"            {why}")
            print("            The Secret may still exist and still look fine.")
        else:
            when = status.get("refreshTime", "unknown")
            print(f"  [ok     ] {ns}/{name}  (last refreshed {when})")
    if not ok:
        print("  Delivered by External Secrets from Infisical (ADR-055).")
        print("  A failure here means the next rebuild produces a broken cluster.")
    return ok


def _check_nodes() -> bool:
    """Assert every expected node is registered and Ready.

    Checks against the fleet defined in site.yml rather than against whatever
    happens to be present, so a node that silently never joined is a failure
    rather than a smaller cluster that looks healthy."""
    expected = [v.name for _, v in all_vms()]
    try:
        provision.wait_for_nodes_ready(bootstrap_vm(), expected)
        return True
    except RuntimeError as e:
        print(f"  node check failed: {e}")
        return False


def _check_system_pods() -> bool:
    """Wait for every system pod to be Running with all containers ready.

    Checks readiness per-container rather than trusting phase alone: a pod can
    sit in Running with 0/1 containers ready indefinitely (a failing readiness
    probe), which is exactly the crash-looping state seen when CNI was broken
    by the `Type=ether` bug. "Running" on its own is not health.
    """
    print("--- system pods ---")
    deadline = time.time() + PODS_READY_TIMEOUT
    last_report = None
    while time.time() < deadline:
        unhealthy = _unhealthy_pods()
        if unhealthy is not None and not unhealthy:
            print("  all system pods Running and ready")
            return True
        if unhealthy:
            report = tuple(sorted(unhealthy))
            if report != last_report:
                for line in sorted(unhealthy):
                    print(f"  waiting on: {line}")
                last_report = report
        time.sleep(PODS_POLL_INTERVAL)

    print(f"  system pods did not settle within {PODS_READY_TIMEOUT}s")
    for line in sorted(_unhealthy_pods() or ["<could not query>"]):
        print(f"    still unhealthy: {line}")
    return False


def _unhealthy_pods() -> list[str] | None:
    """Names of system workloads that aren't fully rolled out and ready.

    Covers both pods that exist but aren't ready, AND DaemonSets that have not
    finished scheduling onto every node — the second is not implied by the
    first.

    Returns None if the API can't be reached or parsed — a transient state
    during a rebuild, not a failure. Callers keep polling.
    """
    bad = []
    for namespace in SYSTEM_NAMESPACES:
        result = kubectl(f"get pods -n {namespace} -o json")
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        for pod in payload.get("items", []):
            name = pod.get("metadata", {}).get("name", "<unnamed>")
            status = pod.get("status", {})
            phase = status.get("phase")
            # Completed one-shot pods are fine; they're not meant to stay up.
            if phase == "Succeeded":
                continue
            statuses = status.get("containerStatuses", [])
            ready = sum(1 for c in statuses if c.get("ready"))
            total = len(statuses)
            if phase != "Running" or total == 0 or ready != total:
                bad.append(f"{namespace}/{name} ({phase}, {ready}/{total} ready)")

        # A DaemonSet that has not finished SCHEDULING passes the loop above,
        # because that loop only asks whether the pods which EXIST are ready.
        # Four ready konnectivity-agents with the fifth not yet created reads as
        # "all system pods Running and ready" — and the fingerprint taken
        # immediately afterwards then records numberReady=4.
        #
        # That is exactly what happened on 2026-08-28: `gate.py compare python
        # ansible` reported
        #     konnectivity-agent: python=4 vs ansible=5
        # on two rebuilds that were both correct and both settled at 5/5. A
        # comparison that reports differences at random is worse than no
        # comparison, so the readiness gate has to wait for the full rollout.
        result = kubectl(f"get daemonsets -n {namespace} -o json")
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        for ds in payload.get("items", []):
            name = ds.get("metadata", {}).get("name", "<unnamed>")
            status = ds.get("status", {})
            desired = status.get("desiredNumberScheduled")
            ready = status.get("numberReady")
            # `desired` is 0 before the controller has observed the DaemonSet at
            # all; treat that as "not settled yet" rather than as satisfied.
            if desired is None or ready is None or desired == 0 or ready != desired:
                bad.append(
                    f"{namespace}/daemonset/{name} "
                    f"({ready if ready is not None else '?'}/"
                    f"{desired if desired is not None else '?'} scheduled-and-ready)"
                )
    return bad


def failure_prone_hypervisors() -> set[str]:
    """Hosts site.yml declares may not come back on their own.

    Read from config rather than hardcoded: which machine is the unreliable one
    is a property of this fleet, not of the gate.
    """
    return {host.name for host in HOSTS if host.failure_prone}


def node_to_hypervisor() -> dict[str, str]:
    """Map each node name to the hypervisor that hosts it, from config.

    Read from the fleet definition rather than parsed out of node names. The
    `s1-`/`s2-` prefixes happen to encode placement today, but that is a naming
    convention and not a guarantee — a renamed VM would silently be attributed
    to the wrong failure domain, which is precisely the mistake this check
    exists to catch.
    """
    return {vm.name: host.name for host, vm in all_vms()}


def schedulable_pods_by_node(payload: dict) -> dict[str, int]:
    """Count the pods the SCHEDULER placed, per node.

    DaemonSet pods are excluded because they run one per node by definition:
    counting them makes any fleet look evenly balanced and hides the very
    concentration being measured. Including them turned a real 39-vs-3 split
    into a reassuring 66-vs-21. Job pods are excluded as transient.

    Only Running pods count. A Pending pod has no node yet, and a Succeeded one
    is finished and holds nothing.
    """
    counts: dict[str, int] = {}
    for pod in payload.get("items", []):
        owners = pod.get("metadata", {}).get("ownerReferences") or []
        if any(o.get("kind") in ("DaemonSet", "Job") for o in owners):
            continue
        if pod.get("status", {}).get("phase") != "Running":
            continue
        node = pod.get("spec", {}).get("nodeName")
        if node:
            counts[node] = counts.get(node, 0) + 1
    return counts


def concentration_failures(
    counts: dict[str, int],
    node_hypervisor: dict[str, str],
    ready_nodes: list[str],
    failure_prone: set[str] | None = None,
) -> list[str]:
    """Reasons the placement is unacceptable. Empty list means it is fine.

    Two distinct failures, because they have different causes:

    1. A Ready node running NOTHING the scheduler chose to put there. That is
       the ADR-097 signature exactly — the node joined after the platform had
       already been placed onto a one-node cluster, and Kubernetes never moves
       a running pod.
    2. One hypervisor holding too much of everything. The cap is asymmetric: a
       `failure_prone` host may not hold the MAJORITY, while a dedicated one is
       allowed up to MAX_HYPERVISOR_POD_SHARE. Treating both alike would accept
       a platform piled onto the machine most likely to reboot, which is the
       state a naive remediation produces.

    A fleet can have every node occupied and still be dangerously lopsided, so
    neither check implies the other.
    """
    failure_prone = failure_prone or set()
    failures = []

    for node in sorted(ready_nodes):
        if counts.get(node, 0) == 0:
            failures.append(f"{node} is Ready but runs no scheduled pods")

    total = sum(counts.values())
    if total == 0:
        failures.append("no scheduled pods found at all")
        return failures

    by_hypervisor: dict[str, int] = {}
    for node, count in counts.items():
        # A pod on a node the fleet definition does not know about is itself a
        # finding: attributing it to a guessed hypervisor would hide that.
        host = node_hypervisor.get(node)
        if host is None:
            failures.append(f"pods scheduled on unknown node {node!r}")
            continue
        by_hypervisor[host] = by_hypervisor.get(host, 0) + count

    for host, count in sorted(by_hypervisor.items()):
        share = count / total
        prone = host in failure_prone
        limit = MAX_FAILURE_PRONE_POD_SHARE if prone else MAX_HYPERVISOR_POD_SHARE
        if share > limit:
            why = " and may not come back unattended" if prone else ""
            failures.append(
                f"{host} holds {count}/{total} scheduled pods "
                f"({share:.0%}, limit {limit:.0%}){why}"
            )
    return failures


def node_label_failures(
    payload: dict,
    node_hypervisor: dict[str, str],
    label_key: str = HYPERVISOR_LABEL,
) -> list[str]:
    """Reasons the cluster's topology labels disagree with the fleet definition.

    ADR-144 renders `invariant-platform.io/hypervisor` into every node's
    cloud-config, so a REBUILT node declares its own failure domain. Two things
    that arrangement does not give you, and this check supplies:

    1. **Kubelet applies `--node-labels` only when it CREATES the Node object.**
       A restart, a reboot, or a k0s upgrade re-registers against the existing
       object and re-applies nothing. So a node that predates the build change
       carries the label only because a human ran `kubectl label`, and the
       declaration asserts itself on that node no earlier than its next rebuild.
       Declared and applied are different states; this is what compares them.

    2. **PARTIAL labelling degrades SILENTLY, and total absence does not.** With
       no node labelled, a DoNotSchedule spread constraint leaves the pod
       Pending — loud, and caught by the critical-pair criterion. With only
       *some* nodes labelled, nodes lacking the key are excluded from spreading
       altogether: both replicas can sit in one domain while the constraint
       reports perfect satisfaction, because skew across a single domain is
       always zero. The control evaluates successfully and measures nothing.

    Fewer than two represented domains is reported even when every node agrees
    with site.yml, because a spread constraint cannot be satisfied by one
    domain — it would be satisfied *vacuously*, which is the same defect as a
    selector that matches nothing.
    """
    failures = []
    seen: dict[str, str] = {}

    for node in payload.get("items", []):
        name = node.get("metadata", {}).get("name")
        labels = node.get("metadata", {}).get("labels") or {}
        expected = node_hypervisor.get(name)
        actual = labels.get(label_key)

        if expected is None:
            failures.append(f"node {name!r} is in the cluster but not in site.yml")
            continue
        if actual is None:
            failures.append(
                f"{name} carries no {label_key} label — site.yml says "
                f"{expected!r}. Nothing schedulable can place it in a failure "
                f"domain, and a spread constraint will skip it silently"
            )
            continue
        if actual != expected:
            failures.append(
                f"{name} is labelled {label_key}={actual!r} but site.yml says "
                f"{expected!r} — the cluster and the fleet definition disagree"
            )
            continue
        seen[name] = actual

    if seen and len(set(seen.values())) < 2:
        only = sorted(set(seen.values()))
        failures.append(
            f"every correctly labelled node is in one failure domain ({only[0]}) "
            f"— a spread constraint over one domain is satisfied vacuously"
        )
    return failures


def _check_node_labels() -> bool:
    """Assert the cluster's topology labels match the fleet definition.

    Ninth criterion (ADR-144). The label is what every spread constraint in the
    platform reasons about; nothing else verifies it exists.
    """
    print("--- hypervisor topology labels ---")
    result = kubectl("get nodes -o json")
    if result.returncode != 0:
        print("  could not list nodes")
        return False
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("  could not parse the node list")
        return False

    node_hypervisor = node_to_hypervisor()
    for node in sorted(payload.get("items", []), key=lambda n: n["metadata"]["name"]):
        name = node["metadata"]["name"]
        actual = (node["metadata"].get("labels") or {}).get(HYPERVISOR_LABEL, "-")
        print(f"  {name:10} {HYPERVISOR_LABEL}={actual}")

    failures = node_label_failures(payload, node_hypervisor)
    if not failures:
        print("  every node declares a failure domain matching site.yml")
        return True
    for line in failures:
        print(f"  {line}")
    print(
        "  the label is rendered into the cloud-config by the substrate build\n"
        "  (ADR-144), but kubelet applies --node-labels only when it CREATES\n"
        "  the Node object — a node that merely rebooted needs:\n"
        "    kubectl label node <node> "
        f"{HYPERVISOR_LABEL}=<hypervisor>"
    )
    return False


def pods_matching(payload: dict, namespace: str, selector: dict) -> list[dict]:
    """Running pods in `namespace` carrying every label in `selector`.

    Every label, not any — a partial match would silently widen the selector to
    a whole namespace and make any spread question trivially satisfiable.

    Only Running pods. A Pending pod has no node and therefore no failure
    domain, and counting one as placed would report a spread that does not yet
    exist.
    """
    out = []
    for pod in payload.get("items", []):
        meta = pod.get("metadata", {})
        if meta.get("namespace") != namespace:
            continue
        if pod.get("status", {}).get("phase") != "Running":
            continue
        labels = meta.get("labels") or {}
        if all(labels.get(k) == v for k, v in selector.items()):
            out.append(pod)
    return out


def critical_pair_failures(
    payload: dict,
    node_hypervisor: dict[str, str],
    specs: list[dict] | None = None,
) -> list[str]:
    """Reasons a named critical workload is not spread. Empty means it is fine.

    Three distinct findings, because they have different causes and different
    fixes:

    1. FEWER REPLICAS THAN REQUIRED. Either the workload is degraded, or the
       selector no longer matches what the operator labels its pods. Both are
       reported, because from here they look identical and both invalidate the
       spread question — this is the guard against a check that passes by
       finding nothing.
    2. A REPLICA ON AN UNKNOWN NODE. Attributing it to a guessed hypervisor
       would hide the fact that the fleet definition and the cluster disagree.
    3. EVERY REPLICA IN ONE FAILURE DOMAIN. The finding this check exists for.

    Reads the node -> hypervisor map from site.yml, NOT from the node label
    added in the substrate build. Deliberate: the gate must be able to report
    that the labels are missing or wrong, and a check that trusted them could
    not. The label is for the SCHEDULER to act on; this is the independent
    witness that it worked.
    """
    specs = CRITICAL_PAIRS if specs is None else specs
    failures = []

    for spec in specs:
        name = spec["name"]
        pods = pods_matching(payload, spec["namespace"], spec["selector"])
        wanted = spec["min_replicas"]

        if len(pods) < wanted:
            failures.append(
                f"{name}: found {len(pods)} Running replica(s), expected at "
                f"least {wanted} — degraded, or the selector no longer matches"
            )
            continue

        domains: dict[str, list[str]] = {}
        for pod in pods:
            node = pod.get("spec", {}).get("nodeName")
            host = node_hypervisor.get(node)
            if host is None:
                failures.append(f"{name}: replica on unknown node {node!r}")
                continue
            domains.setdefault(host, []).append(pod["metadata"]["name"])

        if len(domains) < 2:
            where = ", ".join(
                f"{host} ({len(names)})" for host, names in sorted(domains.items())
            )
            failures.append(
                f"{name}: all {len(pods)} replicas in ONE failure domain — "
                f"{where}. {spec['why']}"
            )
    return failures


def _check_critical_pairs() -> bool:
    """Assert named critical workloads span both hypervisors.

    Eighth criterion. The seventh (pod distribution) measures AGGREGATE share
    and passed on 2026-09-07 while both BIND primaries ran on s2-vm1: 76% is
    under the 80% limit, and "not concentrated" is not "redundant". A property
    that matters has to be stated to be checked.
    """
    print("--- critical workload spread ---")
    result = kubectl("get pods -A -o json")
    if result.returncode != 0:
        print("  could not list pods")
        return False
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("  could not parse the pod list")
        return False

    node_hypervisor = node_to_hypervisor()
    for spec in CRITICAL_PAIRS:
        pods = pods_matching(payload, spec["namespace"], spec["selector"])
        placed = sorted(
            f"{p['metadata']['name']} -> "
            f"{node_hypervisor.get(p.get('spec', {}).get('nodeName'), '?')}"
            for p in pods
        )
        print(f"  {spec['name']}:")
        for line in placed or ["    (no Running replicas found)"]:
            print(f"    {line}")

    failures = critical_pair_failures(payload, node_hypervisor)
    if not failures:
        print("  every critical workload spans both failure domains")
        return True
    for line in failures:
        print(f"  {line}")
    print(
        "  a MutatingAdmissionPolicy imposes this at Pod admission "
        "(substrate_config,\n  infrastructure-config/bindy-primary-spread.yaml). "
        "It acts at Pod CREATE\n  only, so an already-running pair stays where "
        "it is until something\n  recreates it — see ADR-139."
    )
    return False


def _check_pod_distribution() -> bool:
    """Assert the platform is spread across the fleet, not piled on one host.

    Seventh criterion (ADR-097). Five rebuild samples asserted that every pod
    was Ready and none asserted that any pod was sensibly PLACED, so all five
    passed while 41 of 43 pods sat on 4.5 GiB and 34.4 GiB stood idle. A
    cluster in that state is healthy by every other measure here and is one
    hypervisor away from having no capacity at all.
    """
    print("--- pod distribution ---")
    result = kubectl("get pods -A -o json")
    if result.returncode != 0:
        print("  could not list pods")
        return False
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("  could not parse the pod list")
        return False

    counts = schedulable_pods_by_node(payload)
    node_hypervisor = node_to_hypervisor()
    ready = healthy_nodes()

    total = sum(counts.values()) or 1
    prone = failure_prone_hypervisors()
    for node in sorted(set(counts) | set(ready)):
        host = node_hypervisor.get(node, "?")
        count = counts.get(node, 0)
        flag = " (failure-prone)" if host in prone else ""
        print(f"  {node:10} {host:8} {count:3} pods  ({count / total:.0%}){flag}")

    failures = concentration_failures(
        counts, node_hypervisor, ready, failure_prone_hypervisors()
    )
    if not failures:
        print("  platform is spread across the fleet")
        return True
    for line in failures:
        print(f"  {line}")
    print(
        "  remediate with ./rebalance.sh (needs a jit-admin grant). This recurs\n"
        "  on every rebuild until the platform stops reconciling onto a\n"
        "  one-node cluster — see ADR-097."
    )
    return False


def _check_dns() -> bool:
    """Resolve an in-cluster name from inside a pod.

    Done from a pod, not from a node, on purpose: this is the path real
    workloads use, so it exercises CoreDNS *plus* the CNI and kube-proxy
    together. A node-level DNS query would pass while pod networking was
    completely broken — which is precisely the failure the `Type=ether` bug
    produced.
    """
    print("--- cluster DNS ---")
    pod = f"gate-dns-{int(time.time())}"

    # Deliberately NOT `kubectl run -i --rm`. That attaches to the pod and
    # streams its output, and log streaming goes through the konnectivity
    # agents — which are still churning for a minute or two after a rebuild.
    # The first version of this check did exactly that and produced a FALSE
    # FAILURE on a cluster whose DNS was working perfectly:
    #     couldn't fetch pre-attach logs: ... context deadline exceeded
    # It was really testing "can I stream logs right now" as much as "does DNS
    # resolve". A gate that cries wolf is worse than no gate.
    #
    # Instead: fire and forget, then assert on the pod's TERMINAL PHASE.
    # nslookup exits non-zero when resolution fails, so phase == Succeeded IS
    # the assertion — no output parsing, nothing routed through konnectivity.
    started = kubectl(
        f"run {pod} --image=busybox:1.36 --restart=Never "
        f"-- nslookup kubernetes.default.svc.cluster.local"
    )
    if started.returncode != 0:
        print(f"  could not start the DNS test pod: {started.stderr.strip()[:200]}")
        _force_delete_pod(pod)
        return False

    deadline = time.time() + DNS_TIMEOUT
    phase = ""
    while time.time() < deadline:
        result = kubectl(f"get pod {pod} -o jsonpath={{.status.phase}}")
        phase = result.stdout.strip()
        if phase in ("Succeeded", "Failed"):
            break
        time.sleep(3)

    resolved = phase == "Succeeded"
    if resolved:
        print("  kubernetes.default.svc.cluster.local resolved")
    else:
        # Best-effort evidence only — never let an unavailable log turn into
        # the verdict, which is the mistake this whole rewrite fixes.
        logs = kubectl(f"logs {pod}")
        detail = (logs.stdout or logs.stderr).strip()[:400] or "<no logs available>"
        print(f"  DNS check pod ended in phase {phase or '<timed out>'}:\n    {detail}")

    _force_delete_pod(pod)
    return resolved


def _check_flux() -> bool:
    """Assert Flux is actually reconciling, not merely installed.

    WHY THIS EXISTS: without it the gate passed on a cluster whose platform
    could have been completely wedged. Nodes Ready, system pods healthy and DNS
    resolving say nothing about whether the config artifact was pulled and
    applied — so a rebuild that produced an empty cluster would have been
    scored identically to one that produced a working platform.

    That gap was found by verifying Flux BY HAND after a passing run: exactly
    the "checked by a human, not by the tooling" pattern the gate exists to
    eliminate.

    Skipped (not failed) when Flux isn't installed, so the gate still works on
    a substrate-only cluster — this is a platform assertion, not a
    substrate one.
    """
    print("--- flux reconciliation ---")
    result = kubectl("get kustomization -A -o json")
    if result.returncode != 0:
        print("  Flux not installed — skipping (substrate-only cluster)")
        return True

    try:
        items = json.loads(result.stdout).get("items", [])
    except json.JSONDecodeError:
        print("  could not parse Kustomization list")
        return False

    if not items:
        print(
            "  Flux is installed but has NO Kustomizations — nothing is being reconciled"
        )
        return False

    deadline = time.time() + PODS_READY_TIMEOUT
    while time.time() < deadline:
        items = json.loads(kubectl("get kustomization -A -o json").stdout).get(
            "items", []
        )
        bad = []
        for k in items:
            name = f"{k['metadata']['namespace']}/{k['metadata']['name']}"
            ready = next(
                (
                    c
                    for c in k.get("status", {}).get("conditions", [])
                    if c.get("type") == "Ready"
                ),
                None,
            )
            if not ready or ready.get("status") != "True":
                bad.append(
                    f"{name}: {(ready or {}).get('message', 'no Ready condition')[:80]}"
                )
        if not bad:
            revs = {k["status"].get("lastAppliedRevision", "?") for k in items}
            print(f"  {len(items)} Kustomizations reconciled")
            for r in sorted(revs):
                print(f"    revision {r}")
            return True
        time.sleep(PODS_POLL_INTERVAL)

    print(f"  Kustomizations did not reconcile within {PODS_READY_TIMEOUT}s:")
    for line in bad:
        print(f"    {line}")
    return False


def _force_delete_pod(pod: str) -> None:
    """`--rm` doesn't clean up when the run times out or the pod never starts,
    which would leave the next gate run tripping over its own litter."""
    kubectl(f"delete pod {pod} --ignore-not-found --force --grace-period=0")


# ---------------------------------------------------------------- rebuild


BOOTSTRAP_METHODS = {
    "python": ([sys.executable, "-u", "provision.py"], None),
    "ansible": ([".venv/bin/ansible-playbook", "site.yml"], "ansible"),
}


def rebuild(method: str = "python") -> bool:
    """Wipe, rebuild from scratch with one bootstrap method, verify.

    Runs the bootstrap tool as a SUBPROCESS rather than importing it, so what
    the gate exercises is exactly the entrypoint a human would run — not a
    slightly different in-process path. That matters more for the Ansible case,
    where "run the playbook" is the only meaningful interface.
    """
    argv, cwd = BOOTSTRAP_METHODS[method]
    started = time.time()
    wipe()
    print(f"\n=== rebuilding with {method} ===")
    # The ansible venv path is relative to the repo root, so resolve it before
    # changing directory.
    if cwd:
        argv = [str(Path(__file__).parent / argv[0])] + argv[1:]
    result = subprocess.run(argv, cwd=cwd, check=False)
    if result.returncode != 0:
        print(f"\nGATE FAILED: {method} bootstrap exited {result.returncode}")
        return False
    print()
    ok = verify()
    mins = (time.time() - started) / 60
    print(f"\n{method.upper()} REBUILD {'PASSED' if ok else 'FAILED'} — {mins:.1f} min")
    if ok:
        # Saved rather than held in memory, so the two halves of the gate can be
        # run at different times — and compared later without a single command
        # ever destroying the cluster twice.
        save_fingerprint(method)
        print(
            "\nWhen you've done the other method too:  ./gate.py compare python ansible"
        )
    return ok


def cluster_fingerprint() -> dict:
    """A comparable description of the cluster's end state.

    Parts 3-4 of the gate need more than "both runs passed" — two runs could
    each be healthy while having built materially different clusters (a node on
    the wrong hypervisor, a different k0s version, a missing etcd member). This
    captures the properties that must match, and deliberately EXCLUDES things
    that legitimately differ between rebuilds: pod names, UIDs, IPs assigned by
    the CNI, ages, and resource versions.
    """
    fingerprint = {}

    result = kubectl("get nodes -o json")
    payload = json.loads(result.stdout)
    nodes = {}
    for node in payload.get("items", []):
        meta = node.get("metadata", {})
        status = node.get("status", {})
        nodes[meta.get("name")] = {
            "ready": any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in status.get("conditions", [])
            ),
            "kubelet_version": status.get("nodeInfo", {}).get("kubeletVersion"),
            "os_image": status.get("nodeInfo", {}).get("osImage"),
            "internal_ip": next(
                (
                    a.get("address")
                    for a in status.get("addresses", [])
                    if a.get("type") == "InternalIP"
                ),
                None,
            ),
            "roles": sorted(
                k.split("/", 1)[1]
                for k in meta.get("labels", {})
                if k.startswith("node-role.kubernetes.io/")
            ),
        }
    fingerprint["nodes"] = nodes

    # Which VM sits on which hypervisor — a cluster that came back with nodes
    # on the wrong hosts would still look healthy to kubectl.
    fingerprint["placement"] = {
        vm.name: host.name for host, vm in all_vms() if provision.vm_exists(host, vm)
    }

    # Workload identity, not instance identity: DaemonSet/Deployment names and
    # their expected counts, rather than the ephemeral pod names.
    workloads = {}
    for namespace in SYSTEM_NAMESPACES:
        for kind in ("daemonsets", "deployments"):
            result = kubectl(f"get {kind} -n {namespace} -o json")
            if result.returncode != 0:
                continue
            for item in json.loads(result.stdout).get("items", []):
                name = item["metadata"]["name"]
                status = item.get("status", {})
                workloads[f"{namespace}/{kind}/{name}"] = (
                    status.get("numberReady")
                    if kind == "daemonsets"
                    else status.get("readyReplicas")
                )
    fingerprint["workloads"] = workloads

    # Platform state. Included so the python-vs-ansible comparison covers what
    # the cluster RUNS, not merely how it was built — the source URL and the
    # set of reconciled Kustomizations must match across both methods.
    #
    # Deliberately NOT the applied revision: that is the artifact digest, which
    # legitimately changes whenever the config repo is pushed. Comparing it
    # would make the two passes differ for reasons unrelated to reproducibility.
    result = kubectl("get kustomization -A -o json")
    if result.returncode == 0:
        try:
            fingerprint["flux_kustomizations"] = sorted(
                f"{k['metadata']['namespace']}/{k['metadata']['name']}"
                for k in json.loads(result.stdout).get("items", [])
            )
        except json.JSONDecodeError:
            pass
    # The image pin this cluster was built against. NOT part of the field-by-field
    # comparison — it is metadata about the run — but `compare` refuses to compare
    # fingerprints captured against different pins, because a version bump changes
    # kubelet_version legitimately and would otherwise look like a reproducibility
    # failure.
    fingerprint["_pinned_image_sha256"] = hosts_module.KAIROS_ISO_SHA256

    result = kubectl("get ocirepository -A -o json")
    if result.returncode == 0:
        try:
            fingerprint["flux_sources"] = sorted(
                f"{o['metadata']['namespace']}/{o['metadata']['name']}={o['spec']['url']}"
                for o in json.loads(result.stdout).get("items", [])
            )
        except json.JSONDecodeError:
            pass

    return fingerprint


def compare_fingerprints(a: dict, b: dict, label_a: str, label_b: str) -> bool:
    """Report every difference between two cluster end states.

    Reports ALL differences rather than stopping at the first: one fix at a
    time would hide the rest behind it. Recurses into nested dicts so a change
    buried in platform.flux.source is as visible as a top-level one.

    Returns True when the states match, which is what makes the two-method
    rebuild a comparison rather than two independent claims of success."""
    problems = []

    def walk(x, y, path=""):
        """Recurse two fingerprints in parallel, recording every difference.

        Compares the union of keys at each level, so a key present on only one side
        is reported rather than skipped — that asymmetry is the most important
        thing this comparison can catch."""
        for key in sorted(set(x) | set(y)):
            where = f"{path}.{key}" if path else key
            if key not in x:
                problems.append(
                    f"  {where}: absent after {label_a}, present after {label_b}"
                )
            elif key not in y:
                problems.append(
                    f"  {where}: present after {label_a}, absent after {label_b}"
                )
            elif isinstance(x[key], dict) and isinstance(y[key], dict):
                walk(x[key], y[key], where)
            elif x[key] != y[key]:
                problems.append(
                    f"  {where}: {label_a}={x[key]!r} vs {label_b}={y[key]!r}"
                )

    walk(a, b)
    if problems:
        print(f"\n=== END STATES DIFFER between {label_a} and {label_b} ===")
        print("\n".join(problems))
        return False
    print(f"\n=== end states IDENTICAL between {label_a} and {label_b} ===")
    return True


FINGERPRINT_DIR = Path(__file__).parent / ".fingerprints"


def save_fingerprint(method: str) -> Path:
    """Record the current end state, tagged with the method that built it.

    Written to .fingerprints/<method>.json so `compare` can put two rebuilds
    side by side long after both have finished."""
    FINGERPRINT_DIR.mkdir(exist_ok=True)
    path = FINGERPRINT_DIR / f"{method}.json"
    path.write_text(json.dumps(cluster_fingerprint(), indent=2, sort_keys=True) + "\n")
    print(f"fingerprint saved: {path}")
    return path


def compare_saved(a: str, b: str) -> bool:
    """Compare two previously saved fingerprints.

    Separate from the rebuilds on purpose — see `full_gate`'s note. This is what
    turns two independent runs, done whenever suits, into the actual proof.
    """
    pa, pb = FINGERPRINT_DIR / f"{a}.json", FINGERPRINT_DIR / f"{b}.json"
    missing = [str(p) for p in (pa, pb) if not p.exists()]
    if missing:
        print(f"missing fingerprint(s): {', '.join(missing)}", file=sys.stderr)
        print(
            "run: ./gate.py rebuild --yes --method <method>   (saves one each time)",
            file=sys.stderr,
        )
        return False
    fa, fb = json.loads(pa.read_text()), json.loads(pb.read_text())

    # Precondition: both must have been captured against the SAME pinned image.
    # A version bump legitimately changes kubelet_version and os_image, so
    # comparing across pins would report a difference that is not a fault — and
    # worse, would look like the two bootstrap methods disagreeing.
    pin_a = fa.pop("_pinned_image_sha256", None)
    pin_b = fb.pop("_pinned_image_sha256", None)
    if pin_a != pin_b:
        print(
            "REFUSING to compare: the fingerprints were captured against "
            "DIFFERENT pinned images.",
            file=sys.stderr,
        )
        print(f"  {a}: {pin_a or '<not recorded>'}", file=sys.stderr)
        print(f"  {b}: {pin_b or '<not recorded>'}", file=sys.stderr)
        print(
            "\nA version bump changes kubelet_version legitimately. Re-run both "
            "passes on the current pin, then compare.",
            file=sys.stderr,
        )
        return False

    return compare_fingerprints(fa, fb, a, b)


# ---------------------------------------------------- rolling node replacement


def expected_k0s_version() -> str | None:
    """The k0s version the PINNED image carries, parsed from its asset name.

    Kairos encodes it in the filename (`...-k0sv1.36.3+k0s.2.iso`), which makes
    the intended outcome of a roll checkable rather than assumed. URL-decoded
    first: the `+` arrives as `%2B`.
    """
    import urllib.parse

    m = re.search(
        r"k0sv([\d.]+)\+k0s", urllib.parse.unquote(hosts_module.KAIROS_ISO_URL)
    )
    return m.group(1) if m else None


def node_kubelet_version(name: str) -> str | None:
    """The kubelet version a node reports, or None if it cannot be queried.

    None is not an error here: the gate polls this while nodes are still
    joining, and "cannot answer yet" is an expected state."""
    result = kubectl(f"get node {name} -o jsonpath={{.status.nodeInfo.kubeletVersion}}")
    return result.stdout.strip() if result.returncode == 0 else None


def healthy_nodes() -> list[str]:
    """Names of nodes the cluster currently considers Ready.

    Goes through provision.node_ready_states, which asks the bootstrap node
    over SSH rather than using a local kubeconfig — after a wipe there is no
    local kubeconfig, and a stale one points at a cluster that no longer
    exists."""
    states = provision.node_ready_states(bootstrap_vm()) or {}
    return sorted(n for n, ready in states.items() if ready)


def _etcd_members(vm) -> set:
    """Member names etcd reports, or an empty set on failure.

    Empty rather than raising: the caller treats "cannot ask" and "unhealthy"
    the same way, and during a roll the member being replaced is legitimately
    unreachable."""
    r = subprocess.run(
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
            f"{provision.ADMIN_USER}@{vm.static_ip}",
            "sudo k0s etcd member-list",
        ],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    if r.returncode != 0:
        return set()
    try:
        return set((json.loads(r.stdout.strip().splitlines()[-1])).get("members", {}))
    except Exception:
        return set()


def wait_etcd_healthy(expected_names, timeout: int = 300) -> bool:
    """Block until etcd membership matches AND every API server's etcd is serving.

    WHY THIS EXISTS
    The between-node gate used to check Kubernetes health only — nodes Ready,
    system pods healthy. Those pass while etcd is mid-election or a member is
    missing, because the API server keeps serving from the surviving quorum.
    A roll that continues on that basis removes a second member from a cluster
    that has not finished absorbing the first removal.

    That is not hypothetical: it is what broke the first unattended roll. Three
    membership changes in seven minutes, `k0s token create` timed out, and the
    roll stopped mid-fleet.

    TWO signals, because neither alone is sufficient:

      1. MEMBERSHIP — the rejoined node is actually back in the member list.
         k0s only exposes `member-list`, so this is the membership half.
      2. SERVING — `/healthz/etcd` from EVERY API server, addressed directly.
         Checked per-controller rather than through the VIP: the load balancer
         round-robins, so one probe can hit a healthy controller and report
         success while others are not serving. Same reasoning as the tunnel
         check (ADR-044).
    """
    want = set(expected_names)
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        members = _etcd_members(bootstrap_vm())
        if members == want:
            unhealthy = []
            for _, vm in all_vms():
                r = subprocess.run(
                    [
                        "kubectl",
                        f"--server=https://{vm.static_ip}:6443",
                        "get",
                        "--raw",
                        "/healthz/etcd",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if r.returncode != 0 or "ok" not in r.stdout.lower():
                    unhealthy.append(vm.name)
            if not unhealthy:
                print(f"    etcd healthy — {len(members)} members, all serving")
                return True
            last = f"etcd not serving on: {', '.join(unhealthy)}"
        else:
            missing = want - members
            extra = members - want
            last = (
                "membership "
                + (f"missing {', '.join(sorted(missing))}" if missing else "")
                + (f" unexpected {', '.join(sorted(extra))}" if extra else "")
            )
        time.sleep(10)
    print(f"    etcd did NOT become healthy within {timeout}s — {last}")
    return False


def wait_longhorn_healthy(timeout: int = 900) -> bool:
    """Block until every Longhorn volume is healthy and nothing is rebuilding.

    No-op when Longhorn is not installed, so this is safe to call unconditionally.

    WHY IT MATTERS DURING A ROLL
    Replacing a node destroys its replicas. Longhorn rebuilds them elsewhere,
    which takes minutes and moves real data. Every other gate criterion passes
    throughout — nodes Ready, pods healthy, etcd fine — because none of them can
    see replica health. Replace the next node before the rebuild finishes and a
    volume drops below replica quorum. On a two-replica volume that is data loss,
    not degradation.

    The timeout is generous (15 min) because rebuild time scales with volume
    size, and halting a roll is far cheaper than losing a volume.
    """
    probe = subprocess.run(
        ["kubectl", "get", "crd", "volumes.longhorn.io"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if probe.returncode != 0:
        return True  # Longhorn not installed — nothing to wait for

    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        r = subprocess.run(
            [
                "kubectl",
                "-n",
                "longhorn-system",
                "get",
                "volumes.longhorn.io",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if r.returncode == 0:
            try:
                items = json.loads(r.stdout).get("items", [])
            except Exception:
                items = None
            if items is not None:
                bad = []
                for v in items:
                    name = v["metadata"]["name"]
                    st = v.get("status") or {}
                    rob = (st.get("robustness") or "unknown").lower()
                    # `degraded` means a replica is missing or rebuilding.
                    # `faulted` means the volume is already unusable.
                    if rob not in ("healthy",):
                        # A detached volume has no replicas to be healthy about.
                        if (st.get("state") or "").lower() == "detached":
                            continue
                        bad.append(f"{name}={rob}")
                if not bad:
                    print(
                        f"    longhorn healthy — {len(items)} volume(s), no rebuilds in flight"
                    )
                    return True
                last = ", ".join(bad[:4])
        time.sleep(15)
    print(f"    longhorn volumes did NOT become healthy within {timeout}s — {last}")
    return False


def roll(target: str | None = None) -> bool:
    """Replace nodes ONE AT A TIME onto the currently-pinned Kairos image.

    THE REQUIREMENT: Kairos/Hadron updates are destroy-and-rebuild, never
    in-place. The node OS is immutable — there is no `dnf update` path, so the
    only way to patch a node is to replace it.

    That makes this the NODE PATCHING STORY. The hypervisors get nightly
    updates; the nodes get none, and will run whatever image they were built
    from indefinitely. Rolling is not version hygiene, it is how node CVEs
    actually get fixed.

    WHY STRICTLY ONE AT A TIME, even though etcd could tolerate two:
    5 nodes means quorum 3, so two *could* be down at once — but that leaves
    ZERO margin, and a single unexpected failure inside that window loses
    quorum and takes the cluster with it. One at a time keeps a spare failure
    in hand throughout. The extra minutes are cheaper than the risk.

    Cluster health is re-verified BETWEEN every node, so a roll that starts
    going wrong stops instead of continuing to eat the fleet.
    """
    targets = [(h, v) for h, v in all_vms() if target is None or v.name == target]
    if not targets:
        print(f"no such node: {target}", file=sys.stderr)
        return False

    print(
        f"=== rolling {len(targets)} node(s) onto image {hosts_module.KAIROS_ISO_SHA256[:12]}... ==="
    )
    print("    one at a time; cluster health re-verified between each\n")

    expected = [v.name for _, v in all_vms()]

    for host, vm in targets:
        # --- gate: refuse to start unless the cluster is already whole ---
        ready = healthy_nodes()
        unhealthy = [n for n in expected if n not in ready]
        if unhealthy:
            print(
                f"REFUSING to roll {vm.name}: cluster is not fully healthy "
                f"(not Ready: {unhealthy})"
            )
            print(
                "  Rolling into a degraded cluster is how a maintenance window "
                "becomes an outage."
            )
            return False

        # The bootstrap node holds no special status once the cluster exists,
        # but a join token must be minted from something STILL RUNNING — never
        # from the node being replaced.
        donors = [(h, v) for h, v in all_vms() if v.name != vm.name and v.name in ready]
        if not donors:
            print(
                f"REFUSING to roll {vm.name}: no other healthy node to mint a token from"
            )
            return False
        donor_host, donor_vm = donors[0]

        print(f"--- {vm.name} (on {host.name}) --- token donor: {donor_vm.name}")

        # ⚠️ FETCH THE PINNED IMAGE FIRST. Without this the roll destroys the VM
        # and rebuilds it from whatever ISO is ALREADY on the hypervisor —
        # reporting "rolling onto image <new sha>" while changing nothing, and
        # passing every health gate because the cluster really is healthy. It is
        # just still on the old version.
        #
        # That happened: a roll to Kairos v4.2.0 brought the node back on
        # v4.1.2. Silent success is the worst failure mode a patching tool can
        # have — it reports the fleet as updated when it is not.
        #
        # ensure_kairos_iso() is checksum-gated, so this is a no-op when the
        # image is already correct.
        provision.ensure_kairos_iso(host)

        provision.destroy_and_undefine(host, vm)
        # A destroyed node's etcd membership outlives it. Left behind, that
        # ghost costs quorum on the NEXT replacement — the failure that once
        # bricked this cluster outright.
        provision.etcd_prune(donor_host, donor_vm, vm)
        provision.run(
            host, ["rm", "-f", f"{ISO_POOL_PATH}/{vm.name}-cloudinit.iso"], check=False
        )
        subprocess.run(
            ["ssh-keygen", "-R", vm.static_ip],
            capture_output=True,
            text=True,
            check=False,
        )

        token = provision.generate_join_token(donor_host, donor_vm)
        provision.create_vm(
            host, vm, join_token=token, bootstrap_pair=(donor_host, donor_vm)
        )

        print(f"    waiting for {vm.name} to rejoin and the cluster to settle...")
        provision.wait_for_nodes_ready(bootstrap_vm(), expected)
        if not _check_system_pods():
            print(f"ROLL HALTED: system pods did not settle after replacing {vm.name}")
            return False

        # Kubernetes health is NOT cluster health. Both of the checks below pass
        # through the gaps the criteria above cannot see — and both have a real
        # failure behind them (etcd) or a predicted one (Longhorn). Neither is
        # optional before touching the NEXT node.
        if not wait_etcd_healthy(expected):
            print(
                f"ROLL HALTED: etcd did not return to health after replacing {vm.name}"
            )
            print("  Continuing would remove a second member from a cluster that has")
            print(
                "  not absorbed the first removal — how the first unattended roll broke."
            )
            return False

        if not wait_longhorn_healthy():
            print(f"ROLL HALTED: Longhorn replicas still rebuilding after {vm.name}")
            print("  Replacing the next node now can drop a volume below replica")
            print("  quorum. That is data loss, not degradation.")
            return False

        # ASSERT THE OUTCOME, don't assume it. "Healthy" is not "updated" — the
        # bug above passed every health check while achieving nothing. The
        # expected k0s version is derivable from the pinned asset name, so there
        # is no excuse for taking the rebuild on trust.
        want = expected_k0s_version()
        if want:
            got = node_kubelet_version(vm.name)
            if got and want not in got:
                print(
                    f"ROLL HALTED: {vm.name} came back on kubelet {got}, "
                    f"but the pinned image carries k0s {want}."
                )
                print(
                    "  The node was rebuilt from a STALE image — the fleet is "
                    "NOT patched. Do not continue."
                )
                return False
            print(f"    {vm.name} verified on k0s {got}")

        print(f"    {vm.name} replaced and healthy\n")

    print("=== roll complete — every node rebuilt on the pinned image ===")
    provision.refresh_client_access(bootstrap_vm(), [v.static_ip for _, v in all_vms()])
    return True


# ------------------------------------------------------------------- cli


def main() -> int:
    """Dispatch the requested subcommand.

    Every destructive path requires --yes explicitly. The gate exists to be run
    unattended, so a mistyped subcommand must do nothing rather than something
    plausible."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_wipe = sub.add_parser("wipe", help="DESTRUCTIVE: destroy the entire fleet")
    p_wipe.add_argument(
        "--yes", action="store_true", help="required to actually destroy"
    )
    p_wipe.add_argument(
        "--dry-run", action="store_true", help="show what would be destroyed"
    )

    sub.add_parser("verify", help="check cluster health (non-destructive)")

    p_rebuild = sub.add_parser("rebuild", help="DESTRUCTIVE: wipe, rebuild, verify")
    p_rebuild.add_argument(
        "--yes", action="store_true", help="required to actually destroy"
    )
    p_rebuild.add_argument(
        "--method",
        choices=sorted(BOOTSTRAP_METHODS),
        default="python",
        help="which bootstrap implementation to rebuild with",
    )

    p_cmp = sub.add_parser(
        "compare", help="compare two saved fingerprints (non-destructive)"
    )
    p_cmp.add_argument("a", choices=sorted(BOOTSTRAP_METHODS))
    p_cmp.add_argument("b", choices=sorted(BOOTSTRAP_METHODS))

    sub.add_parser(
        "fingerprint", help="print the cluster's comparable end state (non-destructive)"
    )

    p_roll = sub.add_parser(
        "roll",
        help="DESTRUCTIVE (one node at a time): rebuild nodes onto the pinned Kairos image",
    )
    p_roll.add_argument(
        "--yes", action="store_true", help="required to actually replace nodes"
    )
    p_roll.add_argument("--node", help="roll only this node (default: the whole fleet)")

    args = parser.parse_args()

    if args.command == "verify":
        return 0 if verify() else 1

    if args.command == "fingerprint":
        print(json.dumps(cluster_fingerprint(), indent=2, sort_keys=True))
        return 0

    if args.command == "compare":
        return 0 if compare_saved(args.a, args.b) else 1

    if args.command == "roll":
        if not args.yes:
            print("refusing to roll without --yes", file=sys.stderr)
            return 2
        return 0 if roll(args.node) else 1

    # Destructive paths need an explicit flag. This tears down the whole
    # cluster; it must never be reachable by a bare command or a stray
    # shell-history recall.
    if args.command == "wipe":
        if args.dry_run:
            wipe(dry_run=True)
            return 0
        if not args.yes:
            print(
                "refusing to wipe without --yes (use --dry-run to preview)",
                file=sys.stderr,
            )
            return 2
        wipe()
        return 0

    if not args.yes:
        print("refusing to rebuild without --yes", file=sys.stderr)
        return 2
    return 0 if rebuild(args.method) else 1


if __name__ == "__main__":
    sys.exit(main())
