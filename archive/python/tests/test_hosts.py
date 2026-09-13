"""Topology logic that is easy to get subtly wrong and hard to notice."""

from __future__ import annotations

import pytest

import deploy_updates
import hosts


def test_fixture_topology():
    assert len(hosts.HOSTS) == 2
    assert sum(len(h.vms) for h in hosts.HOSTS) == 5
    assert (
        sum(1 for h in hosts.HOSTS for v in h.vms if v.bootstrap) == 1
    ), "exactly one VM in the fleet may be the bootstrap controller"


def test_peer_target_is_written_from_the_peers_point_of_view():
    """`ssh_target: null` means 'local' from the CONTROLLER's point of view. From
    the other hypervisor that same host is an ordinary remote, so peer_target
    must be used instead — otherwise the peer is handed `None` and the reboot
    safety gate silently has no peer to check."""
    local = next(h for h in hosts.HOSTS if h.ssh_target is None)
    remote = next(h for h in hosts.HOSTS if h.ssh_target is not None)

    # From the remote host, reaching the local one must use peer_target.
    assert deploy_updates.peer_ssh_target(remote, local) == local.peer_target
    # From the local host, the remote is reachable by its own ssh_target.
    assert deploy_updates.peer_ssh_target(local, remote) == remote.ssh_target


def test_peer_without_a_reachable_address_fails_loudly():
    """Silently returning None here would produce a reboot gate that always
    passes because it can never find its peer."""
    local = next(h for h in hosts.HOSTS if h.ssh_target is None)
    other = next(h for h in hosts.HOSTS if h.ssh_target is not None)
    stranded = hosts.Host(name="hvC", ssh_target=None, peer_target=None)
    with pytest.raises(RuntimeError):
        deploy_updates.peer_ssh_target(other, stranded)
    assert deploy_updates.peer_of(local) is not None


def test_every_node_has_a_distinct_address():
    ips = [v.static_ip for h in hosts.HOSTS for v in h.vms]
    assert len(ips) == len(set(ips)), f"duplicate node IPs: {ips}"
