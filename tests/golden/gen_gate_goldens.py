#!/usr/bin/env python3
"""Generate the gate-logic parity corpus FROM the Python gate.

Writes tests/golden/gate_logic.json: every pure decision function in gate.py,
run over the same shapes its own tests use plus the edge cases that a port
gets wrong (None names, Python repr quoting, quantity suffix order, insertion
order that leaks into output). The Rust integration test
crates/substrate-core/tests/gate_parity.rs replays it.

Generated, never hand-written, for the reason RUST_PORT.md gives for shlex:
a hand-written table proves only that the author's belief is self-consistent.

    .venv/bin/python tests/golden/gen_gate_goldens.py
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import gate  # noqa: E402

cases: list[dict] = []


def case(fn: str, args: list, expected) -> None:
    cases.append({"fn": fn, "args": args, "expected": expected})


# ------------------------------------------------------------ quantities
for q in [
    "", "  ", "0", "128Mi", "1Gi", "1.5Gi", "512Ki", "1023Ki", "1Ti", "1K", "1M", "1G",
    "100M", "1000000", "1073741824", "1073741825", "-5Mi", "5", "Mi", "abcMi", "5Ei",
    "1e3Mi", "2.5Mi", "0.4Mi", " 64Mi ", "64mi", "1.9999Gi",
]:
    case("parse_quantity_mib", [q], gate.parse_quantity_mib(q))


def _pod_req(*mems):
    return {"spec": {"containers": [{"resources": {"requests": {"memory": m}}} if m is not None else {} for m in mems]}}


for pod in [_pod_req("64Mi", "1Gi"), _pod_req(None), _pod_req("64Mi", None, "abc"), {"spec": {}}, {}]:
    case("pod_memory_request_mib", [pod], gate.pod_memory_request_mib(pod))

# ------------------------------------------------------------ percent + repr
for v in [0.0, 0.5, 0.005, 0.125, 0.8, 0.805, 0.91, 1.0, 2 / 3, 0.995, 0.245, 0.255]:
    case("pct0", [v], f"{v:.0%}")
for s_ in ["s1-vm1", "", "it's", 'say "hi"', "both ' and \"", "tab\there", "new\nline", "back\\slash", "ünïcode", "\x01ctl"]:
    case("py_repr_str", [s_], repr(s_))
for v in [None, True, False, 0, -3, 5, "x", ["a", 1, None], {"k": "v", "n": [1, 2]}, [], {}]:
    case("py_repr", [v], repr(v))

# ------------------------------------------------------------ system pods
def _fake_kubectl(mapping):
    def _k(args, timeout=60):
        for key, payload in mapping.items():
            if key in args:
                if payload is None:
                    return types.SimpleNamespace(returncode=1, stdout="", stderr="x")
                return types.SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        return types.SimpleNamespace(returncode=1, stdout="", stderr="unmatched")
    return _k


def _p(name, phase="Running", ready=True, statuses=1, ns="kube-system"):
    return {"metadata": {"name": name, "namespace": ns},
            "status": {"phase": phase, "containerStatuses": [{"ready": ready}] * statuses}}


def _ds(name, desired, ready):
    st = {}
    if desired is not None:
        st["desiredNumberScheduled"] = desired
    if ready is not None:
        st["numberReady"] = ready
    return {"metadata": {"name": name}, "status": st}


sysp_cases = [
    ({"items": [_p("a"), _p("b")]}, {"items": [_ds("d", 5, 5)]}),
    ({"items": [_p("a", ready=False)]}, {"items": []}),
    ({"items": [_p("a", phase="Pending", statuses=0)]}, {"items": []}),
    ({"items": [_p("job", phase="Succeeded")]}, {"items": []}),
    ({"items": [_p("a")]}, {"items": [_ds("d", 5, 4), _ds("e", None, None), _ds("f", 0, 0), _ds("g", 3, None)]}),
    ({"items": [{"metadata": {}, "status": {}}]}, {"items": [{"metadata": {}, "status": {}}]}),
    ({"items": [_p("m", statuses=3), {"metadata": {"name": "n"}, "status": {"phase": "Running", "containerStatuses": [{"ready": True}, {"ready": False}]}}]}, {"items": []}),
]
for pods, dss in sysp_cases:
    gate.kubectl = _fake_kubectl({"get pods -n kube-system": pods, "get daemonsets -n kube-system": dss})
    case("unhealthy_in_namespace", ["kube-system", pods, dss], gate._unhealthy_pods())

# ------------------------------------------------------------ placement
def _pod(node, owner_kind=None, phase="Running", name="p"):
    meta = {"name": name}
    if owner_kind:
        meta["ownerReferences"] = [{"kind": owner_kind}]
    return {"metadata": meta, "spec": {"nodeName": node}, "status": {"phase": phase}}


dist_payloads = [
    {"items": [_pod("a", "DaemonSet")] * 10 + [_pod("b", "DaemonSet")] * 10 + [_pod("a")] * 5},
    {"items": [_pod("a", "Job"), _pod("a", phase="Succeeded"), _pod("a", phase="Pending"), _pod("a")]},
    {"items": [_pod("zeta"), _pod("alpha"), _pod("zeta"), _pod(None), _pod("")]},
    {"items": []},
]
for pl in dist_payloads:
    case("schedulable_pods_by_node", [pl], list(gate.schedulable_pods_by_node(pl).items()))

NH = {"s1-vm1": "server1", "s1-vm2": "server1", "s2-vm1": "server2", "s2-vm2": "server2", "s2-vm3": "server2"}
conc_cases = [
    ({"s1-vm1": 5, "s2-vm1": 5}, NH, ["s1-vm1", "s2-vm1"], set()),
    ({"s1-vm1": 5}, NH, ["s1-vm1", "s2-vm1"], set()),
    ({"s2-vm1": 19, "s1-vm1": 1}, NH, ["s1-vm1", "s2-vm1"], set()),
    ({"s1-vm1": 6, "s2-vm1": 4}, NH, ["s1-vm1", "s2-vm1"], {"server1"}),
    ({"s1-vm1": 4, "s2-vm1": 6}, NH, ["s1-vm1", "s2-vm1"], {"server1"}),
    ({"ghost": 3, "s1-vm1": 1, "other'q": 1}, NH, [], set()),
    ({}, NH, ["s1-vm1"], set()),
    ({"s1-vm1": 41, "s2-vm1": 1, "s2-vm2": 1}, NH, ["s2-vm3", "s1-vm1", "s2-vm1", "s2-vm2"], {"server1"}),
]
for counts, nh, ready, prone in conc_cases:
    case("concentration_failures", [list(counts.items()), nh, ready, sorted(prone)],
         gate.concentration_failures(counts, nh, ready, prone))

# ------------------------------------------------------------ labels
LABEL = gate.HYPERVISOR_LABEL


def _node(name, hypervisor=None, extra=None):
    labels = {"kubernetes.io/hostname": name} if name is not None else {}
    if hypervisor is not None:
        labels[LABEL] = hypervisor
    labels.update(extra or {})
    meta = {"labels": labels}
    if name is not None:
        meta["name"] = name
    return {"metadata": meta}


label_cases = [
    [_node("s1-vm1", "server1"), _node("s1-vm2", "server1"), _node("s2-vm1", "server2")],
    [_node("s1-vm1", "server1"), _node("s2-vm1")],
    [_node("s1-vm1", "server1"), _node("s1-vm2", "server1"), _node("s2-vm1")],
    [_node("s1-vm1", "server2"), _node("s2-vm1", "server2")],
    [_node("s1-vm1", "server1"), _node("s1-vm2", "server1")],
    [_node("s9-vm1", "server9")],
    [_node(None, "server1")],
    [{"metadata": {"name": "s1-vm1"}}],
    [],
]
for nodes in label_cases:
    pl = {"items": nodes}
    case("node_label_failures", [pl, NH, LABEL], gate.node_label_failures(pl, NH))

# ------------------------------------------------------------ critical pairs
def _bind_pod(name, node, namespace="bindy-system", labels=None, phase="Running"):
    return {"metadata": {"name": name, "namespace": namespace,
                         "labels": {"bindy.firestoned.io/role": "primary", **(labels or {})}},
            "spec": {"nodeName": node}, "status": {"phase": phase}}


PART = {"app.kubernetes.io/part-of": "bindy"}
crit_cases = [
    [_bind_pod("p0", "s2-vm1", labels=PART), _bind_pod("p1", "s2-vm1", labels=PART)],
    [_bind_pod("p0", "s2-vm1", labels=PART), _bind_pod("p1", "s2-vm2", labels=PART)],
    [_bind_pod("p0", "s1-vm1", labels=PART), _bind_pod("p1", "s2-vm1", labels=PART)],
    [],
    [_bind_pod("p0", "s1-vm1", labels=PART)],
    [_bind_pod("p0", "s1-vm1", labels=PART), _bind_pod("p1", "s2-vm1", labels=PART, phase="Pending")],
    [_bind_pod("p0", "s1-vm1", labels=PART), _bind_pod("p1", "ghost", labels=PART)],
    [_bind_pod("p0", "s1-vm1"), _bind_pod("p1", "s2-vm1")],
    [_bind_pod("p0", "s1-vm1", namespace="other", labels=PART), _bind_pod("p1", "s2-vm1", labels=PART)],
    [_bind_pod("p0", "s1-vm1", labels=PART), _bind_pod("p1", None, labels=PART), _bind_pod("p2", "s2-vm1", labels=PART)],
]
for pods in crit_cases:
    pl = {"items": pods}
    case("critical_pair_failures", [pl, NH], gate.critical_pair_failures(pl, NH))
    case("pods_matching_names", [pl, "bindy-system", [list(kv) for kv in gate.CRITICAL_PAIRS[0]["selector"].items()]],
         [p["metadata"]["name"] for p in gate.pods_matching(pl, "bindy-system", gate.CRITICAL_PAIRS[0]["selector"])])

# ------------------------------------------------------------ survivability
NH3 = {"s1-vm1": "server1", "s1-vm2": "server1", "s2-vm1": "server2"}


def _wl(node, mib, name="p", kind="ReplicaSet", pin=None, namespace="ns", phase="Running", req=None):
    pod = {"metadata": {"name": name, "namespace": namespace, "ownerReferences": [{"kind": kind}]},
           "spec": {"nodeName": node, "containers": [{"resources": {"requests": {"memory": req or f"{mib}Mi"}}}]},
           "status": {"phase": phase}}
    if pin:
        pod["spec"]["affinity"] = {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
            "nodeSelectorTerms": [{"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": pin}]}]}}}
    return pod


ALLOC = {"s1-vm1": 4000, "s1-vm2": 4000, "s2-vm1": 3000}
surv_cases = [
    ([_wl("s1-vm1", 2000), _wl("s1-vm2", 2000)], ALLOC, NH3),
    ([_wl("s1-vm1", 500), _wl("s2-vm1", 500)], ALLOC, NH3),
    ([_wl("s1-vm1", 100, name="pinned", pin=["s1-vm1", "s1-vm2"]), _wl("s2-vm1", 100)], ALLOC, NH3),
    ([_wl("s1-vm1", 100, name="wide", pin=["s1-vm1", "s2-vm1"])], ALLOC, NH3),
    ([_wl("s1-vm1", 100, kind="DaemonSet"), _wl("s2-vm1", 2900, kind="DaemonSet"), _wl("s1-vm1", 200)], ALLOC, NH3),
    ([_wl("s1-vm1", 9999, kind="Job")], ALLOC, NH3),
    ([_wl("s1-vm1", 100)], {"s1-vm1": 4000}, {"s1-vm1": "server1"}),
    ([_wl("s1-vm1", m, name=f"p{i}", pin=["s1-vm1"]) for i, m in enumerate([5, 50, 500, 5000, 1, 2])] + [_wl("s2-vm1", 1)], ALLOC, NH3),
    ([_wl("s1-vm1", 100, phase="Pending"), _wl("s1-vm1", 100, phase="Succeeded"), _wl("ghost", 100), _wl(None, 100)], ALLOC, NH3),
    ([_wl("s1-vm1", 0, req=""), _wl("s1-vm1", 0, req="1Gi")], ALLOC, NH3),
    ([{"metadata": {"ownerReferences": []}, "spec": {"nodeName": "s1-vm1"}, "status": {"phase": "Running"}}], ALLOC, NH3),
    ([{"metadata": {}, "spec": {"nodeName": "s1-vm1", "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": ["s2-vm1"]}]}]}}}}, "status": {"phase": "Running"}}], ALLOC, NH3),
]
for pods, alloc, nh in surv_cases:
    pl = {"items": pods}
    w, room, pinned = gate.survivability_budget(pl, alloc, nh)
    case("survivability_budget", [pl, alloc, nh], {"workload": w, "room": room, "pinned_by_host": {k: [list(t) for t in v] for k, v in pinned.items()}})
    case("survivability_failures", [pl, alloc, nh], gate.survivability_failures(pl, alloc, nh))
    for p in pods:
        case("pinned_hypervisors", [p, nh], sorted(gate.pinned_hypervisors(p, nh)))

# a preferred affinity does not pin
pref = _wl("s1-vm1", 100)
pref["spec"]["affinity"] = {"nodeAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": [
    {"weight": 1, "preference": {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": ["s1-vm1"]}]}}]}}
case("pinned_hypervisors", [pref, NH3], sorted(gate.pinned_hypervisors(pref, NH3)))
notin = _wl("s1-vm1", 100, pin=["s1-vm1"])
notin["spec"]["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"][0]["matchExpressions"][0]["operator"] = "NotIn"
case("pinned_hypervisors", [notin, NH3], sorted(gate.pinned_hypervisors(notin, NH3)))

# ------------------------------------------------------------ fingerprints
fp_cases = [
    ({"a": 1}, {"a": 1}),
    ({"a": 1}, {"a": 2}),
    ({"a": 1, "b": 2}, {"a": 1}),
    ({"nodes": {"x": {"ready": True, "v": "1"}}}, {"nodes": {"x": {"ready": False, "v": "1"}, "y": {}}}),
    ({"k": [1, 2]}, {"k": [1, 3]}),
    ({"k": None}, {"k": "s1-vm1"}),
    ({"k": {"deep": {"er": "it's"}}}, {"k": {"deep": {"er": 'say "hi"'}}}),
    ({"k": {"n": 1}}, {"k": 1}),
    ({"placement": {"s1-vm1": "server1"}}, {"placement": {"s1-vm1": "server2"}}),
]
for a, b in fp_cases:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        same = gate.compare_fingerprints(a, b, "python", "rust")
    case("fingerprint_differences", [a, b, "python", "rust"], {"same": same, "output": buf.getvalue()})

# ------------------------------------------------------------ etcd + version
for out in [
    'level=info msg="..."\n{"members":{"s1-vm1":"https://a:2380","s2-vm1":"https://b:2380"}}\n',
    '{"members":{}}', "", "garbage", '{"nope":1}', '{"members":{"only":"x"}}\n\n',
]:
    last = out.strip().splitlines()[-1] if out.strip() else ""
    try:
        exp = sorted(json.loads(last).get("members", {}))
    except Exception:
        exp = []
    case("etcd_members_from", [out], exp)

import hosts as hosts_module  # noqa: E402
for url in [
    "https://github.com/kairos-io/kairos/releases/download/v4.2.0/kairos-hadron-v0.5.1-standard-amd64-generic-v4.2.0-k0sv1.36.3%2Bk0s.2.iso",
    "https://x/kairos-k0sv1.36.3+k0s.2.iso", "https://x/kairos-k0sv1.2.iso", "https://x/nothing.iso",
    "https://x/k0sv+k0s.iso", "https://x/k0svabc-k0sv1.0+k0s.iso", "",
]:
    hosts_module.KAIROS_ISO_URL = url
    case("expected_k0s_version", [url], gate.expected_k0s_version())

out = Path(__file__).with_name("gate_logic.json")
out.write_text(json.dumps({"generated_by": "tests/golden/gen_gate_goldens.py", "cases": cases}, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
print(f"{len(cases)} cases -> {out}")
