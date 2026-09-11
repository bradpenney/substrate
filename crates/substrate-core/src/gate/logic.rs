//! The gate's DECISIONS, as pure functions over what the cluster reports.
//!
//! Ported from `gate.py`. Nothing in this file talks to a cluster: every
//! function takes the JSON a `kubectl -o json` returned and answers a
//! question about it. That is what makes the decisions testable in both
//! directions — a verify that can only pass is how a half-rolled DaemonSet
//! got through (ADR-080) — and what lets a corpus GENERATED from the Python
//! prove the two agree, line for line, before the Python is archived.
//!
//! Output strings are reproduced exactly, including Python's `repr` of the
//! values it quotes, because the live differential diffs the two gates'
//! stdout and a cosmetic drift would hide a real one.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A rebuilt cluster needs a moment after nodes go Ready before every system
/// pod has been rescheduled and settled. Separate from the node timeout
/// because it is a different failure mode: nodes Ready, workloads not
/// converging.
pub const PODS_READY_TIMEOUT: u64 = 600;
pub const PODS_POLL_INTERVAL: u64 = 10;
pub const DNS_TIMEOUT: u64 = 120;

/// Namespaces whose pods must all be healthy for the cluster to count as
/// "live and ready". k0s puts everything it manages in these.
pub const SYSTEM_NAMESPACES: &[&str] = &["kube-system"];

/// No single hypervisor may hold more than this share of the schedulable pods
/// (ADR-097). Deliberately loose — it exists to catch CONCENTRATION, not to
/// enforce balance. The runs it is meant to fail measured 95% and 93%.
pub const MAX_HYPERVISOR_POD_SHARE: f64 = 0.80;

/// A host marked `failure_prone` may not hold the MAJORITY of the platform.
/// The symmetric cap above passed a fleet with 74% on the host that does not
/// power itself back on. Spread is the goal; relocation is not.
pub const MAX_FAILURE_PRONE_POD_SHARE: f64 = 0.50;

/// The node label naming a node's hypervisor (ADR-144). Restated here rather
/// than imported from the renderer: this is the value the gate ASSERTS
/// against, and a gate that read the constant the renderer writes would agree
/// with itself and could never report that the two had diverged.
pub const HYPERVISOR_LABEL: &str = "invariant-platform.io/hypervisor";

/// A workload whose replicas MUST land in different failure domains, checked
/// by name rather than in aggregate. `min_replicas` is load-bearing: without
/// it a selector typo finds no pods and the spread question is vacuously
/// satisfied — a check that passes because it found nothing.
pub struct CriticalPair {
    pub name: &'static str,
    pub namespace: &'static str,
    pub selector: &'static [(&'static str, &'static str)],
    pub min_replicas: usize,
    pub why: &'static str,
}

pub const CRITICAL_PAIRS: &[CriticalPair] = &[CriticalPair {
    name: "BIND primaries (LAN DNS)",
    namespace: "bindy-system",
    // Matches both `homelab-primary-0` and `-1`: separate single-replica
    // Deployments, which no constraint about one workload's replicas can spread.
    selector: &[
        ("bindy.firestoned.io/role", "primary"),
        ("app.kubernetes.io/part-of", "bindy"),
    ],
    min_replicas: 2,
    why: "a single-domain resolver takes the LAN offline with one host",
}];

/// Credentials the platform cannot function without, checked through the
/// ExternalSecret that produces each one rather than by reading the Secret
/// (ADR-071). Short on purpose: a gate, not an inventory.
pub const REQUIRED_EXTERNAL_SECRETS: &[(&str, &str, &str)] = &[
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
];

// ------------------------------------------------------------ JSON helpers

fn s<'a>(v: &'a Value, path: &str) -> Option<&'a str> {
    v.pointer(path).and_then(Value::as_str)
}

fn items(v: &Value) -> &[Value] {
    v.get("items")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Python's `repr()` of a str, for the messages that quote one. ASCII-exact;
/// non-ASCII printable characters pass through as Python 3 would print them.
pub fn py_repr_str(v: &str) -> String {
    let quote = if v.contains('\'') && !v.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(v.len() + 2);
    out.push(quote);
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `repr()` of a JSON-shaped value: `None`, `True`, `'str'`,
/// `['a', 1]`, `{'k': v}`.
pub fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", py_repr_str(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `f"{x:.0%}"` — Python multiplies in double precision and rounds the
/// exact binary value half-to-even, which is also what Rust's formatter does.
pub fn pct0(share: f64) -> String {
    format!("{:.0}%", share * 100.0)
}

/// An optional JSON string as Python would print it in an f-string: the
/// string itself, or `None`.
fn or_none(v: Option<&str>) -> String {
    v.map_or_else(|| "None".to_string(), str::to_string)
}

// ------------------------------------------------------------ system pods

/// Names of system workloads in one namespace that aren't fully rolled out
/// and ready. Pure half of `gate.py::_unhealthy_pods`: the caller has already
/// fetched the pod list and the DaemonSet list.
///
/// Readiness is per-container, not phase: a pod sits in Running with 0/1
/// ready indefinitely under a failing probe. And a DaemonSet that has not
/// finished SCHEDULING passes the pod loop — four ready konnectivity-agents
/// with the fifth not yet created reads as healthy, and the fingerprint taken
/// straight after records numberReady=4 (what broke `compare` on 2026-08-28).
pub fn unhealthy_in_namespace(namespace: &str, pods: &Value, daemonsets: &Value) -> Vec<String> {
    let mut bad = Vec::new();
    for pod in items(pods) {
        let name = s(pod, "/metadata/name").unwrap_or("<unnamed>");
        let phase = s(pod, "/status/phase");
        // Completed one-shot pods are fine; they're not meant to stay up.
        if phase == Some("Succeeded") {
            continue;
        }
        let statuses = pod
            .pointer("/status/containerStatuses")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let ready = statuses
            .iter()
            .filter(|c| c.get("ready").and_then(Value::as_bool) == Some(true))
            .count();
        let total = statuses.len();
        if phase != Some("Running") || total == 0 || ready != total {
            bad.push(format!(
                "{namespace}/{name} ({}, {ready}/{total} ready)",
                or_none(phase)
            ));
        }
    }
    for ds in items(daemonsets) {
        let name = s(ds, "/metadata/name").unwrap_or("<unnamed>");
        let desired = ds
            .pointer("/status/desiredNumberScheduled")
            .and_then(Value::as_i64);
        let ready = ds.pointer("/status/numberReady").and_then(Value::as_i64);
        // `desired` is 0 before the controller has observed the DaemonSet at
        // all; treat that as "not settled yet" rather than as satisfied.
        if desired.is_none() || ready.is_none() || desired == Some(0) || ready != desired {
            let show = |v: Option<i64>| v.map_or("?".to_string(), |n| n.to_string());
            bad.push(format!(
                "{namespace}/daemonset/{name} ({}/{} scheduled-and-ready)",
                show(ready),
                show(desired)
            ));
        }
    }
    bad
}

// -------------------------------------------------------------- placement

fn owner_kinds(pod: &Value) -> Vec<&str> {
    pod.pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .map(|os| {
            os.iter()
                .filter_map(|o| o.get("kind").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

/// Pods the SCHEDULER placed, per node, in first-seen order (the Python
/// returns a dict, and one caller's output order depends on insertion order).
///
/// DaemonSet pods run one per node by definition; counting them makes any
/// fleet look balanced and hid a real 39-vs-3 split as 66-vs-21. Job pods are
/// transient. Only Running pods count: Pending has no node, Succeeded holds
/// nothing.
pub fn schedulable_pods_by_node(payload: &Value) -> Vec<(String, i64)> {
    let mut counts: Vec<(String, i64)> = Vec::new();
    for pod in items(payload) {
        if owner_kinds(pod)
            .iter()
            .any(|k| *k == "DaemonSet" || *k == "Job")
        {
            continue;
        }
        if s(pod, "/status/phase") != Some("Running") {
            continue;
        }
        if let Some(node) = s(pod, "/spec/nodeName").filter(|n| !n.is_empty()) {
            match counts.iter_mut().find(|(n, _)| n == node) {
                Some((_, c)) => *c += 1,
                None => counts.push((node.to_string(), 1)),
            }
        }
    }
    counts
}

/// A Kubernetes memory quantity as whole MiB. Unparseable reads as 0 — the
/// honest answer for a container with no request, and what the scheduler
/// itself assumes when deciding what fits.
pub fn parse_quantity_mib(value: &str) -> i64 {
    let v = value.trim();
    if v.is_empty() {
        return 0;
    }
    const UNITS: &[(&str, f64)] = &[
        ("Ki", 1.0 / 1024.0),
        ("Mi", 1.0),
        ("Gi", 1024.0),
        ("Ti", 1024.0 * 1024.0),
        ("K", 1000.0 / 1048576.0),
        ("M", 1000000.0 / 1048576.0),
        ("G", 1000000000.0 / 1048576.0),
    ];
    for (suffix, factor) in UNITS {
        if let Some(num) = v.strip_suffix(suffix) {
            return match num.parse::<f64>() {
                Ok(f) => (f * factor) as i64,
                Err(_) => 0,
            };
        }
    }
    match v.parse::<i64>() {
        Ok(n) => (n as f64 / 1048576.0) as i64,
        Err(_) => 0,
    }
}

/// Total memory REQUEST of a pod in MiB. Requests, not limits and not usage:
/// requests are what the scheduler reserves, so they decide whether a pod
/// fits on a surviving node.
pub fn pod_memory_request_mib(pod: &Value) -> i64 {
    pod.pointer("/spec/containers")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .map(|c| parse_quantity_mib(s(c, "/resources/requests/memory").unwrap_or("")))
                .sum()
        })
        .unwrap_or(0)
}

/// Hypervisors a pod's REQUIRED nodeAffinity confines it to. Empty means
/// anywhere. Only `required` counts: `preferred` is a hint the scheduler may
/// ignore under pressure, which is exactly the situation being modelled.
pub fn pinned_hypervisors(
    pod: &Value,
    node_hypervisor: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let Some(terms) = pod
        .pointer("/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms")
        .and_then(Value::as_array)
    else {
        return hosts;
    };
    for term in terms {
        for expr in term
            .get("matchExpressions")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
        {
            if expr.get("key").and_then(Value::as_str) != Some("kubernetes.io/hostname") {
                continue;
            }
            if expr.get("operator").and_then(Value::as_str) != Some("In") {
                continue;
            }
            for node in expr
                .get("values")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
            {
                if let Some(host) = node.as_str().and_then(|n| node_hypervisor.get(n)) {
                    hosts.insert(host.clone());
                }
            }
        }
    }
    hosts
}

pub struct Budget {
    /// Reschedulable memory, DaemonSets excluded.
    pub workload: i64,
    /// What the survivors offer if THIS host is lost, net of their DaemonSets.
    pub room: BTreeMap<String, i64>,
    /// Pods confined to one host by nodeAffinity: (namespace/name, MiB).
    pub pinned_by_host: BTreeMap<String, Vec<(String, i64)>>,
}

/// The arithmetic behind survivability. One implementation, both directions:
/// the passing path prints the same numbers the failing path computes, so a
/// green line is distinguishable from a check that measured nothing.
pub fn survivability_budget(
    pods: &Value,
    allocatable_mib: &BTreeMap<String, i64>,
    node_hypervisor: &BTreeMap<String, String>,
) -> Budget {
    let hypervisors: BTreeSet<&String> = node_hypervisor.values().collect();
    let mut ds_by_host: BTreeMap<String, i64> =
        hypervisors.iter().map(|h| ((*h).clone(), 0)).collect();
    let mut pinned_by_host: BTreeMap<String, Vec<(String, i64)>> = hypervisors
        .iter()
        .map(|h| ((*h).clone(), Vec::new()))
        .collect();
    let mut workload = 0;

    for pod in items(pods) {
        let node = s(pod, "/spec/nodeName").unwrap_or("");
        let Some(host) = node_hypervisor.get(node) else {
            continue;
        };
        if !matches!(s(pod, "/status/phase"), Some("Running") | Some("Pending")) {
            continue;
        }
        let kind = owner_kinds(pod).first().copied().unwrap_or("");
        let mib = pod_memory_request_mib(pod);
        if kind == "DaemonSet" {
            *ds_by_host.entry(host.clone()).or_insert(0) += mib;
            continue;
        }
        if kind == "Job" {
            continue; // transient; it will not need rescheduling
        }
        workload += mib;
        let confined = pinned_hypervisors(pod, node_hypervisor);
        if confined.len() == 1 {
            let only = confined.into_iter().next().unwrap();
            let name = format!(
                "{}/{}",
                or_none(s(pod, "/metadata/namespace")),
                or_none(s(pod, "/metadata/name"))
            );
            pinned_by_host.entry(only).or_default().push((name, mib));
        }
    }

    let mut alloc_by_host: BTreeMap<String, i64> =
        hypervisors.iter().map(|h| ((*h).clone(), 0)).collect();
    for (node, mib) in allocatable_mib {
        if let Some(host) = node_hypervisor.get(node) {
            *alloc_by_host.entry(host.clone()).or_insert(0) += mib;
        }
    }

    let room = hypervisors
        .iter()
        .map(|lost| {
            let sum = hypervisors
                .iter()
                .filter(|h| *h != lost)
                .map(|h| {
                    alloc_by_host.get(*h).copied().unwrap_or(0)
                        - ds_by_host.get(*h).copied().unwrap_or(0)
                })
                .sum();
            ((*lost).clone(), sum)
        })
        .collect();
    Budget {
        workload,
        room,
        pinned_by_host,
    }
}

/// Reasons the fleet would not survive losing a hypervisor. Empty is fine.
///
/// The property the spread check only approximates. On 2026-09-10 the share
/// check failed at 91% and recommended a descheduler, while the fleet was
/// 610 MiB short of fitting on the survivor however the pods were arranged
/// (ADR-170). A descheduler moves pods; it does not create memory.
pub fn survivability_failures(
    pods: &Value,
    allocatable_mib: &BTreeMap<String, i64>,
    node_hypervisor: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut failures = Vec::new();
    let hypervisors: BTreeSet<&String> = node_hypervisor.values().collect();
    if hypervisors.len() < 2 {
        return failures; // nothing to survive the loss of
    }
    let b = survivability_budget(pods, allocatable_mib, node_hypervisor);
    for lost in hypervisors {
        let available = b.room.get(lost).copied().unwrap_or(0);
        if b.workload > available {
            failures.push(format!(
                "losing {lost} leaves {available} MiB for {} MiB of workload — short by {} MiB",
                b.workload,
                b.workload - available
            ));
        }
        if let Some(stranded) = b.pinned_by_host.get(lost).filter(|v| !v.is_empty()) {
            let mut by_size = stranded.clone();
            by_size.sort_by_key(|(_, m)| -m);
            let mut listed = by_size
                .iter()
                .take(4)
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            if by_size.len() > 4 {
                listed.push_str(&format!(", +{} more", by_size.len() - 4));
            }
            let total: i64 = stranded.iter().map(|(_, m)| m).sum();
            failures.push(format!(
                "losing {lost} strands {} pod(s) ({total} MiB) pinned to it by nodeAffinity — they go Pending, not elsewhere: {listed}",
                stranded.len()
            ));
        }
    }
    failures
}

/// Reasons the placement is unacceptable. Empty means it is fine.
///
/// Two distinct failures: a Ready node running NOTHING the scheduler chose to
/// put there (the ADR-097 signature), and one hypervisor holding too much of
/// everything — asymmetrically, because a `failure_prone` host may not hold
/// the majority while a dedicated one may hold up to the general cap.
pub fn concentration_failures(
    counts: &[(String, i64)],
    node_hypervisor: &BTreeMap<String, String>,
    ready_nodes: &[String],
    failure_prone: &BTreeSet<String>,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut ready: Vec<&String> = ready_nodes.iter().collect();
    ready.sort();
    for node in ready {
        let count = counts
            .iter()
            .find(|(n, _)| n == node)
            .map_or(0, |(_, c)| *c);
        if count == 0 {
            failures.push(format!("{node} is Ready but runs no scheduled pods"));
        }
    }
    let total: i64 = counts.iter().map(|(_, c)| c).sum();
    if total == 0 {
        failures.push("no scheduled pods found at all".into());
        return failures;
    }
    let mut by_hypervisor: BTreeMap<&String, i64> = BTreeMap::new();
    for (node, count) in counts {
        // A pod on a node the fleet definition does not know about is itself
        // a finding: attributing it to a guessed hypervisor would hide that.
        match node_hypervisor.get(node) {
            None => failures.push(format!(
                "pods scheduled on unknown node {}",
                py_repr_str(node)
            )),
            Some(host) => *by_hypervisor.entry(host).or_insert(0) += count,
        }
    }
    for (host, count) in by_hypervisor {
        let share = count as f64 / total as f64;
        let prone = failure_prone.contains(host);
        let limit = if prone {
            MAX_FAILURE_PRONE_POD_SHARE
        } else {
            MAX_HYPERVISOR_POD_SHARE
        };
        if share > limit {
            let why = if prone {
                " and may not come back unattended"
            } else {
                ""
            };
            failures.push(format!(
                "{host} holds {count}/{total} scheduled pods ({}, limit {}){why}",
                pct0(share),
                pct0(limit)
            ));
        }
    }
    failures
}

/// Reasons the cluster's topology labels disagree with the fleet definition
/// (ADR-144). Kubelet applies `--node-labels` only when it CREATES the Node
/// object, so declared and applied are different states; and PARTIAL
/// labelling makes a spread constraint succeed while measuring nothing, so
/// fewer than two represented domains is reported even when every node agrees.
pub fn node_label_failures(
    payload: &Value,
    node_hypervisor: &BTreeMap<String, String>,
    label_key: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for node in items(payload) {
        let name = s(node, "/metadata/name");
        let actual = node
            .pointer("/metadata/labels")
            .and_then(|l| l.get(label_key))
            .and_then(Value::as_str);
        let expected = name.and_then(|n| node_hypervisor.get(n));
        let shown = or_none(name);
        let Some(expected) = expected else {
            failures.push(format!(
                "node {} is in the cluster but not in site.yml",
                name.map_or("None".to_string(), py_repr_str)
            ));
            continue;
        };
        let Some(actual) = actual else {
            failures.push(format!(
                "{shown} carries no {label_key} label — site.yml says {}. Nothing schedulable can place it in a failure domain, and a spread constraint will skip it silently",
                py_repr_str(expected)
            ));
            continue;
        };
        if actual != expected {
            failures.push(format!(
                "{shown} is labelled {label_key}={} but site.yml says {} — the cluster and the fleet definition disagree",
                py_repr_str(actual),
                py_repr_str(expected)
            ));
            continue;
        }
        seen.insert(actual);
    }
    if !seen.is_empty() && seen.len() < 2 {
        let only = seen.iter().next().unwrap();
        failures.push(format!(
            "every correctly labelled node is in one failure domain ({only}) — a spread constraint over one domain is satisfied vacuously"
        ));
    }
    failures
}

/// Running pods in `namespace` carrying EVERY label in `selector`. Every, not
/// any — a partial match silently widens the selector to a whole namespace.
pub fn pods_matching<'a>(
    payload: &'a Value,
    namespace: &str,
    selector: &[(&str, &str)],
) -> Vec<&'a Value> {
    items(payload)
        .iter()
        .filter(|pod| s(pod, "/metadata/namespace") == Some(namespace))
        .filter(|pod| s(pod, "/status/phase") == Some("Running"))
        .filter(|pod| {
            let labels = pod.pointer("/metadata/labels");
            selector
                .iter()
                .all(|(k, v)| labels.and_then(|l| l.get(*k)).and_then(Value::as_str) == Some(*v))
        })
        .collect()
}

/// Reasons a named critical workload is not spread. Empty means it is fine.
///
/// Reads the node → hypervisor map from site.yml, NOT from the node label:
/// the gate must be able to report that the labels are missing or wrong, and
/// a check that trusted them could not.
pub fn critical_pair_failures(
    payload: &Value,
    node_hypervisor: &BTreeMap<String, String>,
    specs: &[CriticalPair],
) -> Vec<String> {
    let mut failures = Vec::new();
    for spec in specs {
        let pods = pods_matching(payload, spec.namespace, spec.selector);
        if pods.len() < spec.min_replicas {
            failures.push(format!(
                "{}: found {} Running replica(s), expected at least {} — degraded, or the selector no longer matches",
                spec.name,
                pods.len(),
                spec.min_replicas
            ));
            continue;
        }
        let mut domains: BTreeMap<&String, Vec<&str>> = BTreeMap::new();
        for pod in &pods {
            let node = s(pod, "/spec/nodeName");
            match node.and_then(|n| node_hypervisor.get(n)) {
                None => failures.push(format!(
                    "{}: replica on unknown node {}",
                    spec.name,
                    node.map_or("None".to_string(), py_repr_str)
                )),
                Some(host) => domains
                    .entry(host)
                    .or_default()
                    .push(s(pod, "/metadata/name").unwrap_or("")),
            }
        }
        if domains.len() < 2 {
            let wher = domains
                .iter()
                .map(|(h, names)| format!("{h} ({})", names.len()))
                .collect::<Vec<_>>()
                .join(", ");
            failures.push(format!(
                "{}: all {} replicas in ONE failure domain — {wher}. {}",
                spec.name,
                pods.len(),
                spec.why
            ));
        }
    }
    failures
}

// -------------------------------------------------------------- fingerprint

/// Every difference between two cluster end states, as `gate.py` prints them.
///
/// Reports ALL differences rather than stopping at the first, and compares the
/// union of keys at each level so a key present on only one side is reported
/// rather than skipped — that asymmetry is the most important thing a
/// comparison can catch.
pub fn fingerprint_differences(a: &Value, b: &Value, label_a: &str, label_b: &str) -> Vec<String> {
    let mut problems = Vec::new();
    fn walk(x: &Value, y: &Value, path: &str, la: &str, lb: &str, out: &mut Vec<String>) {
        let (Some(xo), Some(yo)) = (x.as_object(), y.as_object()) else {
            return;
        };
        let keys: BTreeSet<&String> = xo.keys().chain(yo.keys()).collect();
        for key in keys {
            let wher = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            match (xo.get(key), yo.get(key)) {
                (None, _) => out.push(format!("  {wher}: absent after {la}, present after {lb}")),
                (_, None) => out.push(format!("  {wher}: present after {la}, absent after {lb}")),
                (Some(xv), Some(yv)) if xv.is_object() && yv.is_object() => {
                    walk(xv, yv, &wher, la, lb, out)
                }
                (Some(xv), Some(yv)) if xv != yv => out.push(format!(
                    "  {wher}: {la}={} vs {lb}={}",
                    py_repr(xv),
                    py_repr(yv)
                )),
                _ => {}
            }
        }
    }
    walk(a, b, "", label_a, label_b, &mut problems);
    problems
}

/// Member names from `k0s etcd member-list` output, or empty on any failure.
/// The JSON is the LAST line; k0s prints log lines before it.
pub fn etcd_members_from(stdout: &str) -> BTreeSet<String> {
    let Some(last) = stdout.trim().lines().last() else {
        return BTreeSet::new();
    };
    serde_json::from_str::<Value>(last)
        .ok()
        .and_then(|v| {
            v.get("members")
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
        })
        .unwrap_or_default()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The k0s version the PINNED image carries, parsed from its asset name —
/// Kairos encodes it as `...-k0sv1.36.3+k0s.2.iso` (the `+` arrives as `%2B`).
/// Makes the intended outcome of a roll checkable rather than assumed.
pub fn expected_k0s_version(iso_url: &str) -> Option<String> {
    let url = percent_decode(iso_url);
    let mut start = 0;
    while let Some(pos) = url[start..].find("k0sv") {
        let after = start + pos + 4;
        let ver: String = url[after..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !ver.is_empty() && url[after + ver.len()..].starts_with("+k0s") {
            return Some(ver);
        }
        start += pos + 1;
    }
    None
}

/// The comparable end state of a cluster, built from what kubectl returned.
/// Pure so the JSON shape is fixed by tests; `cluster::fingerprint` fetches.
pub struct FingerprintInputs<'a> {
    pub nodes: &'a Value,
    /// vm name → hypervisor, for VMs that currently exist.
    pub placement: &'a BTreeMap<String, String>,
    /// (namespace, kind, payload) for each workload list fetched.
    pub workloads: &'a [(&'a str, &'a str, Value)],
    pub kustomizations: Option<&'a Value>,
    pub ocirepositories: Option<&'a Value>,
    pub pinned_image_sha256: &'a str,
}

pub fn build_fingerprint(i: &FingerprintInputs) -> Value {
    let mut nodes = serde_json::Map::new();
    for node in items(i.nodes) {
        let name = or_none(s(node, "/metadata/name"));
        let ready = node
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .is_some_and(|cs| {
                cs.iter().any(|c| {
                    c.get("type").and_then(Value::as_str) == Some("Ready")
                        && c.get("status").and_then(Value::as_str) == Some("True")
                })
            });
        let internal_ip = node
            .pointer("/status/addresses")
            .and_then(Value::as_array)
            .and_then(|a| {
                a.iter()
                    .find(|x| x.get("type").and_then(Value::as_str) == Some("InternalIP"))
                    .and_then(|x| x.get("address").cloned())
            })
            .unwrap_or(Value::Null);
        let mut roles: Vec<String> = node
            .pointer("/metadata/labels")
            .and_then(Value::as_object)
            .map(|l| {
                l.keys()
                    .filter_map(|k| k.strip_prefix("node-role.kubernetes.io/"))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        roles.sort();
        nodes.insert(
            name,
            serde_json::json!({
                "ready": ready,
                "kubelet_version": node.pointer("/status/nodeInfo/kubeletVersion").cloned().unwrap_or(Value::Null),
                "os_image": node.pointer("/status/nodeInfo/osImage").cloned().unwrap_or(Value::Null),
                "internal_ip": internal_ip,
                "roles": roles,
            }),
        );
    }
    let mut fp = serde_json::Map::new();
    fp.insert("nodes".into(), Value::Object(nodes));
    fp.insert(
        "placement".into(),
        Value::Object(
            i.placement
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
        ),
    );
    let mut workloads = serde_json::Map::new();
    for (namespace, kind, payload) in i.workloads {
        for item in items(payload) {
            let name = s(item, "/metadata/name").unwrap_or("");
            let field = if *kind == "daemonsets" {
                "/status/numberReady"
            } else {
                "/status/readyReplicas"
            };
            workloads.insert(
                format!("{namespace}/{kind}/{name}"),
                item.pointer(field).cloned().unwrap_or(Value::Null),
            );
        }
    }
    fp.insert("workloads".into(), Value::Object(workloads));
    if let Some(k) = i.kustomizations {
        let mut names: Vec<String> = items(k)
            .iter()
            .map(|x| {
                format!(
                    "{}/{}",
                    or_none(s(x, "/metadata/namespace")),
                    or_none(s(x, "/metadata/name"))
                )
            })
            .collect();
        names.sort();
        fp.insert("flux_kustomizations".into(), serde_json::json!(names));
    }
    fp.insert(
        "_pinned_image_sha256".into(),
        Value::String(i.pinned_image_sha256.into()),
    );
    if let Some(o) = i.ocirepositories {
        let mut names: Vec<String> = items(o)
            .iter()
            .map(|x| {
                format!(
                    "{}/{}={}",
                    or_none(s(x, "/metadata/namespace")),
                    or_none(s(x, "/metadata/name")),
                    or_none(s(x, "/spec/url"))
                )
            })
            .collect();
        names.sort();
        fp.insert("flux_sources".into(), serde_json::json!(names));
    }
    Value::Object(fp)
}
