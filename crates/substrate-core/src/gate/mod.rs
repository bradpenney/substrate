//! The destroy-and-rebuild gate's VERIFYING half, ported from `gate.py`.
//!
//! THE REQUIREMENT this exists to satisfy (Brad, verbatim): "prove that I can
//! fully destroy/rebuild the cluster ... it gets fully wiped, yet comes back
//! with all components live and ready." So the gate answers one question with
//! an exit code: does this cluster genuinely rebuild from nothing, or does it
//! merely happen to be working?
//!
//! WHY THIS IS A SEPARATE MODULE FROM `provision`. The provisioner's job is to
//! build a cluster. It must not be the thing that decides whether its own
//! output is healthy — a provisioner with a wrong idea of "healthy" would
//! happily validate itself. The tool being proven and the tool doing the
//! proving are different code; they share only primitives (`node_ssh`, the
//! readiness poll, the fleet shape).
//!
//! Every decision is a pure function in [`logic`]; this module fetches state,
//! prints, and polls. The split is what lets a corpus generated from the
//! Python prove the two gates agree before the Python is archived.

pub mod logic;

use crate::config::SiteConfig;
use crate::exec::{Host, Output, run};
use crate::provision::{self, Fleet, Vm};
use anyhow::{Context, Result};
use logic::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Everything the checks need to reach the cluster.
pub struct Gate<'a> {
    pub cfg: &'a SiteConfig,
    pub fleet: Fleet,
    bootstrap_ip: String,
}

fn local_kubectl(args: &[&str]) -> Output {
    match std::process::Command::new("kubectl").args(args).output() {
        Ok(o) => Output {
            status: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => Output {
            status: -1,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn sleep(secs: u64) {
    std::thread::sleep(Duration::from_secs(secs));
}

fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn parse(out: &Output) -> Option<Value> {
    if !out.ok() {
        return None;
    }
    serde_json::from_str(&out.stdout).ok()
}

fn ready_condition(v: &Value) -> Option<&Value> {
    v.pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
        })
}

impl<'a> Gate<'a> {
    pub fn new(cfg: &'a SiteConfig) -> Result<Self> {
        let fleet = Fleet::from_config(cfg);
        let bootstrap_ip = fleet.find_bootstrap()?.1.static_ip.clone();
        Ok(Self {
            cfg,
            fleet,
            bootstrap_ip,
        })
    }

    /// kubectl against the cluster via the bootstrap node's `k0s kubectl`.
    ///
    /// Deliberately not a local kubectl: after a wipe there is no local
    /// kubeconfig, and a stale one points at a node that no longer exists —
    /// depending on one would make the gate fail for reasons unrelated to
    /// whether the cluster rebuilt correctly.
    pub fn kubectl(&self, args: &str) -> Output {
        provision::node_ssh(
            &self.cfg.admin_user,
            &self.bootstrap_ip,
            10,
            &format!("sudo k0s kubectl {args}"),
        )
        .unwrap_or_else(|e| Output {
            status: -1,
            stdout: String::new(),
            stderr: e.to_string(),
        })
    }

    fn all_vms(&self) -> Vec<(&Host, &Vm)> {
        self.fleet.all_vms().collect()
    }

    fn expected_nodes(&self) -> Vec<String> {
        self.fleet.all_vms().map(|(_, v)| v.name.clone()).collect()
    }

    /// Node → hypervisor from the fleet definition, never parsed out of
    /// node names: the `s1-`/`s2-` prefixes are a convention, not a guarantee.
    pub fn node_to_hypervisor(&self) -> BTreeMap<String, String> {
        self.fleet
            .all_vms()
            .map(|(h, v)| (v.name.clone(), h.name.clone()))
            .collect()
    }

    /// Hosts site.yml declares may not come back on their own.
    pub fn failure_prone_hypervisors(&self) -> BTreeSet<String> {
        self.cfg
            .hypervisors
            .iter()
            .filter(|(_, hv)| hv.failure_prone)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Names of nodes the cluster currently considers Ready.
    pub fn healthy_nodes(&self) -> Vec<String> {
        provision::node_ready_states(&self.cfg.admin_user, &self.bootstrap_ip)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, ready)| *ready)
            .map(|(n, _)| n)
            .collect()
    }

    // ------------------------------------------------------------ verify

    /// Assert the documented gate criteria. True only if all pass. Every
    /// check runs even if an earlier one fails, so one run reports the full
    /// picture rather than making the operator fix-and-rerun.
    pub fn verify(&self) -> bool {
        println!("=== verifying cluster health ===");
        let results: Vec<(&str, bool)> = vec![
            ("nodes Ready", self.check_nodes()),
            ("system pods healthy", self.check_system_pods()),
            ("cluster DNS resolving", self.check_dns()),
            ("flux reconciling", self.check_flux()),
            ("api-server -> pod tunnel", self.check_apiserver_tunnel()),
            ("required secrets present", self.check_required_secrets()),
            (
                "platform spread across fleet",
                self.check_pod_distribution(),
            ),
            ("critical workloads spread", self.check_critical_pairs()),
            ("hypervisor labels match site.yml", self.check_node_labels()),
            (
                "fleet survives losing a hypervisor",
                self.check_fleet_survivability(),
            ),
        ];
        println!("\n=== gate results ===");
        for (name, ok) in &results {
            println!("  [{}] {name}", if *ok { "PASS" } else { "FAIL" });
        }
        results.iter().all(|(_, ok)| *ok)
    }

    /// Every node site.yml declares is registered and Ready — so a node that
    /// silently never joined is a failure, not a smaller healthy cluster.
    fn check_nodes(&self) -> bool {
        match provision::wait_for_nodes_ready(
            &self.cfg.admin_user,
            &self.bootstrap_ip,
            &self.expected_nodes(),
            provision::NODE_READY_TIMEOUT,
            provision::SSH_WAIT_INTERVAL,
        ) {
            Ok(()) => true,
            Err(e) => {
                println!("  node check failed: {e}");
                false
            }
        }
    }

    /// None when the API can't be reached or parsed — transient during a
    /// rebuild, not a failure. Callers keep polling.
    fn unhealthy_pods(&self) -> Option<Vec<String>> {
        let mut bad = Vec::new();
        for namespace in SYSTEM_NAMESPACES {
            let pods = parse(&self.kubectl(&format!("get pods -n {namespace} -o json")))?;
            let daemonsets =
                parse(&self.kubectl(&format!("get daemonsets -n {namespace} -o json")))?;
            bad.extend(unhealthy_in_namespace(namespace, &pods, &daemonsets));
        }
        Some(bad)
    }

    fn check_system_pods(&self) -> bool {
        println!("--- system pods ---");
        let deadline = Instant::now() + Duration::from_secs(PODS_READY_TIMEOUT);
        let mut last_report: Option<Vec<String>> = None;
        while Instant::now() < deadline {
            let unhealthy = self.unhealthy_pods();
            if let Some(u) = &unhealthy
                && u.is_empty()
            {
                println!("  all system pods Running and ready");
                return true;
            }
            if let Some(u) = unhealthy.filter(|u| !u.is_empty()) {
                let mut report = u;
                report.sort();
                if last_report.as_ref() != Some(&report) {
                    for line in &report {
                        println!("  waiting on: {line}");
                    }
                    last_report = Some(report);
                }
            }
            sleep(PODS_POLL_INTERVAL);
        }
        println!("  system pods did not settle within {PODS_READY_TIMEOUT}s");
        let mut still = self
            .unhealthy_pods()
            .unwrap_or_else(|| vec!["<could not query>".into()]);
        still.sort();
        for line in still {
            println!("    still unhealthy: {line}");
        }
        false
    }

    /// Resolve an in-cluster name from INSIDE a pod: the path real workloads
    /// use, so it exercises CoreDNS plus the CNI and kube-proxy together.
    ///
    /// Fire-and-forget, then assert on the pod's TERMINAL PHASE — never
    /// `run -i --rm`, which streams logs through konnectivity and produced a
    /// false failure on a cluster whose DNS was fine. nslookup exits non-zero
    /// on failure, so phase == Succeeded IS the assertion.
    fn check_dns(&self) -> bool {
        println!("--- cluster DNS ---");
        let pod = format!("gate-dns-{}", now_secs());
        let started = self.kubectl(&format!(
            "run {pod} --image=busybox:1.36 --restart=Never -- nslookup kubernetes.default.svc.cluster.local"
        ));
        if !started.ok() {
            println!(
                "  could not start the DNS test pod: {}",
                head(started.stderr.trim(), 200)
            );
            self.force_delete_pod(&pod);
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(DNS_TIMEOUT);
        let mut phase = String::new();
        while Instant::now() < deadline {
            phase = self
                .kubectl(&format!("get pod {pod} -o jsonpath={{.status.phase}}"))
                .stdout
                .trim()
                .to_string();
            if phase == "Succeeded" || phase == "Failed" {
                break;
            }
            sleep(3);
        }
        let resolved = phase == "Succeeded";
        if resolved {
            println!("  kubernetes.default.svc.cluster.local resolved");
        } else {
            // Best-effort evidence only — an unavailable log never becomes
            // the verdict.
            let logs = self.kubectl(&format!("logs {pod}"));
            let raw = if logs.stdout.is_empty() {
                &logs.stderr
            } else {
                &logs.stdout
            };
            let detail = head(raw.trim(), 400);
            let detail = if detail.is_empty() {
                "<no logs available>".to_string()
            } else {
                detail
            };
            let shown = if phase.is_empty() {
                "<timed out>"
            } else {
                &phase
            };
            println!("  DNS check pod ended in phase {shown}:\n    {detail}");
        }
        self.force_delete_pod(&pod);
        resolved
    }

    /// `--rm` doesn't clean up when the run times out or the pod never
    /// starts; the next gate run would trip over its own litter.
    fn force_delete_pod(&self, pod: &str) {
        self.kubectl(&format!(
            "delete pod {pod} --ignore-not-found --force --grace-period=0"
        ));
    }

    /// Flux is actually reconciling, not merely installed. Skipped (not
    /// failed) when Flux isn't installed: a platform assertion, not a
    /// substrate one.
    fn check_flux(&self) -> bool {
        println!("--- flux reconciliation ---");
        let result = self.kubectl("get kustomization -A -o json");
        if !result.ok() {
            println!("  Flux not installed — skipping (substrate-only cluster)");
            return true;
        }
        let Some(first) = parse(&result) else {
            println!("  could not parse Kustomization list");
            return false;
        };
        if first
            .get("items")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            println!("  Flux is installed but has NO Kustomizations — nothing is being reconciled");
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(PODS_READY_TIMEOUT);
        let mut bad: Vec<String> = Vec::new();
        while Instant::now() < deadline {
            let items: Vec<Value> = parse(&self.kubectl("get kustomization -A -o json"))
                .and_then(|v| v.get("items").and_then(Value::as_array).cloned())
                .unwrap_or_default();
            bad = items
                .iter()
                .filter_map(|k| {
                    let name = format!(
                        "{}/{}",
                        k.pointer("/metadata/namespace")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                        k.pointer("/metadata/name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                    );
                    let ready = ready_condition(k);
                    if ready.and_then(|c| c.get("status")).and_then(Value::as_str) == Some("True") {
                        None
                    } else {
                        let msg = ready
                            .and_then(|c| c.get("message"))
                            .and_then(Value::as_str)
                            .unwrap_or("no Ready condition");
                        Some(format!("{name}: {}", head(msg, 80)))
                    }
                })
                .collect();
            if bad.is_empty() && !items.is_empty() {
                let revs: BTreeSet<&str> = items
                    .iter()
                    .map(|k| {
                        k.pointer("/status/lastAppliedRevision")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                    })
                    .collect();
                println!("  {} Kustomizations reconciled", items.len());
                for r in revs {
                    println!("    revision {r}");
                }
                return true;
            }
            sleep(PODS_POLL_INTERVAL);
        }
        println!("  Kustomizations did not reconcile within {PODS_READY_TIMEOUT}s:");
        for line in bad {
            println!("    {line}");
        }
        false
    }

    /// Every API server must reach the pod network — not just one (ADR-044).
    /// The VIP round-robins, so each controller is addressed DIRECTLY. Reading
    /// a pod's logs is the cheapest operation that crosses the tunnel.
    fn check_apiserver_tunnel(&self) -> bool {
        println!("--- api-server -> pod tunnel (every controller) ---");
        let mut pod = local_kubectl(&[
            "-n",
            "kube-system",
            "get",
            "pods",
            "-l",
            "k8s-app=kube-dns",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ])
        .stdout
        .trim()
        .to_string();
        if pod.is_empty() {
            pod = local_kubectl(&[
                "-n",
                "kube-system",
                "get",
                "pods",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            ])
            .stdout
            .trim()
            .to_string();
        }
        if pod.is_empty() {
            println!("  no kube-system pod to probe with");
            return false;
        }
        let mut ok = true;
        let mut vms = self.all_vms();
        vms.sort_by(|a, b| a.1.static_ip.cmp(&b.1.static_ip));
        for (_, vm) in vms {
            let server = format!("--server=https://{}:6443", vm.static_ip);
            let r = local_kubectl(&[
                &server,
                "-n",
                "kube-system",
                "logs",
                &pod,
                "--tail=1",
                "--limit-bytes=256",
            ]);
            if r.ok() {
                println!("  [ok  ] {:<8} {}", vm.name, vm.static_ip);
            } else {
                ok = false;
                let hint = r
                    .stderr
                    .trim()
                    .lines()
                    .last()
                    .map_or("unknown error".to_string(), |l| head(l, 90));
                println!("  [FAIL] {:<8} {}  {hint}", vm.name, vm.static_ip);
                if r.stderr.contains("No agent available") {
                    println!("         konnectivity agents are not registered with this");
                    println!("         controller — the ADR-044 failure. Check that the");
                    println!("         load balancer DISTRIBUTES across all controllers.");
                }
            }
        }
        ok
    }

    /// The credentials the platform depends on are being DELIVERED. Reads the
    /// ExternalSecret, not the Secret (ADR-071): a Secret is a snapshot that
    /// stays readable for weeks after the pipeline producing it has broken;
    /// `Ready=True` means the operator authenticated and refreshed it, which
    /// is what the NEXT rebuild needs.
    fn check_required_secrets(&self) -> bool {
        println!("--- required credentials ---");
        let mut ok = true;
        for (ns, name, why) in REQUIRED_EXTERNAL_SECRETS {
            let r = local_kubectl(&["-n", ns, "get", "externalsecret", name, "-o", "json"]);
            if !r.ok() {
                ok = false;
                println!("  [MISSING] {ns}/{name} — no ExternalSecret");
                println!("            {why}");
                continue;
            }
            let status = serde_json::from_str::<Value>(&r.stdout)
                .ok()
                .and_then(|v| v.get("status").cloned())
                .unwrap_or(Value::Null);
            let ready = status
                .get("conditions")
                .and_then(Value::as_array)
                .and_then(|cs| {
                    cs.iter()
                        .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
                        .cloned()
                });
            let is_ready = ready
                .as_ref()
                .and_then(|c| c.get("status"))
                .and_then(Value::as_str)
                == Some("True");
            if !is_ready {
                ok = false;
                let reason = ready
                    .as_ref()
                    .and_then(|c| c.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or("no Ready condition");
                println!("  [STALE  ] {ns}/{name} is not syncing ({reason})");
                println!("            {why}");
                println!("            The Secret may still exist and still look fine.");
            } else {
                let when = status
                    .get("refreshTime")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                println!("  [ok     ] {ns}/{name}  (last refreshed {when})");
            }
        }
        if !ok {
            println!("  Delivered by External Secrets from Infisical (ADR-055).");
            println!("  A failure here means the next rebuild produces a broken cluster.");
        }
        ok
    }

    fn pods_and_nodes(&self, what: &str) -> Option<Value> {
        let r = self.kubectl(&format!("get {what} -o json"));
        if !r.ok() {
            println!(
                "  could not list {}",
                if what.starts_with("pods") {
                    "pods"
                } else {
                    "nodes"
                }
            );
            return None;
        }
        match serde_json::from_str(&r.stdout) {
            Ok(v) => Some(v),
            Err(_) => {
                println!(
                    "  could not parse the {} list",
                    if what.starts_with("pods") {
                        "pod"
                    } else {
                        "node"
                    }
                );
                None
            }
        }
    }

    /// The platform is spread across the fleet, not piled on one host
    /// (ADR-097): five rebuild samples passed every readiness check while 41
    /// of 43 pods sat on 4.5 GiB and 34.4 GiB stood idle.
    fn check_pod_distribution(&self) -> bool {
        println!("--- pod distribution ---");
        let Some(payload) = self.pods_and_nodes("pods -A") else {
            return false;
        };
        let counts = schedulable_pods_by_node(&payload);
        let node_hypervisor = self.node_to_hypervisor();
        let ready = self.healthy_nodes();
        let total: i64 = counts.iter().map(|(_, c)| c).sum::<i64>().max(1);
        let prone = self.failure_prone_hypervisors();
        let all: BTreeSet<&String> = counts.iter().map(|(n, _)| n).chain(ready.iter()).collect();
        for node in all {
            let host = node_hypervisor.get(node).map_or("?", String::as_str);
            let count = counts
                .iter()
                .find(|(n, _)| n == node)
                .map_or(0, |(_, c)| *c);
            let flag = if prone.contains(host) {
                " (failure-prone)"
            } else {
                ""
            };
            println!(
                "  {node:<10} {host:<8} {count:>3} pods  ({}){flag}",
                pct0(count as f64 / total as f64)
            );
        }
        let failures = concentration_failures(&counts, &node_hypervisor, &ready, &prone);
        if failures.is_empty() {
            println!("  platform is spread across the fleet");
            return true;
        }
        for line in failures {
            println!("  {line}");
        }
        println!(
            "  ./rebalance.sh (needs a jit-admin grant) fixes the ADR-097 fault: a\n  \
             rebuild reconciling the whole platform onto the bootstrap node, where\n  \
             the pods CAN move and simply have not. It recurs on every rebuild.\n  \
             ⚠️ It does NOT fix a capacity shortfall. If 'fleet survives losing a\n  \
             hypervisor' is also failing, read that first — moving pods cannot\n  \
             create memory on the survivor, and rebalancing into a host that\n  \
             cannot hold the workload just relocates the concentration (ADR-170)."
        );
        false
    }

    /// Named critical workloads span both hypervisors. Aggregate spread
    /// passed on 2026-09-07 while both BIND primaries ran on one node.
    fn check_critical_pairs(&self) -> bool {
        println!("--- critical workload spread ---");
        let Some(payload) = self.pods_and_nodes("pods -A") else {
            return false;
        };
        let node_hypervisor = self.node_to_hypervisor();
        for spec in CRITICAL_PAIRS {
            let pods = pods_matching(&payload, spec.namespace, spec.selector);
            let mut placed: Vec<String> = pods
                .iter()
                .map(|p| {
                    let node = p
                        .pointer("/spec/nodeName")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    format!(
                        "{} -> {}",
                        p.pointer("/metadata/name")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                        node_hypervisor.get(node).map_or("?", String::as_str)
                    )
                })
                .collect();
            placed.sort();
            println!("  {}:", spec.name);
            if placed.is_empty() {
                println!("    (no Running replicas found)");
            }
            for line in placed {
                println!("    {line}");
            }
        }
        let failures = critical_pair_failures(&payload, &node_hypervisor, CRITICAL_PAIRS);
        if failures.is_empty() {
            println!("  every critical workload spans both failure domains");
            return true;
        }
        for line in failures {
            println!("  {line}");
        }
        println!(
            "  a MutatingAdmissionPolicy imposes this at Pod admission (substrate_config,\n  \
             infrastructure-config/bindy-primary-spread.yaml). It acts at Pod CREATE\n  \
             only, so an already-running pair stays where it is until something\n  \
             recreates it — see ADR-139."
        );
        false
    }

    /// The cluster's topology labels match the fleet definition (ADR-144).
    fn check_node_labels(&self) -> bool {
        println!("--- hypervisor topology labels ---");
        let Some(payload) = self.pods_and_nodes("nodes") else {
            return false;
        };
        let node_hypervisor = self.node_to_hypervisor();
        let mut nodes: Vec<&Value> = payload
            .get("items")
            .and_then(Value::as_array)
            .map_or(vec![], |a| a.iter().collect());
        nodes.sort_by_key(|n| {
            n.pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
        });
        for node in nodes {
            let name = node
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let actual = node
                .pointer("/metadata/labels")
                .and_then(|l| l.get(HYPERVISOR_LABEL))
                .and_then(Value::as_str)
                .unwrap_or("-");
            println!("  {name:<10} {HYPERVISOR_LABEL}={actual}");
        }
        let failures = node_label_failures(&payload, &node_hypervisor, HYPERVISOR_LABEL);
        if failures.is_empty() {
            println!("  every node declares a failure domain matching site.yml");
            return true;
        }
        for line in failures {
            println!("  {line}");
        }
        println!(
            "  the label is rendered into the cloud-config by the substrate build\n  \
             (ADR-144), but kubelet applies --node-labels only when it CREATES\n  \
             the Node object — a node that merely rebooted needs:\n    \
             kubectl label node <node> {HYPERVISOR_LABEL}=<hypervisor>"
        );
        false
    }

    /// Could the survivors actually hold the workload if a hypervisor is
    /// lost? In MiB, not pod count (ADR-170).
    fn check_fleet_survivability(&self) -> bool {
        println!("--- fleet survivability ---");
        let pods_result = self.kubectl("get pods -A -o json");
        let nodes_result = self.kubectl("get nodes -o json");
        if !pods_result.ok() || !nodes_result.ok() {
            println!("  could not list pods or nodes");
            return false;
        }
        let (Ok(pods), Ok(nodes)) = (
            serde_json::from_str::<Value>(&pods_result.stdout),
            serde_json::from_str::<Value>(&nodes_result.stdout),
        ) else {
            println!("  could not parse the pod or node list");
            return false;
        };
        let allocatable: BTreeMap<String, i64> = nodes
            .get("items")
            .and_then(Value::as_array)
            .map_or(vec![], |a| a.iter().collect::<Vec<_>>())
            .into_iter()
            .map(|n| {
                (
                    n.pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    parse_quantity_mib(
                        n.pointer("/status/allocatable/memory")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                )
            })
            .collect();
        let node_hypervisor = self.node_to_hypervisor();
        let b = survivability_budget(&pods, &allocatable, &node_hypervisor);
        println!(
            "  reschedulable workload {:>6} MiB (DaemonSets excluded)",
            b.workload
        );
        for (host, room) in &b.room {
            let margin = room - b.workload;
            let verdict = if margin >= 0 {
                format!("ok, {margin} MiB spare")
            } else {
                format!("SHORT {} MiB", -margin)
            };
            println!("  lose {host:<8} survivors offer {room:>6} MiB — {verdict}");
        }
        let failures = survivability_failures(&pods, &allocatable, &node_hypervisor);
        if failures.is_empty() {
            println!("  the fleet survives losing either hypervisor");
            return true;
        }
        for line in failures {
            println!("  {line}");
        }
        println!(
            "  ⚠️ rebalance.sh CANNOT fix this — it moves pods, and this is a memory\n  \
             shortfall. See ADR-170: the options are more RAM on the smaller host,\n  \
             fewer workloads, or accepting the exposure deliberately."
        );
        false
    }

    // -------------------------------------------------------- fingerprint

    /// A comparable description of the cluster's end state: what must match
    /// between two rebuilds, deliberately EXCLUDING what legitimately differs
    /// (pod names, UIDs, CNI-assigned IPs, ages, resource versions).
    pub fn fingerprint(&self) -> Result<Value> {
        let nodes: Value = serde_json::from_str(&self.kubectl("get nodes -o json").stdout)
            .context("could not read the node list from the bootstrap node")?;
        // Which VM sits on which hypervisor — a cluster that came back with
        // nodes on the wrong hosts would still look healthy to kubectl.
        let placement: BTreeMap<String, String> = self
            .fleet
            .all_vms()
            .filter(|(h, v)| crate::libvirt::vm_exists(h, &crate::libvirt::Vm::new(&v.name)))
            .map(|(h, v)| (v.name.clone(), h.name.clone()))
            .collect();
        // Workload identity, not instance identity.
        let mut workloads: Vec<(&str, &str, Value)> = Vec::new();
        for namespace in SYSTEM_NAMESPACES {
            for kind in ["daemonsets", "deployments"] {
                if let Some(v) = parse(&self.kubectl(&format!("get {kind} -n {namespace} -o json")))
                {
                    workloads.push((namespace, kind, v));
                }
            }
        }
        // Platform state — the set of Kustomizations and the source URL, NOT
        // the applied revision: that is the artifact digest, which changes on
        // every push of the config repo.
        let kustomizations = parse(&self.kubectl("get kustomization -A -o json"));
        let ocirepositories = parse(&self.kubectl("get ocirepository -A -o json"));
        Ok(build_fingerprint(&FingerprintInputs {
            nodes: &nodes,
            placement: &placement,
            workloads: &workloads,
            kustomizations: kustomizations.as_ref(),
            ocirepositories: ocirepositories.as_ref(),
            pinned_image_sha256: &self.cfg.kairos.iso_sha256,
        }))
    }

    /// Record the current end state under `.fingerprints/<method>.json` so
    /// `compare` can put two rebuilds side by side long after both finished.
    pub fn save_fingerprint(&self, dir: &Path, method: &str) -> Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{method}.json"));
        std::fs::write(&path, fingerprint_json(&self.fingerprint()?))?;
        println!("fingerprint saved: {}", path.display());
        Ok(path)
    }

    // --------------------------------------------------------------- roll

    /// Block until etcd membership matches AND every API server's etcd is
    /// serving. Kubernetes health passes while etcd is mid-election; a roll
    /// that continues on that basis removes a second member from a cluster
    /// that has not absorbed the first removal — how the first unattended
    /// roll broke.
    fn wait_etcd_healthy(&self, expected: &[String], timeout: u64) -> bool {
        let want: BTreeSet<String> = expected.iter().cloned().collect();
        let deadline = Instant::now() + Duration::from_secs(timeout);
        let mut last = String::new();
        while Instant::now() < deadline {
            let members = provision::node_ssh(
                &self.cfg.admin_user,
                &self.bootstrap_ip,
                10,
                "sudo k0s etcd member-list",
            )
            .ok()
            .filter(Output::ok)
            .map_or_else(BTreeSet::new, |o| etcd_members_from(&o.stdout));
            if members == want {
                let unhealthy: Vec<&str> = self
                    .all_vms()
                    .into_iter()
                    .filter(|(_, vm)| {
                        let r = local_kubectl(&[
                            &format!("--server=https://{}:6443", vm.static_ip),
                            "get",
                            "--raw",
                            "/healthz/etcd",
                        ]);
                        !r.ok() || !r.stdout.to_lowercase().contains("ok")
                    })
                    .map(|(_, vm)| vm.name.as_str())
                    .collect();
                if unhealthy.is_empty() {
                    println!("    etcd healthy — {} members, all serving", members.len());
                    return true;
                }
                last = format!("etcd not serving on: {}", unhealthy.join(", "));
            } else {
                let missing: Vec<&String> = want.difference(&members).collect();
                let extra: Vec<&String> = members.difference(&want).collect();
                last = "membership ".to_string();
                if !missing.is_empty() {
                    last.push_str(&format!(
                        "missing {}",
                        missing
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !extra.is_empty() {
                    last.push_str(&format!(
                        " unexpected {}",
                        extra
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            sleep(10);
        }
        println!("    etcd did NOT become healthy within {timeout}s — {last}");
        false
    }

    /// Block until every Longhorn volume is healthy and nothing is
    /// rebuilding. No-op when Longhorn is not installed. Replacing the next
    /// node while replicas are rebuilding can drop a volume below replica
    /// quorum — on a two-replica volume that is data loss, not degradation.
    fn wait_longhorn_healthy(&self, timeout: u64) -> bool {
        if !local_kubectl(&["get", "crd", "volumes.longhorn.io"]).ok() {
            return true;
        }
        let deadline = Instant::now() + Duration::from_secs(timeout);
        let mut last = String::new();
        while Instant::now() < deadline {
            if let Some(v) = parse(&local_kubectl(&[
                "-n",
                "longhorn-system",
                "get",
                "volumes.longhorn.io",
                "-o",
                "json",
            ])) && let Some(items) = v.get("items").and_then(Value::as_array)
            {
                let bad: Vec<String> = items
                    .iter()
                    .filter_map(|vol| {
                        let name = vol
                            .pointer("/metadata/name")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let rob = vol
                            .pointer("/status/robustness")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_lowercase();
                        let state = vol
                            .pointer("/status/state")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_lowercase();
                        // A detached volume has no replicas to be healthy about.
                        (rob != "healthy" && state != "detached").then(|| format!("{name}={rob}"))
                    })
                    .collect();
                if bad.is_empty() {
                    println!(
                        "    longhorn healthy — {} volume(s), no rebuilds in flight",
                        items.len()
                    );
                    return true;
                }
                last = bad.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
            }
            sleep(15);
        }
        println!("    longhorn volumes did NOT become healthy within {timeout}s — {last}");
        false
    }

    fn node_kubelet_version(&self, name: &str) -> Option<String> {
        let r = self.kubectl(&format!(
            "get node {name} -o jsonpath={{.status.nodeInfo.kubeletVersion}}"
        ));
        r.ok().then(|| r.stdout.trim().to_string())
    }

    /// Replace nodes ONE AT A TIME onto the currently-pinned Kairos image —
    /// the node patching story, since the node OS is immutable and the only
    /// way to patch one is to replace it. Strictly one at a time: 5 nodes
    /// tolerate two down, but that leaves zero margin for a surprise inside
    /// the window. Cluster health is re-verified between every node.
    pub fn roll(&self, target: Option<&str>, ssh_key: &str) -> bool {
        let targets: Vec<(&Host, &Vm)> = self
            .all_vms()
            .into_iter()
            .filter(|(_, v)| target.is_none_or(|t| t == v.name))
            .collect();
        if targets.is_empty() {
            eprintln!("no such node: {}", target.unwrap_or(""));
            return false;
        }
        println!(
            "=== rolling {} node(s) onto image {}... ===",
            targets.len(),
            head(&self.cfg.kairos.iso_sha256, 12)
        );
        println!("    one at a time; cluster health re-verified between each\n");
        let expected = self.expected_nodes();
        let admin = &self.cfg.admin_user;

        for (host, vm) in targets {
            let ready = self.healthy_nodes();
            let unhealthy: Vec<&String> = expected.iter().filter(|n| !ready.contains(n)).collect();
            if !unhealthy.is_empty() {
                println!(
                    "REFUSING to roll {}: cluster is not fully healthy (not Ready: [{}])",
                    vm.name,
                    unhealthy
                        .iter()
                        .map(|n| py_repr_str(n))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!(
                    "  Rolling into a degraded cluster is how a maintenance window becomes an outage."
                );
                return false;
            }
            // A join token must be minted from something STILL RUNNING —
            // never from the node being replaced.
            let Some((donor_host, donor_vm)) = self
                .all_vms()
                .into_iter()
                .find(|(_, v)| v.name != vm.name && ready.contains(&v.name))
            else {
                println!(
                    "REFUSING to roll {}: no other healthy node to mint a token from",
                    vm.name
                );
                return false;
            };
            println!(
                "--- {} (on {}) --- token donor: {}",
                vm.name, host.name, donor_vm.name
            );

            // FETCH THE PINNED IMAGE FIRST. Without this the roll rebuilds
            // from whatever ISO is already on the hypervisor and reports the
            // fleet as updated when it is not — which happened (v4.2.0 roll
            // came back on v4.1.2). Checksum-gated, so a no-op when correct.
            if let Err(e) = provision::ensure_kairos_iso(host, self.cfg) {
                println!(
                    "ROLL HALTED: could not fetch the pinned image on {}: {e}",
                    host.name
                );
                return false;
            }
            provision::destroy_and_undefine(host, vm);
            // A destroyed node's etcd membership outlives it; the ghost costs
            // quorum on the NEXT replacement.
            provision::etcd_prune(admin, donor_host, &donor_vm.static_ip, vm);
            let iso = format!(
                "{}/{}-cloudinit.iso",
                self.cfg.libvirt.iso_pool_path, vm.name
            );
            let _ = run(host, &["rm", "-f", &iso], None);
            let _ = run(
                &Host::local("local"),
                &["ssh-keygen", "-R", &vm.static_ip],
                None,
            );

            let token = match provision::generate_join_token(
                admin,
                donor_host,
                donor_vm,
                &self.cfg.k0s.token_expiry,
            ) {
                Ok(t) => t,
                Err(e) => {
                    println!(
                        "ROLL HALTED: could not mint a join token from {}: {e}",
                        donor_vm.name
                    );
                    return false;
                }
            };
            if let Err(e) = provision::create_vm(
                host,
                vm,
                self.cfg,
                Some(&token),
                ssh_key,
                admin,
                Some((donor_host, &donor_vm.static_ip)),
            ) {
                println!("ROLL HALTED: {} did not come back: {e}", vm.name);
                return false;
            }

            println!(
                "    waiting for {} to rejoin and the cluster to settle...",
                vm.name
            );
            if let Err(e) = provision::wait_for_nodes_ready(
                admin,
                &self.bootstrap_ip,
                &expected,
                provision::NODE_READY_TIMEOUT,
                provision::SSH_WAIT_INTERVAL,
            ) {
                println!("ROLL HALTED: {e}");
                return false;
            }
            if !self.check_system_pods() {
                println!(
                    "ROLL HALTED: system pods did not settle after replacing {}",
                    vm.name
                );
                return false;
            }
            if !self.wait_etcd_healthy(&expected, 300) {
                println!(
                    "ROLL HALTED: etcd did not return to health after replacing {}",
                    vm.name
                );
                println!("  Continuing would remove a second member from a cluster that has");
                println!("  not absorbed the first removal — how the first unattended roll broke.");
                return false;
            }
            if !self.wait_longhorn_healthy(900) {
                println!(
                    "ROLL HALTED: Longhorn replicas still rebuilding after {}",
                    vm.name
                );
                println!("  Replacing the next node now can drop a volume below replica");
                println!("  quorum. That is data loss, not degradation.");
                return false;
            }
            // ASSERT THE OUTCOME. "Healthy" is not "updated".
            if let Some(want) = expected_k0s_version(&self.cfg.kairos.iso_url) {
                let got = self.node_kubelet_version(&vm.name);
                if let Some(got) = got.as_deref().filter(|g| !g.is_empty()) {
                    if !got.contains(&want) {
                        println!(
                            "ROLL HALTED: {} came back on kubelet {got}, but the pinned image carries k0s {want}.",
                            vm.name
                        );
                        println!(
                            "  The node was rebuilt from a STALE image — the fleet is NOT patched. Do not continue."
                        );
                        return false;
                    }
                    println!("    {} verified on k0s {got}", vm.name);
                } else {
                    println!(
                        "    {} verified on k0s {}",
                        vm.name,
                        got.unwrap_or_default()
                    );
                }
            }
            println!("    {} replaced and healthy\n", vm.name);
        }
        println!("=== roll complete — every node rebuilt on the pinned image ===");
        let ips: Vec<String> = self
            .fleet
            .all_vms()
            .map(|(_, v)| v.static_ip.clone())
            .collect();
        if let Err(e) = provision::refresh_client_access(admin, &self.bootstrap_ip, &ips) {
            println!("  (client access refresh failed: {e})");
        }
        true
    }
}

/// Exactly `json.dumps(fp, indent=2, sort_keys=True) + "\n"`: serde_json's
/// Map is a BTreeMap, so keys are sorted, and its pretty printer uses the
/// same two-space layout.
pub fn fingerprint_json(fp: &Value) -> String {
    let mut s = serde_json::to_string_pretty(fp).unwrap_or_default();
    s.push('\n');
    s
}

/// Print every difference between two end states; true when they match.
pub fn compare_fingerprints(a: &Value, b: &Value, label_a: &str, label_b: &str) -> bool {
    let problems = fingerprint_differences(a, b, label_a, label_b);
    if !problems.is_empty() {
        println!("\n=== END STATES DIFFER between {label_a} and {label_b} ===");
        println!("{}", problems.join("\n"));
        return false;
    }
    println!("\n=== end states IDENTICAL between {label_a} and {label_b} ===");
    true
}

/// Compare two saved fingerprints. Refuses across different pinned images: a
/// version bump changes kubelet_version legitimately and would otherwise look
/// like the two rebuilds disagreeing.
pub fn compare_saved(dir: &Path, a: &str, b: &str) -> bool {
    let pa = dir.join(format!("{a}.json"));
    let pb = dir.join(format!("{b}.json"));
    let missing: Vec<String> = [&pa, &pb]
        .iter()
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !missing.is_empty() {
        eprintln!("missing fingerprint(s): {}", missing.join(", "));
        eprintln!("run: substrate fingerprint --save <name>   (after each rebuild)");
        return false;
    }
    let load = |p: &Path| -> Option<Value> {
        serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
    };
    let (Some(mut fa), Some(mut fb)) = (load(&pa), load(&pb)) else {
        eprintln!("could not parse a saved fingerprint");
        return false;
    };
    let pin_a = fa
        .as_object_mut()
        .and_then(|o| o.remove("_pinned_image_sha256"));
    let pin_b = fb
        .as_object_mut()
        .and_then(|o| o.remove("_pinned_image_sha256"));
    if pin_a != pin_b {
        let show = |p: &Option<Value>| {
            p.as_ref()
                .and_then(Value::as_str)
                .map_or("<not recorded>".to_string(), str::to_string)
        };
        eprintln!(
            "REFUSING to compare: the fingerprints were captured against DIFFERENT pinned images."
        );
        eprintln!("  {a}: {}", show(&pin_a));
        eprintln!("  {b}: {}", show(&pin_b));
        eprintln!(
            "\nA version bump changes kubelet_version legitimately. Re-run both passes on the current pin, then compare."
        );
        return false;
    }
    compare_fingerprints(&fa, &fb, a, b)
}
