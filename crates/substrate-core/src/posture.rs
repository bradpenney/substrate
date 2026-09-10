//! Assert the cluster's security invariants still hold, and shout if they do not.
//!
//! WHY THIS EXISTS
//! Every control built through ADR-058..072 is PREVENTIVE. Not one of them
//! notices when it stops being true. Pod Security labels were silently stripped
//! for hours while both Flux Kustomizations reported Ready (ADR-063); the
//! privilege-expiry reaper failed open on a missing base image while
//! `kubectl get cronjob` looked healthy (ADR-065). In both cases the fix was
//! easy and the DISCOVERY was luck.
//!
//! This is the detective half. It re-asserts, from outside, the things the
//! preventive controls are supposed to guarantee.
//!
//! DESIGNED TO RUN READ-ONLY. Every check is a read, so this runs as the scoped
//! `brad` identity and never needs the break-glass certificate (ADR-071). A
//! monitor that requires cluster-admin is a monitor that will be run as root
//! forever.
//!
//! ── ON THE SHAPE OF THIS PORT ────────────────────────────────────────────────
//! Wave 1 of ADR-088, and the pilot precisely because it is read-only.
//!
//! **The checks take parsed JSON, not a cluster.** Every function here is pure:
//! it receives `serde_json::Value` and returns findings. That is what makes them
//! testable against fixtures without a live cluster, and it is the difference
//! between a port that can be PROVEN equivalent and one that can only be run and
//! hoped over.
//!
//! **It still shells out to `kubectl`, deliberately.** `kube-rs` is the eventual
//! destination and is already sanctioned (rustls, no C), but for the pilot the
//! contract that matters is *identical output to the Python*. Shelling out means
//! identical queries and identical credential resolution, so a differential test
//! compares the CHECKS rather than two different client libraries' ideas of what
//! a kubeconfig means. Swapping the transport is a later, separately provable
//! step.
//!
//! **The port REPRODUCES; it does not improve.** Several things below could be
//! written more idiomatically — the string formats especially. They are held
//! byte-identical to the Python on purpose: the differential harness compares
//! output text, and a "nicer" message is an unprovable port.

use serde_json::Value;

/// Namespaces exempt from the default-deny requirement, with the reason.
pub const NETPOL_EXEMPT: &[(&str, &str)] = &[("hello", "podinfo demo, pending removal from Git")];

/// Subjects legitimately holding cluster-admin. Anything else is an alert.
pub const EXPECTED_CLUSTER_ADMIN: &[&str] = &[
    "Group/system:masters", // the bootstrap certificate itself
    "ServiceAccount/kustomize-controller",
    "ServiceAccount/helm-controller", // binding remains; the SA is gone
    "ServiceAccount/flux-operator",
    "ServiceAccount/longhorn-support-bundle",
];

pub const EXPECTED_POLICIES: &[&str] = &["require-pss-labels", "workload-hygiene"];

/// What a check produced. Mirrors the Python's two module-level lists.
///
/// Kept as an accumulator passed to each check rather than globals, because a
/// global is what made the Python's `main()` need `global KUBECTL` and a
/// pylint disable. Same behaviour, no shared mutable state.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub notes: Vec<String>,
    pub failures: Vec<String>,
}

impl Report {
    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
    pub fn fail(&mut self, s: impl Into<String>) {
        self.failures.push(s.into());
    }
}

/// `items` of a list response, or an empty slice.
///
/// A missing or non-array `items` yields nothing rather than panicking: a check
/// that crashes must not hide the others, which is why the Python wraps every
/// call in try/except.
fn items(d: &Value) -> &[Value] {
    d.get("items").and_then(Value::as_array).map_or(&[], |v| v)
}

fn name_of(o: &Value) -> &str {
    o.pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Every namespace must declare a Pod Security enforcement level.
///
/// Asserts the LABEL exists, not which level it is: privileged is legitimate for
/// kube-system and k0s-autopilot. What is never legitimate is a namespace with
/// no enforcement at all, which is what a new namespace defaults to.
pub fn check_pod_security(namespaces: &Value, r: &mut Report) {
    let all = items(namespaces);
    let mut missing: Vec<&str> = all
        .iter()
        .filter(|n| {
            n.pointer("/metadata/labels/pod-security.kubernetes.io~1enforce")
                .is_none()
        })
        .map(name_of)
        .collect();
    if !missing.is_empty() {
        missing.sort_unstable();
        r.fail(format!(
            "namespaces with NO Pod Security enforcement: {}",
            missing.join(", ")
        ));
    } else {
        r.note(format!(
            "pod security: {}/{} namespaces enforced",
            all.len(),
            all.len()
        ));
    }
}

/// Every namespace should deny ingress and egress by default.
///
/// A policy only counts when it has an EMPTY podSelector (so it catches every
/// pod) and lists both directions. An ingress-only policy leaves egress wide
/// open, which is the half that matters for exfiltration.
pub fn check_default_deny(namespaces: &Value, policies: &Value, r: &mut Report) {
    let mut have: Vec<&str> = items(policies)
        .iter()
        .filter(|p| {
            let empty_selector = p
                .pointer("/spec/podSelector")
                .and_then(Value::as_object)
                .is_some_and(|m| m.is_empty());
            let types: Vec<&str> = p
                .pointer("/spec/policyTypes")
                .and_then(Value::as_array)
                .map_or(vec![], |a| a.iter().filter_map(Value::as_str).collect());
            empty_selector && types.contains(&"Ingress") && types.contains(&"Egress")
        })
        .filter_map(|p| p.pointer("/metadata/namespace").and_then(Value::as_str))
        .collect();
    have.sort_unstable();
    have.dedup();

    let mut gaps: Vec<&str> = items(namespaces)
        .iter()
        .map(name_of)
        .filter(|n| !have.contains(n) && !NETPOL_EXEMPT.iter().any(|(ex, _)| ex == n))
        .collect();
    if !gaps.is_empty() {
        gaps.sort_unstable();
        r.fail(format!(
            "namespaces with NO default-deny NetworkPolicy: {}",
            gaps.join(", ")
        ));
    } else {
        r.note(format!(
            "network policy: {} namespaces default-deny",
            have.len()
        ));
    }
}

/// cluster-admin must not grow new holders without someone noticing.
///
/// Compared against a recorded baseline. A subject that DISAPPEARED is a note
/// rather than a failure — it means the baseline is stale, not that the cluster
/// is unsafe.
pub fn check_cluster_admin(bindings: &Value, r: &mut Report) {
    let mut subs: Vec<String> = items(bindings)
        .iter()
        .filter(|b| b.pointer("/roleRef/name").and_then(Value::as_str) == Some("cluster-admin"))
        .flat_map(|b| {
            b.get("subjects")
                .and_then(Value::as_array)
                .map_or(vec![], |a| {
                    a.iter()
                        .map(|s| {
                            format!(
                                "{}/{}",
                                s.get("kind").and_then(Value::as_str).unwrap_or("null"),
                                s.get("name").and_then(Value::as_str).unwrap_or("null")
                            )
                        })
                        .collect()
                })
        })
        .collect();
    subs.sort();
    subs.dedup();

    let mut new: Vec<&String> = subs
        .iter()
        .filter(|s| !EXPECTED_CLUSTER_ADMIN.contains(&s.as_str()))
        .collect();
    if !new.is_empty() {
        new.sort();
        let joined: Vec<&str> = new.iter().map(|s| s.as_str()).collect();
        r.fail(format!(
            "UNEXPECTED cluster-admin subjects: {}",
            joined.join(", ")
        ));
    }
    let mut gone: Vec<&str> = EXPECTED_CLUSTER_ADMIN
        .iter()
        .copied()
        .filter(|e| !subs.iter().any(|s| s == e))
        .collect();
    if !gone.is_empty() {
        gone.sort_unstable();
        r.note(format!(
            "cluster-admin subjects removed since baseline: {}",
            gone.join(", ")
        ));
    }
    if new.is_empty() {
        r.note(format!(
            "cluster-admin: {} subjects, all expected",
            subs.len()
        ));
    }
}

/// The admission policies must still exist AND still be enforcing.
///
/// A binding flipped from Deny to Warn is invisible in `kubectl get` output and
/// silently turns a guardrail into a log line (ADR-068).
pub fn check_admission_policies(policies: &Value, bindings: &Value, r: &mut Report) {
    let have: Vec<&str> = items(policies).iter().map(name_of).collect();
    let mut gone: Vec<&str> = EXPECTED_POLICIES
        .iter()
        .copied()
        .filter(|e| !have.contains(e))
        .collect();
    if !gone.is_empty() {
        gone.sort_unstable();
        r.fail(format!("admission policies MISSING: {}", gone.join(", ")));
    }
    let mut denying: Vec<&str> = items(bindings)
        .iter()
        .filter(|b| {
            b.pointer("/spec/validationActions")
                .and_then(Value::as_array)
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("Deny")))
        })
        .filter_map(|b| b.pointer("/spec/policyName").and_then(Value::as_str))
        .collect();
    denying.sort_unstable();
    denying.dedup();

    if denying.is_empty() {
        r.fail(
            "no admission policy binding is set to Deny -- \
             every guardrail has become advisory",
        );
    } else if gone.is_empty() {
        r.note(format!(
            "admission: {} policies, {} enforcing Deny",
            have.len(),
            denying.len()
        ));
    }
}

/// Flux states that are NORMAL operation rather than a fault.
///
/// A Kustomization that is merely reconciling was once reported as broken,
/// which turned every deploy into a false alarm — and an alert that fires on
/// normal operation is one people learn to ignore.
const PROGRESSING: &[&str] = &[
    "Progressing",
    "ProgressingWithRetry",
    "DependencyNotReady",
    "ReconciliationSucceeded",
    "Unknown",
];

/// Every Flux Kustomization must be Ready, or legitimately mid-reconcile.
///
/// PROGRESSING states are tolerated deliberately (see the constant above). A
/// missing Ready condition is NOT tolerated: absent is not the same as healthy,
/// and treating it as healthy is how a Kustomization that never started looks
/// fine.
pub fn check_flux(kustomizations: &Value, r: &mut Report) {
    let all = items(kustomizations);
    let mut bad: Vec<String> = Vec::new();
    for k in all {
        let name = name_of(k);
        let ready = k
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .and_then(|cs| {
                cs.iter()
                    .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
            });
        match ready {
            None => bad.push(format!("{name} (no Ready condition)")),
            Some(c) => {
                let status = c.get("status").and_then(Value::as_str).unwrap_or("");
                if status != "True" {
                    let reason = c.get("reason").and_then(Value::as_str).unwrap_or("");
                    if PROGRESSING.contains(&reason) || status == "Unknown" {
                        r.note(format!("flux: {name} reconciling ({reason})"));
                    } else {
                        bad.push(format!("{name} ({reason})"));
                    }
                }
            }
        }
    }
    if !bad.is_empty() {
        r.fail(format!("Flux Kustomizations not Ready: {}", bad.join(", ")));
    } else {
        r.note(format!("flux: {} kustomizations reconciling", all.len()));
    }
}

/// Every ExternalSecret must still be syncing.
///
/// A secret that stopped syncing keeps working until whatever it holds is
/// rotated, so the failure is invisible right up until it is urgent.
pub fn check_credentials(secrets: &Value, r: &mut Report) {
    let all = items(secrets);
    let stale: Vec<String> = all
        .iter()
        .filter(|e| {
            !e.pointer("/status/conditions")
                .and_then(Value::as_array)
                .is_some_and(|cs| {
                    cs.iter().any(|c| {
                        c.get("type").and_then(Value::as_str) == Some("Ready")
                            && c.get("status").and_then(Value::as_str) == Some("True")
                    })
                })
        })
        .map(|e| {
            format!(
                "{}/{}",
                e.pointer("/metadata/namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                name_of(e)
            )
        })
        .collect();
    if !stale.is_empty() {
        r.fail(format!(
            "ExternalSecrets not syncing (the Secret may still look fine): {}",
            stale.join(", ")
        ));
    } else {
        r.note(format!(
            "credentials: {} external secrets syncing",
            all.len()
        ));
    }
}

/// How long past expiry a grant may linger before it counts as a failure.
///
/// The reaper is a CronJob, so there is always some lag between the moment a
/// grant expires and the moment it is removed. Zero tolerance here would fire
/// on that ordinary gap.
const REAPER_GRACE_SECS: i64 = -300;

/// A JIT grant left outstanding means the reaper is not working.
///
/// The whole value of the time-boxed grant is that it expires on its own. A
/// binding with no expiry annotation is standing cluster-admin wearing the name
/// of a temporary one.
///
/// `binding` is None when the ClusterRoleBinding does not exist — which is the
/// healthy, ordinary case, and the reason this check cannot use the shared
/// query helper: kubectl exits non-zero for "not found", and that is a note,
/// not a failure.
pub fn check_no_standing_grant(binding: Option<&Value>, now_unix: i64, r: &mut Report) {
    let Some(b) = binding else {
        r.note("jit grant: none outstanding");
        return;
    };
    let exp = b
        .pointer("/metadata/annotations/jit.bradpenney.io~1expires-at")
        .and_then(Value::as_str);
    let Some(exp) = exp.filter(|s| !s.is_empty()) else {
        r.fail("a jit-platform-admin grant exists with NO expiry annotation");
        return;
    };
    let parsed = time::OffsetDateTime::parse(exp, &time::format_description::well_known::Rfc3339);
    let Ok(end) = parsed else {
        // The Python reaches this state as an unhandled exception caught by
        // main()'s wrapper, so it also reports a failure — with a different
        // message. Both refuse to call an unparseable expiry healthy, which is
        // the property that matters.
        r.fail(format!(
            "a jit-platform-admin grant has an unparseable expiry annotation: {exp}"
        ));
        return;
    };
    let left = end.unix_timestamp() - now_unix;
    if left < REAPER_GRACE_SECS {
        r.fail(format!(
            "jit grant EXPIRED at {exp} and is still present -- the reaper is not running"
        ));
    } else {
        r.note(format!("jit grant: outstanding, expires {exp}"));
    }
}

/// Host units whose failure means something stopped protecting the cluster.
///
/// Not an inventory of every timer — only the ones whose SILENCE is dangerous.
pub const WATCHED_UNITS: &[&str] = &[
    "hypervisor-update.service",
    "nextcloud-backup.service",
    "ddns-cloudflare.service",
    "homelab-update.service",
    // These three have no OnFailure= of their own, so this is their ONLY
    // coverage. Until 2026-08-28 they had neither, and auto-roll had already
    // failed unnoticed on Aug 26 ("Could not resolve hostname github.com") --
    // the unit that rolls the fleet onto patched images, silently not running.
    "auto-roll.service",
    "gcal-sync.service",
    "nextcloud-cron.service",
    // The upgrade nag. Its failure mode is invisible by construction: if it
    // stops running, the symptom is the ABSENCE of a reminder, so nothing else
    // would ever notice that platform upgrades were piling up unreviewed.
    "component-nag.service",
    // NOT posture-check.service itself. Watching yourself deadlocks: one failure
    // marks the unit failed, the next run then fails BECAUSE it is failed, and it
    // can never clear -- the unit only leaves the failed state by succeeding.
    // Caught by running it while it happened to be in that state.
];

/// What systemd reported, gathered before any judgement is made about it.
///
/// Separated from the check for the same reason the kubectl checks take parsed
/// JSON: the decision logic is then a pure function that fixtures can exercise,
/// including the states a healthy host never reaches.
#[derive(Debug, Default)]
pub struct SystemdState {
    /// `systemctl is-system-running` — "running", "degraded", ...
    pub system_status: String,
    /// Watched units that report `failed`, with their ExecMainExitTimestamp.
    pub failed_watched: Vec<(String, String)>,
    /// Every unit systemd currently lists as failed, watched or not.
    pub all_failed: Vec<String>,
}

/// Catch host-side automation that has quietly stopped working.
///
/// WHY THIS EXISTS
/// `hypervisor-update.service` failed five nights running -- the host applied no
/// updates and never rebooted -- and nobody knew, because that unit had no
/// OnFailure= wired. It was found by reading the journal for an unrelated
/// reason.
///
/// Two of the watched units had broken notification paths when this was
/// written: one had no OnFailure at all, another had it in the [Service]
/// section where systemd silently ignores it. Both are fixed, but the lesson is
/// that per-unit alerting is something you can forget to add. This check does
/// not depend on remembering.
pub fn check_failed_units(state: &SystemdState, r: &mut Report) {
    for (unit, when) in &state.failed_watched {
        let when = if when.is_empty() { "unknown" } else { when };
        r.fail(format!("systemd unit {unit} is FAILED (since {when})"));
    }
    // A failed unit is a finding, not a footnote. This previously recorded
    // unwatched failures as a NOTE, so the run could print "all invariants hold"
    // while systemd was sitting in a degraded state -- a contradiction that
    // teaches the reader to distrust the summary line.
    if state.system_status == "degraded" {
        let others: Vec<&str> = state
            .all_failed
            .iter()
            .map(String::as_str)
            .filter(|u| !WATCHED_UNITS.contains(u))
            .take(5)
            .collect();
        if !others.is_empty() {
            r.fail(format!(
                "systemd is degraded; failed units not on the watch list: {}",
                others.join(", ")
            ));
        }
    }
    // Deliberately inspects EVERY failure recorded so far, not just this
    // check's — faithful to the Python, which reads the shared list. In
    // practice only this check emits "systemd unit", but narrowing it would be
    // a behaviour change smuggled in as a tidy-up.
    if !r.failures.iter().any(|f| f.contains("systemd unit")) {
        r.note(format!(
            "host units: {} watched, none failed",
            WATCHED_UNITS.len()
        ));
    }
}

/// One host's answer to the SELinux probe.
///
/// `output` is None when the host was unreachable OR produced nothing — the
/// Python treats both identically, and the distinction does not change what can
/// be concluded: either way the control was not verified there.
#[derive(Debug)]
pub struct SelinuxProbe {
    pub label: String,
    pub output: Option<String>,
}

/// Assert SELinux is ENFORCING on both hypervisors, with no escape hatches.
///
/// Both hosts were found already enforcing on 2026-08-29 with a genuinely clean
/// policy — zero permissive domains and zero custom modules — so nothing had to
/// be done. That is exactly why this check exists: nothing was watching it, so a
/// drift to permissive, or a `semanage permissive -a` added to work around one
/// awkward denial, would have gone unnoticed indefinitely.
///
/// Mode alone is not the property. A host can report `enforcing` while
/// individual domains run permissive, which is a per-domain opt-out of the whole
/// control — so the domain count is asserted too.
pub fn check_selinux(probes: &[SelinuxProbe], r: &mut Report) {
    for p in probes {
        let Some(out) = p.output.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            // A note, not a failure. An unreachable host is not evidence the
            // control is broken — but it is also not evidence it holds, and
            // saying "not checked" keeps those apart.
            r.note(format!("selinux: {} unreachable, not checked", p.label));
            continue;
        };
        let fields: Vec<&str> = out.split_whitespace().collect();
        let mode = fields.first().copied().unwrap_or("?");
        // A non-numeric count reads as zero, matching the Python's except
        // ValueError. It is the permissive-DOMAIN count that matters, and an
        // unparseable one should not manufacture a failure.
        let permissive: u32 = fields.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        if mode != "Enforcing" {
            r.fail(format!(
                "selinux: {} is {mode}, expected Enforcing",
                p.label
            ));
        } else if permissive > 0 {
            r.fail(format!(
                "selinux: {} is Enforcing but {permissive} domain(s) are \
                 permissive — a per-domain opt-out of the control",
                p.label
            ));
        } else {
            r.note(format!(
                "selinux: {} enforcing, no permissive domains",
                p.label
            ));
        }
    }
}

/// Peer units this host watches on the OTHER hypervisor's behalf.
pub const PEER_UNITS: &[&str] = &["hypervisor-update.service"];

/// One peer unit's reported state. `state` is None when the host was
/// unreachable — distinct from an empty answer, which means the same thing here
/// but should not be confused with the unit being healthy.
#[derive(Debug)]
pub struct PeerUnitState {
    pub label: String,
    pub unit: String,
    pub state: Option<String>,
}

/// Assert the peer hypervisor's maintenance is not silently failing.
///
/// server2's `hypervisor-update` had been aborting nightly since Aug 25 with a
/// stale kubeconfig -- the identical fault as server1, found only because
/// someone went looking. It had no OnFailure of its own, so nothing on that host
/// could report it; as of 2026-08-28 it does (deploy_updates.py now ships
/// hypervisor-update-notify.service to every hypervisor). This check stays as
/// the second layer: it catches a host whose own notifier is broken or whose
/// ntfy topic is unreachable.
pub fn check_peer_units(states: &[PeerUnitState], r: &mut Report) {
    for s in states {
        match s.state.as_deref().map(str::trim).unwrap_or("") {
            "failed" => r.fail(format!("peer {}: {} is FAILED", s.label, s.unit)),
            // Unreachable is worth knowing, but it is not a security finding --
            // do not fail the whole check because a host is briefly rebooting.
            "" => r.note(format!(
                "peer {}: unreachable, {} not checked",
                s.label, s.unit
            )),
            other => r.note(format!("peer {}: {} {other}", s.label, s.unit)),
        }
    }
}

/// What the two origin-lock probes returned, gathered before judgement.
///
/// `through` is the status via Cloudflare; `direct` is the status when the
/// proxy is bypassed by resolving the hostname straight to the origin. Both are
/// raw curl `%{http_code}` output — "000" means the connection never completed,
/// which for `direct` is the DESIRED answer.
#[derive(Debug, Default)]
pub struct OriginProbe {
    /// None when no public hostname is configured at all.
    pub hostname_configured: bool,
    pub through: String,
    /// None when no origin address is configured, so the bypass was not tried.
    pub direct: Option<String>,
}

/// The public site must answer through Cloudflare and REFUSE a direct hit.
///
/// The hostname and origin address come from site.yml, which is gitignored —
/// `substrate` is a public repository and the WAN address does not belong in it.
///
/// This is the check that would have caught the original exposure, and it is
/// the one most likely to regress: the allowlist is a static list of Cloudflare
/// ranges (ADR-070) and a stale list fails closed.
pub fn check_origin_lock(p: &OriginProbe, r: &mut Report) {
    if !p.hostname_configured {
        r.note("origin lock: no public_hostname configured, check skipped");
        return;
    }
    if p.through != "200" {
        r.fail(format!(
            "public site via Cloudflare returned {}, expected 200",
            p.through
        ));
    } else {
        r.note("public site: 200 through Cloudflare");
    }
    let Some(direct) = p.direct.as_deref() else {
        r.note("origin lock: no origin_ip configured, bypass check skipped");
        return;
    };
    if direct == "200" {
        // The one finding in this whole file that means someone can reach the
        // ingress without passing the edge allowlist.
        r.fail(
            "ORIGIN LOCK BROKEN: the ingress answers a direct connection that \
             bypasses Cloudflare (ADR-070)",
        );
    } else {
        let shown = if direct.is_empty() {
            "no response"
        } else {
            direct
        };
        r.note(format!("origin lock: direct bypass refused ({shown})"));
    }
}

/// The config artifact's signature must still be verified on every pull.
///
/// `spec.verify` can be removed from the OCIRepository without anything
/// breaking -- Flux keeps reconciling perfectly, just without checking who
/// produced the artifact. The failure is invisible by construction, which is
/// exactly the kind that needs an external assertion.
///
/// The three failures below are ORDERED, and each returns early, because they
/// are progressively weaker states: no verification at all, verification that
/// would accept anyone's signature, and verification that is configured but not
/// currently passing. Reporting all three at once would bury the first.
pub fn check_source_verified(repo: &Value, r: &mut Report) {
    let verify = repo.pointer("/spec/verify");
    let Some(verify) = verify.filter(|v| !v.is_null()) else {
        r.fail(
            "the config artifact is NO LONGER signature-verified \
             (spec.verify removed from the OCIRepository)",
        );
        return;
    };
    // Without an identity match, cosign accepts ANY valid Sigstore signature —
    // which is to say, anyone who can get a certificate from a public CA. That
    // is weaker than it looks and reads as "verification: on".
    if verify
        .get("matchOIDCIdentity")
        .and_then(Value::as_array)
        .is_none_or(|a| a.is_empty())
    {
        r.fail(
            "cosign verification has no matchOIDCIdentity — it would \
             accept ANY valid Sigstore signature, including an attacker's",
        );
        return;
    }
    let cond = repo
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some("SourceVerified"))
        });
    match cond {
        Some(c) if c.get("status").and_then(Value::as_str) == Some("True") => {
            r.note("supply chain: artifact signature verified against the pinned identity")
        }
        other => {
            let msg = other
                .and_then(|c| c.get("message").and_then(Value::as_str))
                .unwrap_or("no SourceVerified condition");
            r.fail(format!("artifact signature NOT verified: {msg}"));
        }
    }
}

/// One port's two-directional probe result.
///
/// `leaked` answers "can the source that MUST NOT reach this port reach it?"
/// `permitted` answers "can the source that MUST reach it reach it?" — and is
/// None when it was not probed, which the Python does only after `leaked` comes
/// back false. None is inconclusive in both fields, never a verdict.
#[derive(Debug)]
pub struct FirewallProbe {
    pub port: u16,
    pub what: String,
    pub allowed_label: String,
    pub denied_label: String,
    pub leaked: Option<bool>,
    pub permitted: Option<bool>,
}

/// The firewall must REFUSE what its allow-list claims to restrict.
///
/// WHY THIS EXISTS. deploy-observability.py has always written per-source
/// `accept` rich rules for 9100 and 9428, under a comment reading "ALLOW-LIST,
/// not a LAN range (the standing rule)". On 2026-09-02 a negative test showed
/// all of them reachable from hosts that were never allow-listed. The default
/// zone on this workstation opens 1025-65535/tcp, and an `accept` rule on top of
/// an already-open range restricts nothing at all. The rules had been decorative
/// since the day they were written, and every check in this file passed
/// throughout — because nothing here asked whether a refusal actually refuses.
///
/// Asserting the rules EXIST would have reproduced the original mistake. So this
/// connects from a source that must be denied and fails if it succeeds, and from
/// one that must be allowed and warns if it does not. Both directions: a
/// firewall that blocks everything is not correct either, it is just broken in
/// the direction nobody notices until a scrape goes missing.
///
/// `probes` is None when the site config lacks what the matrix needs.
pub fn check_firewall_restrictions(probes: Option<&[FirewallProbe]>, r: &mut Report) {
    let Some(probes) = probes else {
        r.note("firewall: site config incomplete, not checked");
        return;
    };
    let mut checked = 0usize;
    for p in probes {
        match p.leaked {
            None => {
                r.note(format!(
                    "firewall: {} not checked ({} unreachable)",
                    p.port, p.denied_label
                ));
                continue;
            }
            Some(true) => {
                r.fail(format!(
                    "firewall: {} ({}) is reachable from {}, which is NOT allow-listed",
                    p.port, p.what, p.denied_label
                ));
                continue;
            }
            Some(false) => {}
        }
        if p.permitted == Some(false) {
            // The other direction, and it matters just as much: a firewall that
            // blocks everything is not correct, it is broken where nobody looks
            // until a scrape quietly stops arriving.
            r.fail(format!(
                "firewall: {} ({}) is refused for {}, which MUST reach it",
                p.port, p.what, p.allowed_label
            ));
            continue;
        }
        checked += 1;
    }
    if checked > 0 {
        r.note(format!(
            "firewall: {checked} port(s) refuse non-allow-listed sources"
        ));
    }
}
