//! Alert rules and the contact point, rendered into Grafana's provisioning
//! schema. Ported from `deploy-observability.py`.
//!
//! Grafana's format needs ~25 lines of query/reduce/threshold plumbing per
//! rule, which is identical every time and is not where the thinking is. The
//! thinking is the expression, the threshold and the wait — so that is what
//! is written here, and the plumbing is generated.
//!
//! Every expression was checked against metrics that DEMONSTRABLY exist when
//! the rule was written. A rule referencing a metric nothing collects is not a
//! safety net, it is a permanently-green panel. `for` is a deliberate part of
//! each rule: a target that blips for one interval is noise.

use serde_yaml_ng::{Mapping, Value};

pub struct Rule {
    pub uid: &'static str,
    pub title: &'static str,
    pub expr: &'static str,
    pub op: &'static str,
    pub threshold: f64,
    pub wait: &'static str,
    pub severity: &'static str,
    pub summary: &'static str,
    pub runbook: &'static str,
}

pub const ALERT_RULES: &[Rule] = &[
    Rule {
        uid: "target-down",
        title: "Scrape target down",
        expr: "up",
        op: "lt",
        threshold: 1.0,
        wait: "10m",
        severity: "page",
        summary: "A scrape target has been unreachable for 10 minutes.",
        // up=0 collapses at least six distinct causes (ADR-116 corollary).
        runbook: "Check the scraper error and the target's own log, not just this alert.",
    },
    Rule {
        uid: "hypervisor-memory-high",
        title: "Hypervisor memory high",
        expr: "100 * (1 - node_memory_MemAvailable_bytes{tier=\"hypervisor\"} / node_memory_MemTotal_bytes{tier=\"hypervisor\"})",
        op: "gt",
        threshold: 90.0,
        wait: "15m",
        severity: "page",
        summary: "A hypervisor has been above 90% memory for 15 minutes.",
        runbook: "server2 has 15 GiB total; it runs hot by design. Check what grew.",
    },
    Rule {
        uid: "root-filesystem-low",
        title: "Filesystem low",
        // NOT mountpoint="/": the immutable node root is permanently 9.2% free
        // (ADR-119). `unless node_filesystem_readonly == 1` excludes it from
        // the node's own report; `min by (...device)` collapses bind mounts.
        expr: "min by (tier,host,node,device) (100 * node_filesystem_avail_bytes{fstype!~\"tmpfs|ramfs|devtmpfs|overlay|squashfs|iso9660\"} / node_filesystem_size_bytes{fstype!~\"tmpfs|ramfs|devtmpfs|overlay|squashfs|iso9660\"} unless node_filesystem_readonly == 1)",
        op: "lt",
        threshold: 10.0,
        wait: "15m",
        severity: "page",
        summary: "A writable filesystem is below 10% free.",
        runbook: "Includes each node's /dev/vdb Longhorn disk. Immutable roots are excluded.",
    },
    Rule {
        uid: "log-ingestion-stopped",
        title: "Log ingestion stopped",
        expr: "sum(rate(vl_rows_ingested_total[15m]))",
        op: "lt",
        threshold: 0.001,
        wait: "30m",
        severity: "page",
        summary: "No log lines have been ingested for 30 minutes.",
        runbook: "Vector drops all events if its VRL fails to compile. Check vector logs.",
    },
    Rule {
        uid: "store-disk-low",
        title: "Metrics or log store disk low",
        expr: "min(vm_free_disk_space_bytes) / 1024 / 1024 / 1024 or min(vl_free_disk_space_bytes) / 1024 / 1024 / 1024",
        op: "lt",
        threshold: 20.0,
        wait: "15m",
        severity: "page",
        summary: "A store has less than 20 GiB of free disk.",
        runbook: "Both stores go read-only rather than crash; data stops silently.",
    },
    Rule {
        uid: "cronjob-not-succeeding",
        title: "CronJob has not succeeded",
        // `exported_namespace`, NOT `namespace` (label collision with the
        // scraper's own). Suspended CronJobs excluded: seven drills carry
        // `suspend: true` on a date that never occurs.
        expr: "(time() - max by (exported_namespace,cronjob) (kube_cronjob_status_last_successful_time)) and on(exported_namespace,cronjob) (max by (exported_namespace,cronjob) (kube_cronjob_spec_suspend) == 0)",
        op: "gt",
        // 25 hours: one missed run of a daily job, plus an hour of slack.
        threshold: 90000.0,
        wait: "30m",
        severity: "page",
        summary: "A CronJob has not succeeded in over 25 hours.",
        runbook: "Check `kubectl -n <ns> get job` first: a job stuck Init:0/1 on an RWO volume looks identical to one that never ran. Suspended CronJobs are excluded by design.",
    },
    Rule {
        uid: "pvc-nearly-full",
        title: "PersistentVolume nearly full",
        expr: "max by (namespace,persistentvolumeclaim) (100 * kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes)",
        op: "gt",
        threshold: 75.0,
        wait: "15m",
        severity: "page",
        // Sees only volumes currently MOUNTED — a real blind spot (ADR-152).
        summary: "A PersistentVolume has been over 75% full for 15 minutes.",
        runbook: "Longhorn supports online expansion, but size it from the observed growth curve, not a round number. Only MOUNTED volumes appear here.",
    },
    Rule {
        uid: "scrape-config-not-loaded",
        title: "VictoriaMetrics rejected its scrape config",
        expr: "vm_promscrape_config_last_reload_successful",
        op: "lt",
        threshold: 1.0,
        wait: "10m",
        severity: "page",
        summary: "The scrape config failed to reload; the previous one is still live.",
        runbook: "The running config is stale. Check victoria-metrics logs for the parse error.",
    },
    Rule {
        uid: "certificate-not-ready",
        title: "Certificate not ready",
        expr: "certmanager_certificate_ready_status{condition=\"True\"}",
        op: "lt",
        threshold: 1.0,
        wait: "30m",
        severity: "page",
        summary: "A certificate has been un-Ready for 30 minutes.",
        runbook: "Check the Certificate, then its CertificateRequest, Order and Challenge.",
    },
    Rule {
        uid: "certificate-expiring",
        title: "Certificate expiring soon",
        // NOT redundant with certificate-not-ready: a failing RENEWAL leaves
        // Ready=True on a still-valid cert. That is what was in flight when
        // the Cloudflare token expired unnoticed for five days.
        expr: "(certmanager_certificate_expiration_timestamp_seconds - time()) / 86400",
        op: "lt",
        threshold: 21.0,
        wait: "60m",
        severity: "page",
        summary: "A certificate expires in under 21 days and has not renewed.",
        runbook: "Renewal is failing silently. Verify the DNS-01 credential first: curl -H 'Authorization: Bearer $TOKEN' https://api.cloudflare.com/client/v4/user/tokens/verify",
    },
];

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn map(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Mapping::new();
    for (k, v) in pairs {
        m.insert(s(k), v);
    }
    Value::Mapping(m)
}

fn num(v: f64) -> Value {
    // PyYAML writes `1` for an int and `0.001` for a float; the spec used ints
    // where the value was whole. Keep that distinction.
    if v.fract() == 0.0 && v.abs() < 1e15 {
        Value::Number((v as i64).into())
    } else {
        Value::Number(v.into())
    }
}

/// Grafana evaluates each rule as a small pipeline: query (A), reduce to a
/// single value (B), compare against a threshold (C). C is the condition.
pub fn alert_rules_document() -> Value {
    let rules: Vec<Value> = ALERT_RULES
        .iter()
        .map(|r| {
            map(vec![
                ("uid", s(r.uid)),
                ("title", s(r.title)),
                ("condition", s("C")),
                ("for", s(r.wait)),
                // NoData is reported rather than paged: it is what a brand-new
                // rule sees before its first evaluation.
                ("noDataState", s("NoData")),
                // A rule that cannot be evaluated ALERTS. A broken alert rule
                // that fails quietly is the thing this exists to prevent.
                ("execErrState", s("Alerting")),
                ("labels", map(vec![("severity", s(r.severity))])),
                (
                    "annotations",
                    map(vec![("summary", s(r.summary)), ("runbook", s(r.runbook))]),
                ),
                (
                    "data",
                    Value::Sequence(vec![
                        map(vec![
                            ("refId", s("A")),
                            (
                                "relativeTimeRange",
                                map(vec![("from", num(600.0)), ("to", num(0.0))]),
                            ),
                            ("datasourceUid", s("victoriametrics")),
                            (
                                "model",
                                map(vec![
                                    ("refId", s("A")),
                                    ("expr", s(r.expr)),
                                    ("instant", Value::Bool(true)),
                                ]),
                            ),
                        ]),
                        map(vec![
                            ("refId", s("B")),
                            ("datasourceUid", s("__expr__")),
                            (
                                "model",
                                map(vec![
                                    ("refId", s("B")),
                                    ("type", s("reduce")),
                                    ("expression", s("A")),
                                    ("reducer", s("last")),
                                ]),
                            ),
                        ]),
                        map(vec![
                            ("refId", s("C")),
                            ("datasourceUid", s("__expr__")),
                            (
                                "model",
                                map(vec![
                                    ("refId", s("C")),
                                    ("type", s("threshold")),
                                    ("expression", s("B")),
                                    (
                                        "conditions",
                                        Value::Sequence(vec![map(vec![(
                                            "evaluator",
                                            map(vec![
                                                ("type", s(r.op)),
                                                ("params", Value::Sequence(vec![num(r.threshold)])),
                                            ]),
                                        )])]),
                                    ),
                                ]),
                            ),
                        ]),
                    ]),
                ),
            ])
        })
        .collect();
    map(vec![
        ("apiVersion", num(1.0)),
        (
            "groups",
            Value::Sequence(vec![map(vec![
                ("orgId", num(1.0)),
                ("name", s("fleet")),
                ("folder", s("Alerts")),
                ("interval", s("1m")),
                ("rules", Value::Sequence(rules)),
            ])]),
        ),
    ])
}

/// Fold long scalar values the way `yaml.safe_dump(width=100)` does.
///
/// PyYAML's emitter breaks a plain or single-quoted scalar at a SINGLE space
/// once the column has passed `best_width`, continuing on the next line at
/// the key's indent + 2. serde's emitter never folds. The two documents are
/// semantically identical either way; this exists so the sha256 the drift
/// checker compares on each host is the same one the Python wrote, and a
/// redeploy does not have to explain a cosmetic reflow (ADR-100).
pub fn fold_like_pyyaml(yaml: &str, best_width: usize) -> String {
    let mut out = String::with_capacity(yaml.len());
    for line in yaml.lines() {
        let indent = line.len() - line.trim_start().len();
        let body = &line[indent..];
        // `key: value` only; sequences and keys-without-values pass through.
        let Some((key, value)) = body.split_once(": ") else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        if key.is_empty() || key.starts_with('-') || key.starts_with('#') || value.is_empty() {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let quoted = value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2;
        let text = if quoted {
            &value[1..value.len() - 1]
        } else {
            value
        };
        let mut column = indent + key.len() + 2;
        let cont = " ".repeat(indent + 2);
        out.push_str(&line[..indent + key.len() + 2]);
        if quoted {
            out.push('\'');
            column += 1;
        }
        // Chunk into words and space runs, as write_plain / write_single_quoted do.
        let chars: Vec<char> = text.chars().collect();
        let n = chars.len();
        let mut start = 0;
        let mut i = 0;
        while i <= n {
            let ch = chars.get(i).copied();
            let in_spaces = start < n && chars[start] == ' ';
            if in_spaces {
                if ch != Some(' ') {
                    let single = start + 1 == i;
                    let at_edge = quoted && (start == 0 || i == n);
                    if single && column > best_width && !at_edge {
                        out.push('\n');
                        out.push_str(&cont);
                        column = cont.len();
                    } else {
                        out.extend(chars[start..i].iter());
                        column += i - start;
                    }
                    start = i;
                }
            } else if ch.is_none() || ch == Some(' ') {
                out.extend(chars[start..i].iter());
                column += i - start;
                start = i;
            }
            i += 1;
        }
        if quoted {
            out.push('\'');
        }
        out.push('\n');
    }
    out
}

pub fn alert_rules() -> String {
    let header = "# Generated by deploy-observability.py — do not edit by hand.\n\
                  # Rules are defined as a compact spec in ALERT_RULES; this is rendered.\n";
    format!(
        "{header}{}",
        fold_like_pyyaml(
            &serde_yaml_ng::to_string(&alert_rules_document()).unwrap_or_default(),
            100
        )
    )
}

/// The body ntfy receives, in ITS shape rather than Grafana's.
///
/// Grafana's default webhook body is its whole alert payload — several KB —
/// and ntfy turns anything over its 4 KB message limit into an attachment,
/// so every page arrived as a JSON file to open rather than a line to read
/// (bug-149). This template posts to ntfy's JSON endpoint (the root URL, topic
/// in the body) with a title, a one-line-per-target message, and a priority
/// that drops when the group resolves. Labels only in the body: a summary
/// annotation with a quote in it would break the JSON.
pub fn ntfy_payload_template(topic: &str) -> String {
    format!(
        r#"{{
  "topic": "{topic}",
  "title": "{{{{ .CommonLabels.alertname }}}}: {{{{ .Status }}}} ({{{{ len .Alerts }}}})",
  "message": "{{{{ range .Alerts }}}}{{{{ .Labels.job }}}} {{{{ .Labels.instance }}}}\n{{{{ end }}}}",
  "priority": {{{{ if eq .Status "firing" }}}}4{{{{ else }}}}2{{{{ end }}}},
  "tags": ["{{{{ .Status }}}}"]
}}"#
    )
}

/// The ntfy contact point and the policy that routes to it. THE TOPIC IS A
/// SECRET (a capability URL), resolved from the operator's environment at
/// deploy time and installed root:grafana 0640.
pub fn contact_points_document(topic: &str) -> Value {
    map(vec![
        ("apiVersion", num(1.0)),
        (
            "contactPoints",
            Value::Sequence(vec![map(vec![
                ("orgId", num(1.0)),
                ("name", s("ntfy")),
                (
                    "receivers",
                    Value::Sequence(vec![map(vec![
                        ("uid", s("ntfy")),
                        ("type", s("webhook")),
                        (
                            "settings",
                            map(vec![
                                // The ROOT, not /<topic>: ntfy's JSON publish
                                // endpoint takes the topic in the body.
                                ("url", s("https://ntfy.sh/")),
                                ("httpMethod", s("POST")),
                                (
                                    "payload",
                                    map(vec![("template", s(&ntfy_payload_template(topic)))]),
                                ),
                            ]),
                        ),
                    ])]),
                ),
            ])]),
        ),
        (
            "policies",
            Value::Sequence(vec![map(vec![
                ("orgId", num(1.0)),
                ("receiver", s("ntfy")),
                // Group by rule: five nodes crossing one threshold is one
                // notification naming five.
                ("group_by", Value::Sequence(vec![s("alertname")])),
                ("group_wait", s("30s")),
                ("group_interval", s("5m")),
                // A permanently-failing condition must not page indefinitely.
                ("repeat_interval", s("4h")),
            ])]),
        ),
    ])
}

pub fn contact_points(topic: &str) -> String {
    let header = "# Generated by deploy-observability.py — do not edit by hand.\n\
                  # CONTAINS A CREDENTIAL (the ntfy topic). root:grafana 0640.\n";
    format!(
        "{header}{}",
        fold_like_pyyaml(
            &serde_yaml_ng::to_string(&contact_points_document(topic)).unwrap_or_default(),
            100
        )
    )
}

#[cfg(test)]
mod ntfy_payload_tests {
    use super::*;

    #[test]
    fn the_payload_is_ntfy_shaped_json_with_the_topic_in_the_body() {
        // Render the template with the Go-template holes stubbed, then parse:
        // a payload that is not JSON is an attachment again (bug-149).
        let t = ntfy_payload_template("t0pic");
        let rendered = t
            .replace("{{ .CommonLabels.alertname }}", "target-down")
            .replace("{{ .Status }}", "firing")
            .replace("{{ len .Alerts }}", "3")
            .replace(
                "{{ range .Alerts }}{{ .Labels.job }} {{ .Labels.instance }}\\n{{ end }}",
                "kubelet s2-vm1\\nkubelet s2-vm2\\n",
            )
            .replace("{{ if eq .Status \"firing\" }}4{{ else }}2{{ end }}", "4");
        let v: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(v["topic"], "t0pic");
        assert_eq!(v["priority"], 4);
        assert!(v["message"].as_str().unwrap().contains("kubelet s2-vm1"));
    }

    #[test]
    fn the_contact_point_posts_to_the_root_with_the_template() {
        let doc = contact_points_document("t0pic");
        let settings = &doc["contactPoints"][0]["receivers"][0]["settings"];
        assert_eq!(
            settings["url"], "https://ntfy.sh/",
            "topic goes in the body, not the path"
        );
        let tpl = settings["payload"]["template"].as_str().unwrap();
        assert!(tpl.contains("\"topic\": \"t0pic\""));
    }
}
