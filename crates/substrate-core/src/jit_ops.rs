//! Time-boxed platform-admin grants — the kubectl half.
//!
//! Ported from `jit-admin.py`. The pure functions (attribution, audit line,
//! trimming, window validation) live in [`crate::jit`] and are pinned by
//! goldens generated from the Python; this module is the part that WRITES,
//! which cannot be proven by running both tools against one cluster.
//!
//! Creating the grant means creating a ClusterRoleBinding, which the scoped
//! identity deliberately CANNOT do — otherwise the time box would constrain
//! nothing. So `grant` and `revoke` name the break-glass context explicitly:
//! the god credential goes from "everything you do all day" to "one command,
//! which leaves a record." `status` runs as the current user, because
//! requiring break-glass just to look would discourage looking.

use crate::exec::Output;
use crate::jit::{self, ANNOTATION, Attribution, BINDING};
use serde_json::{Value, json};

pub const BREAK_GLASS_CONTEXT: &str = "break-glass";
/// The audit trail lives in a ConfigMap, not in annotations on the binding:
/// annotations disappear when the grant is reaped, which is precisely when you
/// most want to know a grant existed. A ConfigMap survives the reap, lives in
/// etcd, and inherits the etcd backup that has been restore-tested (ADR-072).
pub const AUDIT_CONFIGMAP: &str = "jit-admin-audit";
pub const AUDIT_NAMESPACE: &str = "kube-system";

fn kubectl(args: &[&str], context: Option<&str>, input: Option<&str>) -> Output {
    let mut cmd = std::process::Command::new("kubectl");
    if let Some(c) = context {
        cmd.arg(format!("--context={c}"));
    }
    cmd.args(args);
    cmd.stdin(if input.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = cmd.spawn();
    let Ok(mut child) = child else {
        return Output {
            status: -1,
            stdout: String::new(),
            stderr: "could not run kubectl".into(),
        };
    };
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        use std::io::Write as _;
        let _ = stdin.write_all(text.as_bytes());
    }
    match child.wait_with_output() {
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

/// Run kubectl and exit with the failing command and its stderr — a CLI
/// holding a break-glass credential should see the command, not a backtrace.
fn kubectl_or_exit(args: &[&str], context: Option<&str>, input: Option<&str>) -> Output {
    let out = kubectl(args, context, input);
    if !out.ok() {
        let shown: Vec<String> = std::iter::once("kubectl".to_string())
            .chain(context.map(|c| format!("--context={c}")))
            .chain(args.iter().map(|a| a.to_string()))
            .collect();
        eprintln!("command failed: {}\n{}", shown.join(" "), out.stderr.trim());
        std::process::exit(1);
    }
    out
}

/// The outstanding grant, or None — the healthy state.
pub fn current() -> Option<Value> {
    let r = kubectl(
        &["get", "clusterrolebinding", BINDING, "-o", "json"],
        None,
        None,
    );
    r.ok()
        .then(|| serde_json::from_str(&r.stdout).ok())
        .flatten()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn who() -> Attribution {
    Attribution {
        invoker: jit::invoker_from_env(),
        host: hostname(),
    }
}

fn now_utc() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// `strftime("%Y-%m-%dT%H:%M:%SZ")`.
fn stamp(t: time::OffsetDateTime) -> String {
    let (y, mo, d) = (t.year(), t.month() as u8, t.day());
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn subjects(crb: &Value) -> String {
    crb.get("subjects")
        .and_then(Value::as_array)
        .map(|s| {
            s.iter()
                .map(|x| {
                    format!(
                        "{}/{}",
                        x.get("kind").and_then(Value::as_str).unwrap_or(""),
                        x.get("name").and_then(Value::as_str).unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

/// Report whether a grant exists and how long it has left.
pub fn status() -> i32 {
    let Some(crb) = current() else {
        println!("  no outstanding grant - read-only");
        return 0;
    };
    let subs = subjects(&crb);
    let exp = crb
        .pointer(&format!(
            "/metadata/annotations/{}",
            ANNOTATION.replace('/', "~1")
        ))
        .and_then(Value::as_str);
    let Some(exp) = exp.filter(|e| !e.is_empty()) else {
        println!("  grant to {subs} has NO expiry - the reaper will remove it within 2m");
        return 0;
    };
    let end = time::OffsetDateTime::parse(exp, &time::format_description::well_known::Rfc3339);
    let state = match end {
        Ok(end) => {
            let left = (end - now_utc()).whole_seconds();
            if left > 0 {
                format!("{}m remaining", left / 60)
            } else {
                "EXPIRED, awaiting reaper".to_string()
            }
        }
        Err(_) => "unparseable expiry".to_string(),
    };
    println!("  granted to {subs}\n  expires    {exp}  ({state})");
    0
}

/// Append one record to the audit ConfigMap. A FAILURE HERE WARNS AND DOES
/// NOT BLOCK: break-glass exists for the times the cluster is already unwell,
/// and refusing to grant admin because the audit could not be written would
/// make the control fail closed at the exact moment it is needed. The grant
/// still carries its attribution annotations either way.
fn append_audit(line: &str) {
    let result = kubectl(
        &[
            "-n",
            AUDIT_NAMESPACE,
            "get",
            "configmap",
            AUDIT_CONFIGMAP,
            "-o",
            "json",
        ],
        Some(BREAK_GLASS_CONTEXT),
        None,
    );
    let existing = if result.ok() {
        serde_json::from_str::<Value>(&result.stdout)
            .ok()
            .and_then(|v| {
                v.pointer("/data/log")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let cm = json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": AUDIT_CONFIGMAP, "namespace": AUDIT_NAMESPACE},
        "data": {"log": jit::trimmed_log(&existing, line)},
    });
    let applied = kubectl(
        &["apply", "-f", "-"],
        Some(BREAK_GLASS_CONTEXT),
        Some(&cm.to_string()),
    );
    if !applied.ok() {
        eprintln!(
            "  WARNING: could not write the audit record: {}",
            applied.stderr.trim()
        );
        eprintln!("  The grant still carries its attribution annotations.");
    }
}

/// Bind platform-admin to a user for a fixed window. Refuses to stack on an
/// existing grant: a second one would silently extend the first.
pub fn grant(user: &str, minutes: i64, reason: &str) -> i32 {
    if jit::validate_minutes(minutes).is_err() {
        eprintln!(
            "--minutes must be between 1 and 480; a grant longer than a working day is a standing privilege wearing a costume"
        );
        return 1;
    }
    if current().is_some() {
        eprintln!("a grant is already outstanding; run `substrate jit status` or revoke it first");
        return 1;
    }
    let issued = now_utc();
    let now = stamp(issued);
    let exp = stamp(issued + time::Duration::minutes(minutes));
    let who = who();
    let crb = json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": BINDING,
            "annotations": jit::attribution(user, reason, &exp, &now, &who),
            "labels": {"rbac.bradpenney.io/jit": "true"},
        },
        "subjects": [{"kind": "User", "name": user, "apiGroup": "rbac.authorization.k8s.io"}],
        "roleRef": {"kind": "ClusterRole", "name": "platform-admin", "apiGroup": "rbac.authorization.k8s.io"},
    });
    kubectl_or_exit(
        &["apply", "-f", "-"],
        Some(BREAK_GLASS_CONTEXT),
        Some(&crb.to_string()),
    );
    append_audit(&jit::audit_line("grant", user, reason, &now, &who));
    println!("  granted platform-admin to {user} until {exp} ({minutes}m)");
    println!("  invoker: {}@{}  reason: {reason}", who.invoker, who.host);
    println!("  revoke early: substrate jit revoke");
    0
}

/// Remove the grant now rather than waiting for the reaper, and record that
/// it was revoked — "did it end early or run its window?" is exactly the
/// question the trail exists to answer.
pub fn revoke() -> i32 {
    let Some(crb) = current() else {
        println!("  no outstanding grant");
        return 0;
    };
    let subject = crb
        .pointer("/metadata/annotations/jit.bradpenney.io~1subject")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    kubectl_or_exit(
        &["delete", "clusterrolebinding", BINDING],
        Some(BREAK_GLASS_CONTEXT),
        None,
    );
    let now = stamp(now_utc());
    append_audit(&jit::audit_line("revoke", &subject, "", &now, &who()));
    println!("  revoked");
    0
}

#[cfg(test)]
mod tests {
    use super::stamp;
    #[test]
    fn stamp_is_strftime_utc_z() {
        let t = time::OffsetDateTime::from_unix_timestamp(1_757_635_200).unwrap(); // 2025-09-12T00:00:00Z
        assert_eq!(stamp(t), "2025-09-12T00:00:00Z");
    }
}
