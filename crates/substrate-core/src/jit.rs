//! Time-boxed platform-admin grants — the pure half.
//!
//! THE MODEL (ADR-065)
//! Read-only access is permanent and unremarkable. Write access is an event:
//! you ask for it, it is recorded, and it goes away on its own.
//!
//! Kubernetes has no TTL on a ClusterRoleBinding, so the expiry lives in an
//! annotation and the `jit-reaper` CronJob enforces it every two minutes. The
//! reaper also deletes any grant with NO expiry annotation, so a binding made
//! by hand cannot quietly become permanent.
//!
//! ── WHY THIS PORT IS SHAPED DIFFERENTLY FROM `posture` ───────────────────────
//! posture-check is READ-ONLY, so both implementations could be run against the
//! same cluster and their output diffed. jit-admin WRITES — it grants
//! cluster-admin — and you cannot prove two write tools equivalent by running
//! both, because both would write.
//!
//! So the contract here is GOLDENS, the same one the renderer uses: every
//! function below is pure, its inputs are fixed, and its output is compared
//! byte-for-byte against a file generated from the Python. `identity` and
//! `hostname` are INJECTED rather than read from the environment, which is the
//! change that makes that possible — the Python reads them inside each
//! function, and a value that varies by machine cannot be a golden.

use serde_json::Value;
use std::collections::BTreeMap;
use std::io;

pub const BINDING: &str = "jit-platform-admin";
pub const ANNOTATION: &str = "jit.bradpenney.io/expires-at";
pub const AUDIT_MAX_ENTRIES: usize = 200;

/// Who ran this, and from where. Injected so the pure functions stay pure.
///
/// This is attribution, NOT authentication — anything here can be spoofed by
/// whoever can already run the command. Its job is to answer "who did this?"
/// on a Tuesday, not to withstand an adversary who already holds the
/// break-glass context.
#[derive(Debug, Clone)]
pub struct Attribution {
    pub invoker: String,
    pub host: String,
}

/// Best-effort identity of the human who ran this.
///
/// `SUDO_USER` first: under sudo, `USER` is root and says nothing about who is
/// actually at the keyboard. Falls back through the login environment to the
/// process owner.
pub fn invoker_from_env() -> String {
    for var in ["SUDO_USER", "USER", "LOGNAME"] {
        // An exported-but-empty variable falls through, matching the Python's
        // `if value:` — SUDO_USER="" must not resolve to an empty invoker.
        if let Some(v) = std::env::var(var).ok().filter(|v| !v.is_empty()) {
            return v;
        }
    }
    // The Python's last resort is getpass.getuser(), which itself consults the
    // same variables before falling back to the password database. Reaching
    // here means none were set; an empty string is honest about that rather
    // than inventing a name for the audit log.
    String::new()
}

/// Annotations recording who asked for a grant, from where, and why.
///
/// A grant that records only its expiry — which is what this tool wrote until
/// 2026-09-06 — cannot answer the one question asked after the fact. An
/// unattributed grant appeared on this cluster on 2026-09-05 and neither the
/// operator nor the tooling could say who issued it (ADR-136).
pub fn attribution(
    user: &str,
    reason: &str,
    expires: &str,
    granted: &str,
    who: &Attribution,
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(ANNOTATION.to_string(), expires.to_string());
    m.insert("jit.bradpenney.io/granted-at".into(), granted.to_string());
    m.insert("jit.bradpenney.io/invoker".into(), who.invoker.clone());
    m.insert("jit.bradpenney.io/source-host".into(), who.host.clone());
    m.insert("jit.bradpenney.io/reason".into(), reason.to_string());
    m.insert("jit.bradpenney.io/subject".into(), user.to_string());
    m
}

/// A serde_json formatter that matches Python's `json.dumps` defaults.
///
/// ⚠️ THIS EXISTS BECAUSE OF A RECORDED TRAP, not a style preference.
/// `json.dumps` separates with `", "` and `": "`; serde_json writes neither.
/// The audit log is compared byte-for-byte against goldens generated from the
/// Python, and an audit record that differs only in whitespace is still a
/// record the two tools do not agree on — and would show as a spurious diff
/// forever after.
struct PythonJson;

impl serde_json::ser::Formatter for PythonJson {
    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
}

/// Serialise exactly as Python's `json.dumps(..., sort_keys=True)` would.
fn dumps(v: &Value) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, PythonJson);
    serde::Serialize::serialize(v, &mut ser).expect("serialising a Value cannot fail");
    String::from_utf8(buf).expect("serde_json emits valid UTF-8")
}

/// One JSON line for the audit ConfigMap. Newline-free by construction.
///
/// Keys are sorted because the Python passes `sort_keys=True`; a `BTreeMap`
/// gives that for free rather than by remembering to ask for it.
pub fn audit_line(action: &str, user: &str, reason: &str, when: &str, who: &Attribution) -> String {
    let mut m = serde_json::Map::new();
    m.insert("at".into(), Value::String(when.into()));
    m.insert("action".into(), Value::String(action.into()));
    m.insert("subject".into(), Value::String(user.into()));
    m.insert("invoker".into(), Value::String(who.invoker.clone()));
    m.insert("host".into(), Value::String(who.host.clone()));
    m.insert("reason".into(), Value::String(reason.into()));
    // serde_json's Map preserves insertion order unless the `preserve_order`
    // feature is off — it is off here, so this is already a BTreeMap and the
    // keys come out sorted, matching sort_keys=True.
    dumps(&Value::Object(m))
}

/// Append `line` to `existing`, keeping only the newest `AUDIT_MAX_ENTRIES`.
///
/// A log that grows without bound eventually exceeds the ~1 MiB ConfigMap
/// limit, at which point the audit stops recording — silently, and only once
/// there is a lot of history worth keeping.
pub fn trimmed_log(existing: &str, line: &str) -> String {
    let mut entries: Vec<&str> = existing.split('\n').filter(|x| !x.is_empty()).collect();
    if AUDIT_MAX_ENTRIES > 1 {
        let keep = AUDIT_MAX_ENTRIES - 1;
        if entries.len() > keep {
            entries.drain(..entries.len() - keep);
        }
    } else {
        entries.clear();
    }
    entries.push(line);
    entries.join("\n")
}

/// Why a requested grant window was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum WindowError {
    OutOfRange,
}

/// A grant longer than a working day is not time-boxed in any meaningful sense.
pub fn validate_minutes(minutes: i64) -> Result<i64, WindowError> {
    if (1..=480).contains(&minutes) {
        Ok(minutes)
    } else {
        Err(WindowError::OutOfRange)
    }
}
