//! Longhorn's share of a node replacement, as pure decisions (bugs 154, 158,
//! 170). Nothing here talks to a cluster: every function takes the JSON a
//! `kubectl -o json` returned, or builds the patch the caller will send.
//! `provision` and `gate` do the fetching and the sending.
//!
//! WHY THIS EXISTS. The 2026-09-16 roll (v0.2.4) replaced five nodes and
//! needed a human four times: the re-created node's disk came back as
//! `DiskNotReady: record diskUUID doesn't match the one on the disk` every
//! single time (bug-154, the three-patch dance run by hand ×5); the dead
//! node's volumes stayed attached to it until the attach/detach controller's
//! six-minute unmount wait expired, so every single-writer tenant served
//! 500s for the duration (bug-170); and a detached volume could still lose
//! its last replica to a same-name replacement with nothing rebuilding it
//! (bug-158). A roll that needs a human is not a roll.

use serde_json::{Value, json};

/// Where every node's Longhorn disk lives (the Kairos cloud-init mounts it).
pub const DISK_PATH: &str = "/usr/local/longhorn";

/// Longhorn's own words for a re-created node's disk: its node CR outlived
/// the node, so the recorded UUID belongs to the disk that was destroyed.
pub const STALE_DISK_MARKER: &str = "diskUUID doesn't match";

/// A disk entry that must be evicted, removed and re-added (bug-154).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleDisk {
    /// Key under `spec.disks`.
    pub key: String,
    /// Carried over verbatim. server1's disks reserve 58.7 GiB, server2's
    /// 12 GiB (bug-159: copying one onto the other left the disk unusable
    /// with `DiskPressure`), so the value is read, never assumed.
    pub storage_reserved: u64,
}

/// The disk entry a re-created node cannot use, if any. `None` when the
/// node CR has no disk or Longhorn reports nothing about a UUID mismatch —
/// the honest case for a disk that was forgotten properly.
pub fn stale_disk(node: &Value) -> Option<StaleDisk> {
    let mismatch = node
        .pointer("/status/diskStatus")
        .and_then(Value::as_object)
        .is_some_and(|disks| {
            disks.values().any(|d| {
                d.get("conditions")
                    .and_then(Value::as_array)
                    .is_some_and(|cs| {
                        cs.iter().any(|c| {
                            c.get("message")
                                .and_then(Value::as_str)
                                .is_some_and(|m| m.contains(STALE_DISK_MARKER))
                        })
                    })
            })
        });
    if !mismatch {
        return None;
    }
    let (key, disk) = node
        .pointer("/spec/disks")
        .and_then(Value::as_object)
        .and_then(|m| m.iter().next())?;
    Some(StaleDisk {
        key: key.clone(),
        storage_reserved: disk
            .get("storageReserved")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

/// True once some disk on the node is both Ready and Schedulable — what the
/// re-add is waiting for.
pub fn disk_admitted(node: &Value) -> bool {
    node.pointer("/status/diskStatus")
        .and_then(Value::as_object)
        .is_some_and(|disks| {
            disks.values().any(|d| {
                let cond = |t: &str| {
                    d.get("conditions")
                        .and_then(Value::as_array)
                        .is_some_and(|cs| {
                            cs.iter().any(|c| {
                                c.get("type").and_then(Value::as_str) == Some(t)
                                    && c.get("status").and_then(Value::as_str) == Some("True")
                            })
                        })
                };
                cond("Ready") && cond("Schedulable")
            })
        })
}

/// True while the node CR still reports any disk at all — the removal has
/// not been absorbed yet, and a re-add under a new key would collide with
/// the entry the webhook is still syncing.
pub fn has_disk_status(node: &Value) -> bool {
    node.pointer("/status/diskStatus")
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty())
}

/// Step 1 of the dance: stop scheduling onto the stale entry and ask
/// Longhorn to evict whatever it thinks lives there.
pub fn evict_patch(key: &str) -> String {
    json!([
        {"op": "replace", "path": format!("/spec/disks/{key}/allowScheduling"), "value": false},
        {"op": "add", "path": format!("/spec/disks/{key}/evictionRequested"), "value": true},
    ])
    .to_string()
}

/// Step 2: drop the entry.
pub fn remove_patch(key: &str) -> String {
    json!([{"op": "remove", "path": format!("/spec/disks/{key}")}]).to_string()
}

/// Step 3: re-add the same path under a NEW key. Re-adding under the old
/// name collides with the entry the webhook is still syncing.
pub fn readd_patch(new_key: &str, storage_reserved: u64) -> String {
    json!([{
        "op": "add",
        "path": format!("/spec/disks/{new_key}"),
        "value": {
            "path": DISK_PATH,
            "allowScheduling": true,
            "diskType": "filesystem",
            "storageReserved": storage_reserved,
            "tags": [],
        },
    }])
    .to_string()
}

/// The key for a re-added disk: unique per attempt, sortable, and the same
/// shape the hand procedure used, so a fleet keeps one naming convention.
pub fn new_disk_key(now_secs: u64) -> String {
    format!("disk-{now_secs}")
}

/// Longhorn's webhook refuses a patch while it is still reconciling the
/// previous one; that is a retry, not a failure.
pub fn is_syncing_error(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("syncing") || s.contains("being processed") || s.contains("conflict")
}

/// Names of the Replica records on `node` — every one of which is gone once the
/// roll has destroyed that node, because its storage disk is deleted with it.
///
/// They are not just stale; they are actively harmful (bug-201, third form).
/// For a DETACHED volume nothing ever marks them failed, so they sit at
/// `desire=running, state=stopped` and Longhorn waits for them before it will
/// start the engine. On 2026-10-23 two of them stopped garmin-sync-state from
/// attaching at all (`DeadlineExceeded`), and they had to be deleted by hand.
pub fn replicas_on_node(replicas: &Value, node: &str) -> Vec<String> {
    replicas
        .get("items")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| {
            items
                .iter()
                .filter(|r| r.pointer("/spec/nodeID").and_then(Value::as_str) == Some(node))
                .filter_map(|r| r.pointer("/metadata/name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
}

/// Names of the `volumeattachments.storage.k8s.io` pinning volumes to a
/// node (bug-170). Deleting them after the node is gone lets the CSI
/// attacher unpublish immediately instead of waiting six minutes for a
/// kubelet that no longer exists to confirm the unmount.
pub fn attachments_on_node(attachments: &Value, node: &str) -> Vec<String> {
    attachments
        .get("items")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| {
            items
                .iter()
                .filter(|va| va.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node))
                .filter_map(|va| va.pointer("/metadata/name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
}

/// When Longhorn last saw this node become Ready, if it is Ready now.
///
/// Longhorn keeps a node's disk status after the Kubernetes node is gone: on
/// 2026-10-23 s2-vm1 was mid-reinstall, its Node object deleted, and its OLD
/// disk still read `Ready=True` under the old UUID, while the node itself read
/// `Ready=False, KubernetesNodeGone`. A disk's own condition is therefore not
/// evidence on its own; the node's is the first thing to ask.
fn node_ready_since(node: &Value) -> Option<&str> {
    node.pointer("/status/conditions")
        .and_then(Value::as_array)?
        .iter()
        .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
        .filter(|c| c.get("status").and_then(Value::as_str) == Some("True"))
        .and_then(|c| c.get("lastTransitionTime").and_then(Value::as_str))
}

/// When this disk's Ready condition last became True, if it is True.
fn disk_ready_since(d: &Value) -> Option<&str> {
    d.get("conditions")
        .and_then(Value::as_array)?
        .iter()
        .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
        .filter(|c| c.get("status").and_then(Value::as_str) == Some("True"))
        .and_then(|c| c.get("lastTransitionTime").and_then(Value::as_str))
}

/// The disk was admitted AFTER the node last came back (bug-202).
///
/// `disk_admitted` alone is fooled by a status Longhorn never cleared: a node
/// that rejoins after a roll can briefly show its DESTROYED disk's old
/// `Ready=True`, which reads as "already admitted" and skips the re-admit the
/// new disk needs. A Ready that predates the node's own return is a leftover,
/// not a verdict. Both timestamps are Longhorn's own RFC 3339 strings, so the
/// comparison is on one clock.
pub fn disk_admitted_since_return(node: &Value) -> bool {
    let Some(back) = node_ready_since(node) else {
        return false;
    };
    disk_admitted(node)
        && node
            .pointer("/status/diskStatus")
            .and_then(Value::as_object)
            .is_some_and(|disks| {
                disks
                    .values()
                    .any(|d| disk_ready_since(d).is_some_and(|t| t >= back))
            })
}

/// A `diskStatus` entry whose Ready condition is True.
fn disk_is_ready(d: &Value) -> bool {
    d.get("conditions")
        .and_then(Value::as_array)
        .is_some_and(|cs| {
            cs.iter().any(|c| {
                c.get("type").and_then(Value::as_str) == Some("Ready")
                    && c.get("status").and_then(Value::as_str) == Some("True")
            })
        })
}

/// Volumes that would have NO healthy replica left once `dead` is
/// destroyed (bug-158). Attached or detached makes no difference —
/// exempting detached volumes is exactly how garmin-sync-state eroded to
/// zero replicas across four same-name replacements. Sorted for stable
/// messages.
///
/// A replica counts as surviving only when it has never failed, lives on
/// another node, AND sits on a disk that node currently reports Ready under
/// the same UUID the replica records (bug-201).
///
/// That last condition is the one the first version lacked, and it is not a
/// refinement. A roll deletes a node's storage disk and gives it a new one, so
/// every replica that was on it is gone — but for a DETACHED volume Longhorn
/// does not find out until the volume next attaches. Until then its Replica
/// record still reads `stopped`, with no `failedAt`. On 2026-10-23
/// garmin-sync-state's replica on a just-rolled s1-vm2 read exactly that, and
/// this function counted it, so the guard would have let the roll destroy
/// s1-vm3 — the only copy that still existed. The Replica record describes
/// what Longhorn last knew about a disk; `diskStatus` describes the disk that
/// is there now. Only the second is evidence.
///
/// `lh_nodes` is `nodes.longhorn.io` — Longhorn's nodes, not Kubernetes'.
pub fn volumes_without_surviving_replica(
    replicas: &Value,
    lh_nodes: &Value,
    dead: &str,
) -> Vec<String> {
    use std::collections::BTreeMap;
    let ready_disks = live_disks(lh_nodes);
    let mut survivors: BTreeMap<String, usize> = BTreeMap::new();
    for r in replicas
        .get("items")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        let Some(volume) = r
            .pointer("/metadata/labels/longhornvolume")
            .and_then(Value::as_str)
            .or_else(|| r.pointer("/spec/volumeName").and_then(Value::as_str))
        else {
            continue;
        };
        let entry = survivors.entry(volume.to_string()).or_insert(0);
        let node = r
            .pointer("/spec/nodeID")
            .and_then(Value::as_str)
            .unwrap_or("");
        if node != dead && replica_is_live(r, &ready_disks) {
            *entry += 1;
        }
    }
    survivors
        .into_iter()
        .filter(|(_, n)| *n == 0)
        .map(|(v, _)| v)
        .collect()
}

/// Node name -> the UUIDs of its disks that are live: Ready, on a node
/// Longhorn sees as Ready. The evidence every "is this a real copy?" question
/// in this crate is answered from.
pub fn live_disks(
    lh_nodes: &Value,
) -> std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> {
    lh_nodes
        .get("items")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        // A node Longhorn does not see as Ready contributes no live disks,
        // whatever its disks' own leftover conditions say.
        .filter(|n| node_ready_since(n).is_some())
        .map(|n| {
            let name = n
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let uuids = n
                .pointer("/status/diskStatus")
                .and_then(Value::as_object)
                .map(|disks| {
                    disks
                        .values()
                        .filter(|d| disk_is_ready(d))
                        .filter_map(|d| d.get("diskUUID").and_then(Value::as_str))
                        .collect()
                })
                .unwrap_or_default();
            (name, uuids)
        })
        .collect()
}

/// A replica that is a real copy: never failed, has completed a rebuild at
/// least once (`healthyAt` — a replica still building is not a copy yet), and
/// sits on a live disk under the UUID it records (bug-201: a record left on a
/// disk the roll destroyed still reads `stopped` with no `failedAt`).
pub fn replica_is_live(
    r: &Value,
    live: &std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>>,
) -> bool {
    let failed = r
        .pointer("/spec/failedAt")
        .and_then(Value::as_str)
        .is_some_and(|f| !f.is_empty());
    let built = r
        .pointer("/spec/healthyAt")
        .and_then(Value::as_str)
        .is_some_and(|h| !h.is_empty());
    let node = r
        .pointer("/spec/nodeID")
        .and_then(Value::as_str)
        .unwrap_or("");
    let on_live_disk = r
        .pointer("/spec/diskID")
        .and_then(Value::as_str)
        .is_some_and(|id| live.get(node).is_some_and(|u| u.contains(id)));
    !failed && built && on_live_disk
}

#[cfg(test)]
// Capitals in test names are deliberate emphasis on the thing that must not
// regress — the convention tests/posture.rs already allows.
#[allow(non_snake_case)]
mod tests {
    use super::*;

    fn node(disks: Value, status: Value) -> Value {
        json!({"spec": {"disks": disks}, "status": {"diskStatus": status}})
    }

    fn stale_status() -> Value {
        json!({"default-disk": {"conditions": [
            {"type": "Ready", "status": "False",
             "message": "Disk default-disk(/usr/local/longhorn) on node s1-vm1 is not ready: record diskUUID doesn't match the one on the disk"},
            {"type": "Schedulable", "status": "False"}
        ]}})
    }

    #[test]
    fn stale_disk_reads_key_and_reserved_verbatim() {
        let n = node(
            json!({"disk-1789399045": {"path": DISK_PATH, "storageReserved": 12884901888u64}}),
            stale_status(),
        );
        assert_eq!(
            stale_disk(&n),
            Some(StaleDisk {
                key: "disk-1789399045".into(),
                storage_reserved: 12_884_901_888
            })
        );
    }

    #[test]
    fn healthy_disk_is_not_stale() {
        let n = node(
            json!({"default-disk": {"path": DISK_PATH, "storageReserved": 1}}),
            json!({"default-disk": {"conditions": [
                {"type": "Ready", "status": "True"}, {"type": "Schedulable", "status": "True"}]}}),
        );
        assert_eq!(stale_disk(&n), None);
        assert!(disk_admitted(&n));
        assert!(has_disk_status(&n));
    }

    #[test]
    fn stale_disk_needs_a_spec_entry() {
        assert_eq!(stale_disk(&node(json!({}), stale_status())), None);
        assert!(!disk_admitted(&node(json!({}), stale_status())));
        assert!(!has_disk_status(&node(json!({}), json!({}))));
    }

    #[test]
    fn patches_are_the_hand_procedure() {
        assert_eq!(
            evict_patch("default-disk"),
            r#"[{"op":"replace","path":"/spec/disks/default-disk/allowScheduling","value":false},{"op":"add","path":"/spec/disks/default-disk/evictionRequested","value":true}]"#
        );
        assert_eq!(
            remove_patch("default-disk"),
            r#"[{"op":"remove","path":"/spec/disks/default-disk"}]"#
        );
        let p = readd_patch("disk-1789601830", 12_884_901_888);
        let v: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v[0]["path"], "/spec/disks/disk-1789601830");
        assert_eq!(v[0]["value"]["storageReserved"], 12_884_901_888u64);
        assert_eq!(v[0]["value"]["path"], DISK_PATH);
        assert_eq!(v[0]["value"]["allowScheduling"], true);
        assert_eq!(new_disk_key(1_789_601_830), "disk-1789601830");
    }

    #[test]
    fn syncing_is_a_retry() {
        assert!(is_syncing_error(
            "admission webhook denied: disk default-disk is still syncing"
        ));
        assert!(is_syncing_error(
            "Operation cannot be fulfilled: the object has been modified; Conflict"
        ));
        assert!(!is_syncing_error("nodes.longhorn.io \"s9-vm9\" not found"));
    }

    #[test]
    fn attachments_only_for_the_dead_node() {
        let vas = json!({"items": [
            {"metadata": {"name": "csi-aaa"}, "spec": {"nodeName": "s1-vm1"}},
            {"metadata": {"name": "csi-bbb"}, "spec": {"nodeName": "s1-vm2"}},
            {"metadata": {"name": "csi-ccc"}, "spec": {"nodeName": "s1-vm1"}},
        ]});
        assert_eq!(
            attachments_on_node(&vas, "s1-vm1"),
            vec!["csi-aaa", "csi-ccc"]
        );
        assert!(attachments_on_node(&vas, "s2-vm2").is_empty());
        assert!(attachments_on_node(&json!({}), "s1-vm1").is_empty());
    }

    /// A replica on `node`'s disk, which in these fixtures is `uuid-<node>`.
    fn replica(volume: &str, node: &str, failed_at: &str) -> Value {
        replica_on(volume, node, failed_at, &format!("uuid-{node}"))
    }

    fn replica_on(volume: &str, node: &str, failed_at: &str, disk: &str) -> Value {
        json!({"metadata": {"labels": {"longhornvolume": volume}},
               "spec": {"nodeID": node, "failedAt": failed_at, "diskID": disk,
                        "healthyAt": "2026-10-24T01:00:00Z"}})
    }

    /// Longhorn's nodes, each with one disk `uuid-<node>`; `not_ready` lists the
    /// nodes whose disk is reporting itself not Ready.
    fn lh_nodes(names: &[&str], not_ready: &[&str]) -> Value {
        let items: Vec<Value> = names
            .iter()
            .map(|n| {
                let ready = if not_ready.contains(n) {
                    "False"
                } else {
                    "True"
                };
                json!({"metadata": {"name": n}, "status": {
                    "conditions": [{"type": "Ready", "status": "True", "lastTransitionTime": "2026-10-24T01:00:00Z"}],
                    "diskStatus": {"disk-1": {
                        "diskUUID": format!("uuid-{n}"),
                        "conditions": [{"type": "Ready", "status": ready}]}}}})
            })
            .collect();
        json!({ "items": items })
    }

    const FLEET: &[&str] = &["s1-vm1", "s1-vm2", "s1-vm3", "s2-vm1", "s2-vm2"];

    #[test]
    fn three_healthy_replicas_survive_any_node() {
        let rs = json!({"items": [
            replica("pvc-a", "s1-vm1", ""), replica("pvc-a", "s1-vm2", ""), replica("pvc-a", "s1-vm3", "")]});
        assert!(volumes_without_surviving_replica(&rs, &lh_nodes(FLEET, &[]), "s1-vm1").is_empty());
    }

    /// bug-201, as found: the replica on a just-rolled node still reads as not
    /// failed, but its node's disk is the new, not-yet-admitted one. It is not
    /// a copy, so destroying the node holding the only real one is refused.
    #[test]
    fn a_replica_on_a_disk_that_is_not_Ready_does_not_survive() {
        let rs = json!({"items": [
            replica("pvc-garmin", "s1-vm2", ""), replica("pvc-garmin", "s1-vm3", "")]});
        assert_eq!(
            volumes_without_surviving_replica(&rs, &lh_nodes(FLEET, &["s1-vm2"]), "s1-vm3"),
            vec!["pvc-garmin"]
        );
    }

    /// The same replica after its node's disk was re-admitted: the node is
    /// Ready again, but under a NEW disk UUID. The record points at the old one.
    #[test]
    fn a_replica_recorded_against_a_replaced_disk_does_not_survive() {
        let rs = json!({"items": [
            replica_on("pvc-garmin", "s1-vm2", "", "uuid-of-the-deleted-disk"),
            replica("pvc-garmin", "s1-vm3", "")]});
        assert_eq!(
            volumes_without_surviving_replica(&rs, &lh_nodes(FLEET, &[]), "s1-vm3"),
            vec!["pvc-garmin"]
        );
    }

    /// The s2-vm1 shape: the node is gone (`KubernetesNodeGone`) but its old
    /// disk still reads Ready under the old UUID. Not a copy.
    #[test]
    fn a_replica_on_a_GONE_node_does_not_survive_even_if_its_disk_reads_Ready() {
        let mut nodes = lh_nodes(FLEET, &[]);
        nodes["items"][4]["status"]["conditions"] =
            json!([{"type": "Ready", "status": "False", "reason": "KubernetesNodeGone"}]);
        let rs = json!({"items": [
            replica("pvc-garmin", "s2-vm2", ""), replica("pvc-garmin", "s1-vm3", "")]});
        assert_eq!(
            volumes_without_surviving_replica(&rs, &nodes, "s1-vm3"),
            vec!["pvc-garmin"]
        );
    }

    fn rejoined(node_back: &str, disk_ready: &str) -> Value {
        json!({"status": {
            "conditions": [{"type": "Ready", "status": "True", "lastTransitionTime": node_back}],
            "diskStatus": {"disk-1": {"diskUUID": "u", "conditions": [
                {"type": "Ready", "status": "True", "lastTransitionTime": disk_ready},
                {"type": "Schedulable", "status": "True", "lastTransitionTime": disk_ready}]}}}})
    }

    /// bug-202: a Ready left over from the destroyed disk is not a verdict.
    #[test]
    fn a_disk_Ready_from_BEFORE_the_node_returned_is_not_admitted() {
        let n = rejoined("2026-10-24T01:20:00Z", "2026-09-16T23:10:00Z");
        assert!(
            disk_admitted(&n),
            "the old helper is fooled — that is the bug"
        );
        assert!(!disk_admitted_since_return(&n));
    }

    #[test]
    fn a_disk_Ready_after_the_node_returned_is_admitted() {
        assert!(disk_admitted_since_return(&rejoined(
            "2026-10-24T01:20:00Z",
            "2026-10-24T01:22:30Z"
        )));
    }

    /// A replica still rebuilding has never been healthy: not a copy yet.
    #[test]
    fn a_replica_that_has_never_finished_building_does_not_survive() {
        let mut building = replica("pvc-a", "s2-vm1", "");
        building["spec"]["healthyAt"] = json!("");
        let rs = json!({"items": [building, replica("pvc-a", "s1-vm1", "")]});
        assert_eq!(
            volumes_without_surviving_replica(&rs, &lh_nodes(FLEET, &[]), "s1-vm1"),
            vec!["pvc-a"]
        );
    }

    #[test]
    fn only_the_destroyed_nodes_replica_records_are_named() {
        let rs = json!({"items": [
            {"metadata": {"name": "pvc-a-r-1"}, "spec": {"nodeID": "s1-vm3"}},
            {"metadata": {"name": "pvc-a-r-2"}, "spec": {"nodeID": "s2-vm2"}},
            {"metadata": {"name": "pvc-b-r-1"}, "spec": {"nodeID": "s1-vm3"}}]});
        assert_eq!(
            replicas_on_node(&rs, "s1-vm3"),
            vec!["pvc-a-r-1", "pvc-b-r-1"]
        );
        assert!(replicas_on_node(&rs, "s1-vm1").is_empty());
        assert!(replicas_on_node(&json!({}), "s1-vm3").is_empty());
    }

    /// No Longhorn node data means no evidence any disk is live: refuse.
    #[test]
    fn without_longhorn_node_data_nothing_survives() {
        let rs = json!({"items": [replica("pvc-a", "s1-vm1", ""), replica("pvc-a", "s2-vm1", "")]});
        assert_eq!(
            volumes_without_surviving_replica(&rs, &json!({}), "s1-vm1"),
            vec!["pvc-a"]
        );
    }

    #[test]
    fn the_bug_158_shape_is_refused() {
        // garmin-sync-state, eroded to one replica on the node about to die;
        // a failed record elsewhere does not count.
        let rs = json!({"items": [
            replica("pvc-garmin", "s2-vm1", ""),
            replica("pvc-garmin", "s1-vm3", "2026-09-14T13:00:00Z"),
            replica("pvc-b", "s1-vm1", ""), replica("pvc-b", "s2-vm1", "")]});
        assert_eq!(
            volumes_without_surviving_replica(&rs, &lh_nodes(FLEET, &[]), "s2-vm1"),
            vec!["pvc-garmin"]
        );
        assert!(volumes_without_surviving_replica(&rs, &lh_nodes(FLEET, &[]), "s1-vm1").is_empty());
    }
}
