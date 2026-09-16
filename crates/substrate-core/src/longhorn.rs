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

/// Volumes that would have NO healthy replica left once `dead` is
/// destroyed (bug-158). A replica counts as surviving when it has never
/// failed and lives elsewhere; attached or detached makes no difference —
/// exempting detached volumes is exactly how garmin-sync-state eroded to
/// zero replicas across four same-name replacements. Sorted for stable
/// messages.
pub fn volumes_without_surviving_replica(replicas: &Value, dead: &str) -> Vec<String> {
    use std::collections::BTreeMap;
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
        let failed = r
            .pointer("/spec/failedAt")
            .and_then(Value::as_str)
            .is_some_and(|f| !f.is_empty());
        let node = r
            .pointer("/spec/nodeID")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !failed && node != dead {
            *entry += 1;
        }
    }
    survivors
        .into_iter()
        .filter(|(_, n)| *n == 0)
        .map(|(v, _)| v)
        .collect()
}

#[cfg(test)]
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

    fn replica(volume: &str, node: &str, failed_at: &str) -> Value {
        json!({"metadata": {"labels": {"longhornvolume": volume}},
               "spec": {"nodeID": node, "failedAt": failed_at}})
    }

    #[test]
    fn three_healthy_replicas_survive_any_node() {
        let rs = json!({"items": [
            replica("pvc-a", "s1-vm1", ""), replica("pvc-a", "s1-vm2", ""), replica("pvc-a", "s1-vm3", "")]});
        assert!(volumes_without_surviving_replica(&rs, "s1-vm1").is_empty());
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
            volumes_without_surviving_replica(&rs, "s2-vm1"),
            vec!["pvc-garmin"]
        );
        assert!(volumes_without_surviving_replica(&rs, "s1-vm1").is_empty());
    }
}
