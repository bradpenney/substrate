//! Replay tests/golden/gate_logic.json — a corpus GENERATED from gate.py —
//! against the Rust decision functions. Every case is CPython's actual answer,
//! never a hand-written expectation; see gen_gate_goldens.py for why.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use substrate_core::gate::logic::*;

fn corpus() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/gate_logic.json"
    );
    let text = std::fs::read_to_string(path).expect("run tests/golden/gen_gate_goldens.py first");
    serde_json::from_str::<Value>(&text).unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}

fn str_map(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, x)| (k.clone(), x.as_str().unwrap().to_string()))
        .collect()
}
fn int_map(v: &Value) -> BTreeMap<String, i64> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, x)| (k.clone(), x.as_i64().unwrap()))
        .collect()
}
fn str_vec(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn every_generated_case_matches_cpython() {
    let cases = corpus();
    assert!(
        cases.len() > 150,
        "corpus looks truncated: {} cases",
        cases.len()
    );
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut failures = Vec::new();

    for case in &cases {
        let fn_name = case["fn"].as_str().unwrap();
        let a = case["args"].as_array().unwrap();
        let expected = &case["expected"];
        seen.insert(fn_name.to_string());
        let got: Value = match fn_name {
            "parse_quantity_mib" => parse_quantity_mib(a[0].as_str().unwrap()).into(),
            "pod_memory_request_mib" => pod_memory_request_mib(&a[0]).into(),
            "pct0" => pct0(a[0].as_f64().unwrap()).into(),
            "py_repr_str" => py_repr_str(a[0].as_str().unwrap()).into(),
            "py_repr" => py_repr(&a[0]).into(),
            "unhealthy_in_namespace" => {
                serde_json::json!(unhealthy_in_namespace(a[0].as_str().unwrap(), &a[1], &a[2]))
            }
            "schedulable_pods_by_node" => serde_json::json!(
                schedulable_pods_by_node(&a[0])
                    .into_iter()
                    .map(|(n, c)| serde_json::json!([n, c]))
                    .collect::<Vec<_>>()
            ),
            "concentration_failures" => {
                let counts: Vec<(String, i64)> = a[0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_i64().unwrap()))
                    .collect();
                let prone: BTreeSet<String> = str_vec(&a[3]).into_iter().collect();
                serde_json::json!(concentration_failures(
                    &counts,
                    &str_map(&a[1]),
                    &str_vec(&a[2]),
                    &prone
                ))
            }
            "node_label_failures" => {
                serde_json::json!(node_label_failures(
                    &a[0],
                    &str_map(&a[1]),
                    a[2].as_str().unwrap()
                ))
            }
            "critical_pair_failures" => {
                serde_json::json!(critical_pair_failures(
                    &a[0],
                    &str_map(&a[1]),
                    CRITICAL_PAIRS
                ))
            }
            "pods_matching_names" => {
                let sel: Vec<(String, String)> = a[2]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|kv| {
                        (
                            kv[0].as_str().unwrap().to_string(),
                            kv[1].as_str().unwrap().to_string(),
                        )
                    })
                    .collect();
                let sel_ref: Vec<(&str, &str)> =
                    sel.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                serde_json::json!(
                    pods_matching(&a[0], a[1].as_str().unwrap(), &sel_ref)
                        .iter()
                        .map(|p| p["metadata"]["name"].as_str().unwrap())
                        .collect::<Vec<_>>()
                )
            }
            "survivability_budget" => {
                let b = survivability_budget(&a[0], &int_map(&a[1]), &str_map(&a[2]));
                serde_json::json!({
                    "workload": b.workload,
                    "room": b.room,
                    "pinned_by_host": b.pinned_by_host.iter().map(|(h, v)| (h.clone(), v.iter().map(|(n, m)| serde_json::json!([n, m])).collect::<Vec<_>>())).collect::<BTreeMap<_, _>>(),
                })
            }
            "survivability_failures" => {
                serde_json::json!(survivability_failures(
                    &a[0],
                    &int_map(&a[1]),
                    &str_map(&a[2])
                ))
            }
            "pinned_hypervisors" => serde_json::json!(pinned_hypervisors(&a[0], &str_map(&a[1]))),
            "fingerprint_differences" => {
                let problems = fingerprint_differences(
                    &a[0],
                    &a[1],
                    a[2].as_str().unwrap(),
                    a[3].as_str().unwrap(),
                );
                // Reproduce what compare_fingerprints prints, so the whole
                // stdout the Python captured is what is compared.
                let output = if problems.is_empty() {
                    format!(
                        "\n=== end states IDENTICAL between {} and {} ===\n",
                        a[2].as_str().unwrap(),
                        a[3].as_str().unwrap()
                    )
                } else {
                    format!(
                        "\n=== END STATES DIFFER between {} and {} ===\n{}\n",
                        a[2].as_str().unwrap(),
                        a[3].as_str().unwrap(),
                        problems.join("\n")
                    )
                };
                serde_json::json!({"same": problems.is_empty(), "output": output})
            }
            "etcd_members_from" => serde_json::json!(etcd_members_from(a[0].as_str().unwrap())),
            "expected_k0s_version" => {
                serde_json::json!(expected_k0s_version(a[0].as_str().unwrap()))
            }
            other => panic!("corpus names a function the port does not have: {other}"),
        };
        if &got != expected {
            failures.push(format!(
                "{fn_name}({})\n   python: {}\n   rust:   {}",
                serde_json::to_string(&case["args"])
                    .unwrap()
                    .chars()
                    .take(160)
                    .collect::<String>(),
                serde_json::to_string(expected).unwrap(),
                serde_json::to_string(&got).unwrap()
            ));
        }
    }
    // The corpus must cover every decision function, or a function could be
    // ported wrong and never replayed.
    for must in [
        "parse_quantity_mib",
        "pod_memory_request_mib",
        "pct0",
        "py_repr_str",
        "py_repr",
        "unhealthy_in_namespace",
        "schedulable_pods_by_node",
        "concentration_failures",
        "node_label_failures",
        "critical_pair_failures",
        "pods_matching_names",
        "survivability_budget",
        "survivability_failures",
        "pinned_hypervisors",
        "fingerprint_differences",
        "etcd_members_from",
        "expected_k0s_version",
    ] {
        assert!(seen.contains(must), "corpus has no cases for {must}");
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from CPython:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

/// bug-171: the gate's local kubectl must never inherit the operator's
/// current context. `brad` is read-only and forbidden `/healthz/etcd`.
#[test]
fn local_kubectl_always_breaks_glass() {
    let args = substrate_core::gate::local_kubectl_args(&["get", "--raw", "/healthz/etcd"]);
    assert_eq!(args[0], "--context=break-glass");
    assert_eq!(&args[1..], ["get", "--raw", "/healthz/etcd"]);
}
