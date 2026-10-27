//! The one place a YAML library is named.
//!
//! Everything in substrate that reads or writes YAML goes through here, so the
//! choice of library is one decision in one file. It was made twice before by
//! accident: `serde_yaml` (archived 2024), then `serde_yaml_ng`, which kept the
//! API and the problem — both parse through `unsafe-libyaml`, a machine
//! translation of libyaml's C into unsafe Rust that nobody maintains
//! (RUSTSEC-2024-0449). v0.2.11's first release build stopped on that advisory.
//!
//! **Parsing and writing:** `serde-saphyr`, written in safe Rust.
//!
//! **Untyped YAML** is held as [`serde_json::Value`]. serde-saphyr deliberately
//! has no YAML value tree of its own — it deserializes straight into Rust types
//! — and supports `serde_json::Value` for the cases that need one. Substrate
//! needs one for exactly two jobs: merging `versions.yml` into a raw `site.yml`
//! before it is typed, and editing a kubeconfig without knowing every field.
//! JSON's data model covers both: no YAML tags, anchors or non-string keys
//! appear in anything substrate reads.
//!
//! **Booleans are strict.** Parsed into an untyped value, YAML 1.1 would turn an
//! unquoted `yes`, `no`, `on` or `off` into a boolean. serde_yaml_ng followed
//! YAML 1.2, where they stay strings, and a configuration that meant the string
//! `"on"` must not silently become `true` because the parser changed. Only
//! `true` and `false` are booleans here.

use anyhow::Result;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A YAML mapping with string keys, held in key order.
pub use serde_json::Map as Mapping;
/// Untyped YAML. A mapping is a [`Mapping`]; a sequence is `Value::Array`.
pub use serde_json::Value;

fn options() -> serde_saphyr::Options {
    let mut o = serde_saphyr::Options::default();
    o.strict_booleans = true;
    o
}

/// Parse YAML text into `T` — a typed config, or [`Value`] for untyped YAML.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T> {
    serde_saphyr::from_str_with_options(text, options()).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Type an untyped [`Value`] (one built or edited in memory).
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T> {
    Ok(serde_json::from_value(value)?)
}

/// Write `value` as YAML.
pub fn to_string<T: Serialize>(value: &T) -> Result<String> {
    serde_saphyr::to_string(value).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parity that matters most: YAML 1.1 words stay strings.
    #[test]
    fn yes_no_on_off_stay_strings() {
        let v: Value = from_str("a: yes\nb: no\nc: on\nd: off\ne: true\nf: false\n").unwrap();
        assert_eq!(v["a"], "yes");
        assert_eq!(v["b"], "no");
        assert_eq!(v["c"], "on");
        assert_eq!(v["d"], "off");
        assert_eq!(v["e"], true);
        assert_eq!(v["f"], false);
    }

    #[test]
    fn numbers_and_strings_keep_their_types() {
        let v: Value = from_str("port: 9100\nver: \"1.36\"\nsha: 0a1b\nratio: 0.5\n").unwrap();
        assert_eq!(v["port"], 9100);
        assert_eq!(v["ver"], "1.36");
        assert_eq!(v["sha"], "0a1b");
        assert_eq!(v["ratio"], 0.5);
    }

    #[test]
    fn a_round_trip_reads_back_the_same_value() {
        let v: Value =
            from_str("kind: Config\nusers:\n  - name: a\n    user: {token: x}\n").unwrap();
        let again: Value = from_str(&to_string(&v).unwrap()).unwrap();
        assert_eq!(v, again);
    }

    #[test]
    fn invalid_yaml_is_an_error_not_a_default() {
        assert!(from_str::<Value>("a: [unclosed").is_err());
    }
}
