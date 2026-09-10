#!/usr/bin/env python3
"""Generate the Rust shlex-parity test FROM CPython's own shlex.

Run from the repo root:

    .venv/bin/python tests/golden/gen_shlex_parity.py > \
        crates/substrate-core/tests/shlex_parity.rs

Why generated: the Rust provisioner has to hand a remote shell byte-for-byte
the same string `provision.py` does. Hand-written expectations would only prove
the author's belief about `shlex.quote` is self-consistent — they would pass
against a Rust implementation wrong in exactly the way the belief is wrong.

Add awkward arguments to CASES as they turn up in real commands. Anything that
has ever needed quoting in anger belongs here.
"""

from __future__ import annotations

import shlex

CASES = [
    "", "simple", "with space", "it's", "a'b'c", 'dq"uote', "new\nline", "tab\there",
    "semi;colon", "pipe|x", "amp&x", "dollar$X", "back`tick`", "star*", "q?", "br[a]",
    "brace{a}", "paren(a)", "lt<gt>", "tilde~", "hash#", "bang!", "back\\slash",
    "safe_@%+=:,./-", "192.168.2.203", "s1-vm1", "--join-token", "TESTTOKEN123abc",
    "/var/lib/k0s/manifests", "unicode-é", "trailing ", " leading", "'", "''", "\\'",
]


def rs(s: str) -> str:
    """A Rust string literal. Python's repr is single-quoted and not valid Rust."""
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + out.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r") + '"'


def main() -> None:
    print(HEADER)
    print("/// (input, what CPython's shlex.quote returns)")
    print("const CASES: &[(&str, &str)] = &[")
    for c in CASES:
        print(f"    ({rs(c)}, {rs(shlex.quote(c))}),")
    print("];\n")
    print(BODY.replace("__JOINED__", rs(shlex.join(CASES))))


HEADER = '''//! Byte-for-byte parity with CPython's `shlex` at the SSH boundary.
//!
//! GENERATED — do not hand-edit. Regenerate with:
//!
//! ```text
//! .venv/bin/python tests/golden/gen_shlex_parity.py > \\
//!     crates/substrate-core/tests/shlex_parity.rs
//! ```
//!
//! `provision.py` builds every remote command as an argv and stringifies
//! exactly once, at the SSH boundary, via `shlex.join`. The Rust provisioner
//! must hand the remote shell the SAME string. A divergence is invisible until
//! an argument carries a space, a quote or a newline — which is when it
//! corrupts a command rather than failing one.

use substrate_core::exec::{shell_join, shell_quote};
'''

BODY = '''#[test]
fn shell_quote_matches_cpython_shlex() {
    for (input, expected) in CASES {
        assert_eq!(
            &shell_quote(input),
            expected,
            "shell_quote({input:?}) diverged from CPython shlex.quote"
        );
    }
}

#[test]
fn shell_join_matches_cpython_shlex() {
    let argv: Vec<&str> = CASES.iter().map(|(i, _)| *i).collect();
    assert_eq!(shell_join(&argv), __JOINED__);
}

#[test]
fn a_quoted_argument_survives_a_real_shell_round_trip() {
    // The parity table proves we match Python. This proves Python's rule is
    // actually right — that `sh -c` gives the argument back unchanged. Without
    // it, both implementations could agree on a quoting no shell honours.
    for (input, _) in CASES {
        if input.contains('\\n') || input.is_empty() {
            continue; // command substitution strips trailing newlines
        }
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", shell_quote(input)))
            .output()
            .expect("sh must be available");
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            *input,
            "a real shell did not return {input:?} unchanged"
        );
    }
}'''


if __name__ == "__main__":
    main()
