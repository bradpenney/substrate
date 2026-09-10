# The Rust port

`provision.py` and its supporting modules are being replaced by one Rust binary.
The goal is not a Rust program that builds *a* cluster — it is one that builds
**the same cluster**, so the Python can be archived rather than kept as a
fallback nobody maintains.

Do **not** build hybrids. A Rust binary that shells out to Python, or Python
that shells out to Rust, is a dependency with extra steps. Cross-implementation
comparison belongs in the test suite as proof of equivalence before the cutover
— never in the product.

## Status

| area | Python | Rust | proven by |
|---|---|---|---|
| cloud-config render | `provision.py:render_cloud_config` | `render.rs` | goldens + all 10 live/respec nodes byte-identical |
| shell quoting | `shlex.join` | `exec.rs:shell_quote` | corpus GENERATED from CPython + real-shell round-trip |
| command execution | `run`, `write_file` | `exec.rs` | live, local + over SSH |
| libvirt inspection | 4 fns | `libvirt.rs` | live, identical for 5 VMs on both hypervisors |
| host prep | 4 fns | `provision.rs` | compiles; idempotent, not yet run |
| VM lifecycle | 4 fns | `provision.rs` | **compiles; NEVER EXECUTED** |
| join + readiness | 8 fns | `provision.rs` | **compiles; NEVER EXECUTED** |
| client access | 1 fn | `provision.rs` | **compiles; NEVER EXECUTED** |
| orchestration | `main`, `plan` | `provision_fleet`, `plan` | dry-run byte-identical on both fleets |

**The write path has never run.** That is inherent — this project's test policy
is that orchestration is "covered by the rebuild, not mocked" — and it is why
the next rebuild is the real milestone, not a test run.

## Running it

```bash
substrate provision            # plan only. THE DEFAULT.
substrate provision --apply    # actually build
```

`substrate provision` is **safe by default**; `provision.py` is not (it builds
unless given `--dry-run`). The Python default is kept for existing callers and
muscle memory; the Rust one is corrected because it is a new entry point with
nothing to break. This matches `deploy-cplb.py`: the dangerous thing is the one
you have to ask for.

Neither will run under `sudo` — both refuse with the reason, not the symptom.
They stage as the ordinary user over SSH and escalate once for the installer
(ADR-078); run as root they SSH as root, which has no key, and fail with a bare
`Permission denied (publickey)` long after the mistake was made.

## Verifying equivalence

```bash
# plan parity, live
diff <(.venv/bin/python provision.py --dry-run) <(./target/debug/substrate provision)

# render parity, one node
diff <(.venv/bin/python render-cloud-config.py --name s1-vm1 --ip 192.168.2.203 \
         --hypervisor server1 --join-token TESTTOKEN123abc) \
     <(./target/debug/substrate render --name s1-vm1 --ip 192.168.2.203 \
         --hypervisor server1 --join-token TESTTOKEN123abc)

# python vs jinja
.venv/bin/python ansible/check_render.py

# regenerate the shlex parity table after changing its corpus
.venv/bin/python tests/golden/gen_shlex_parity.py > \
    crates/substrate-core/tests/shlex_parity.rs
```

Point either implementation at a different fleet with `SUBSTRATE_SITE_FILE=`
(Python) or `--repo` (Rust). That is how the ADR-174 respec was verified before
any hardware changed.

## Traps worth not rediscovering

**`shell_quote` is the highest-risk function in the port.** Rust has no `shlex`.
Every remote command is built as an argv and stringified exactly once, at the
SSH boundary; a divergence there is invisible until an argument contains a
space, a quote or a newline — which is when it corrupts a command rather than
failing one. Its expectations are therefore generated from CPython, never
written by hand: a hand-written table proves only that the author's belief about
`shlex.quote` is self-consistent, and passes against a Rust version wrong in
exactly the way that belief is wrong.

**Behaviour is ported as written, not as documented.** `write_file`'s Python
docstring claims it creates parent directories; neither branch does. The Rust
reproduces the behaviour and documents the discrepancy. A fix smuggled into a
port cannot be reviewed as a fix.

**Join tokens must not go on argv.** `/proc/<pid>/cmdline` is world-readable and
a join token grants cluster membership. Use `$SUBSTRATE_JOIN_TOKEN`; the
`--join-token` flag exists for the dummy tokens in goldens and archetypes.

**Everything is data-driven from `site.yml`.** Adding, removing or resizing a
node needs no renderer change, no Ansible change, and no golden regeneration —
every node name in all three renderers and the whole Ansible tree is a comment,
the inventory is dynamic, and the goldens use synthetic fixtures on purpose.
What *does* need editing is any `nodeAffinity` in `substrate_config` that names
nodes; those now select on `invariant-platform.io/hypervisor` so a respec cannot
break them.

**Pin `-c qemu:///system` on every virsh call.** A session-scoped libvirt sees
none of the system domains, so an unpinned query reports "no such VM" about a
running node — and an unpinned create builds a second one beside it.
