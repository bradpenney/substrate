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
| wipe | `gate.py:wipe`, `orphaned_vms` | `wipe.rs` | dry-run byte-identical on the live fleet (incl. live virsh on both hosts) |
| rebuild | `gate.py:rebuild` (wipe→build) | `main.rs:rebuild` | **NEVER EXECUTED** — composes the two above |
| verify (10 criteria) | `gate.py:verify` | `gate/mod.rs` | live differential: identical except where the cluster healed mid-run |
| gate decisions | `gate.py` pure fns | `gate/logic.rs` | **188-case corpus GENERATED from CPython** (`gate_parity.rs`); 4 mutations caught |
| fingerprint / compare | `gate.py` | `gate/mod.rs` | JSON and compare output byte-identical live |
| roll | `gate.py:roll` | `gate/mod.rs:roll` | **NEVER EXECUTED** — composes ported primitives |

**The write path has never run.** That is inherent — this project's test policy
is that orchestration is "covered by the rebuild, not mocked" — and it is why
the next rebuild is the real milestone, not a test run.

## Running it

```bash
substrate provision            # plan only. THE DEFAULT.
substrate provision --apply    # build — or, on a live fleet, RECONCILE it
```

`--apply` against VMs that already exist reconciles them (autostart, running
state) and never calls `create_vm`. A rebuild needs a wipe first, and both
halves live in this binary — composed only in `rebuild`, so the build path
never destroys and the destroy path never builds:

```bash
substrate wipe                 # print every VM, disk volume and seed ISO that would go
substrate wipe --yes           # destroy them
substrate rebuild              # both previews
substrate rebuild --yes        # wipe, then provision. THE REBUILD.
```

Verification is in the same binary and reads only:

```bash
substrate verify                     # the 10 gate criteria; exit 0 = all held
substrate fingerprint --save rust    # comparable end state, saved for compare
substrate compare python rust        # .fingerprints/ is shared with the old gate.py
substrate roll [--yes] [--node N]    # one node at a time onto the pinned image
```

`gate.py` has nothing left that the binary does not do. It stays only until
the Python tree is archived (below). Do NOT add `rust` to its
`BOOTSTRAP_METHODS`: that was done once (2026-09-11) and reverted the same
day — a Rust build behind a Python wipe is the hybrid this file forbids.
Capture the application data first —
`substrate_config/scripts/pre_rebuild_snapshot.sh`, then rehearse the restore
with `restore_from_backup.sh <app> --rehearse`. A rebuild destroys every
Longhorn volume.

## Archiving the Python

Every Python entry point now has a Rust twin that has been proven against it.
What archival means, in order, and what each step must NOT break:

1. **`posture-check.timer` still runs `posture-check.py`.** Change
   `~/homelab/systemd/posture-check.service` `ExecStart=` to the release
   binary (`substrate posture-check`, from a path systemd may execute — NOT
   under /home, SELinux `user_home_t` gives 203/EXEC) on BOTH hypervisors.
   Watch one 07:30 run land green before step 2.
2. **`git mv` the Python into `archive/python/`** — `provision.py`, `gate.py`,
   `posture-check.py`, `deploy-*.py`, `render-cloud-config.py`, `siteconfig.py`,
   `hosts.py`, `ansible/`, `tests/`, `.venv` handling in `Makefile`/CI.
   Keep `tests/golden/*.py` generators: they are how the corpora are
   regenerated, and they import the archived modules by path.
3. **CI**: drop the pytest/pylint/black jobs, keep `cargo test`, `clippy`,
   `fmt`, and the golden regeneration check.
4. **README / anatomy / this file**: "Python" becomes history, not a path.

Not before the first Rust rebuild has passed. Archiving the reference
implementation before the port has built a cluster is the one order that
cannot be undone cheaply.

## Verifying equivalence

```bash
# plan parity, live
diff <(.venv/bin/python provision.py --dry-run) <(./target/debug/substrate provision)

# wipe parity, live (both print the exact volumes they would delete)
diff <(.venv/bin/python gate.py wipe --dry-run) <(./target/release/substrate wipe)

# gate parity, live — fingerprint is byte-for-byte; verify differs only where
# the cluster changed between the two runs (each takes minutes)
diff <(.venv/bin/python gate.py fingerprint) <(./target/release/substrate fingerprint)
diff <(.venv/bin/python gate.py verify) <(./target/release/substrate verify)

# regenerate the gate-logic corpus after changing gate.py's decisions
.venv/bin/python tests/golden/gen_gate_goldens.py

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
