# Test suite

```
.venv/bin/python3 -m pytest tests/ -q                          # what CI runs
SUBSTRATE_SITE_FILE=$PWD/site.yml .venv/bin/python3 -m pytest tests/   # fixture-drift check
```

## Why there is a fixture site.yml

`site.yml` is gitignored (ADR-012) because it carries addresses, an admin
identity and credentials. A suite that needed it could not run in CI at all, and
committing the real one to make tests work would defeat the reason it is
ignored. `tests/fixtures/site.yml` mirrors the schema with entirely synthetic
values.

`conftest.py` sets `$SUBSTRATE_SITE_FILE` with **setdefault**, so an explicit
override wins: run the suite against the real config occasionally to confirm the
fixture has not drifted from the live schema. CI has no `site.yml`, so it always
gets the fixture.

`siteconfig.SITE_FILE` is resolved at *import* time, which is why the override
lives in `conftest.py` — pytest imports it before any test module.

## What is tested, and why each exists

| File | Guards |
|---|---|
| `test_cloud_config.py` | The Kairos traps, which all fail **silently**: `stages` vs `write_files`, unquoted octal permissions, `Name=` vs `Type=ether`, under-escaped regexes, secret file modes |
| `test_equivalence.py` | The two bootstrap implementations stay interchangeable — wraps `check_render.py` and `check_drift.py` so they run on every push |
| `test_readiness.py` | The readiness gate waits for a **full** DaemonSet rollout (ADR-080) |
| `test_deploy_payload.py` | Deploy payload modes, ownership, path safety, and stamped mtimes (ADR-078) |
| `test_systemd_units.py` | Static rules over shipped units — every one of them shipped as a real defect (ADR-077) |
| `test_hosts.py` | Topology logic: one bootstrap node, distinct addresses, peer reachability |

## The rule these tests came from

Every assertion here corresponds to a **logged, reproduced defect** — not a
hypothetical. `.wolf/buglog.json` in the notes repo is the specification. When a
bug is fixed, add the test that would have caught it; that is what stops this
suite from drifting into decoration.

The recurring shape worth internalising: *a check that confirms a thing exists is
not a check that it works.* `network-online.target` being reached does not mean
DNS resolves. An `OnFailure=` line in a file does not mean systemd honoured it.
Every existing pod being ready does not mean every expected pod exists. Each of
those passed a check and shipped a defect.

## Not covered here

Anything needing a live cluster: policy enforcement (`kubectl apply
--dry-run=server` against known-bad manifests), smoke (`gate.py verify`),
end-to-end (`gate.py rebuild` + `compare`), and resilience drills. Those belong
with the cluster, not in CI.
