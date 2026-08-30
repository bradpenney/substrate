# substrate

[![tests](https://img.shields.io/github/actions/workflow/status/bradpenney/substrate/test.yaml?branch=main&label=tests&logo=pytest&logoColor=white)](https://github.com/bradpenney/substrate/actions/workflows/test.yaml)
[![logic coverage](https://raw.githubusercontent.com/bradpenney/substrate/badges/coverage.svg)](#what-is-tested)
[![pylint](https://img.shields.io/badge/pylint-10.00%2F10-brightgreen?logo=python&logoColor=white)](.pylintrc)
[![code style: black](https://img.shields.io/badge/code%20style-black-000000)](https://github.com/psf/black)
[![shellcheck](https://img.shields.io/badge/shellcheck-style%20clean-4EAA25?logo=gnubash&logoColor=white)](https://github.com/bradpenney/substrate/actions/workflows/test.yaml)
[![rebuild](https://img.shields.io/badge/destroy%20%26%20rebuild-verified%20both%20methods-success)](#the-gate)
[![SELinux](https://img.shields.io/badge/SELinux-enforcing-red)](#security-posture)
[![bump-kairos](https://img.shields.io/github/actions/workflow/status/bradpenney/substrate/bump-kairos.yaml?branch=main&label=kairos%20bump&logo=githubactions&logoColor=white)](https://github.com/bradpenney/substrate/actions/workflows/bump-kairos.yaml)
[![bump-flux-operator](https://img.shields.io/github/actions/workflow/status/bradpenney/substrate/bump-flux-operator.yaml?branch=main&label=flux%20bump&logo=flux&logoColor=white)](https://github.com/bradpenney/substrate/actions/workflows/bump-flux-operator.yaml)
[![k0s](https://img.shields.io/badge/k0s-1.36-0F1689?logo=kubernetes&logoColor=white)](https://k0sproject.io)
[![Kairos](https://img.shields.io/badge/Kairos-v4.2.0-6E4AFF)](https://kairos.io)
[![Flux](https://img.shields.io/badge/GitOps-Flux%20via%20OCI-5468FF?logo=flux&logoColor=white)](https://fluxcd.io)
[![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![Ansible](https://img.shields.io/badge/Ansible-core-EE0000?logo=ansible&logoColor=white)](https://ansible.com)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Provisions a five-node [k0s](https://k0sproject.io) cluster across two
bare-metal KVM hypervisors, from bare metal to a cluster Flux is already
reconciling — with no manual step in between.

The distinctive thing here is not the cluster. It is that the build is written
**twice**, in Python and in Ansible, and a test proves the two produce
byte-identical output.

## Why two implementations

The goal is a cluster that can be destroyed and rebuilt on demand, and *trusted*
afterwards. That guarantee is only as good as the thing checking it, so the
check is a second independent implementation rather than a second look at the
first one.

`ansible/check_render.py` renders the cloud-config both ways — bootstrap node,
joining node, and a node with a dedicated storage disk — and diffs them:

```
[ok ] bootstrap node (no token): byte-identical (10731 bytes)
[ok ] joining node (with token): byte-identical (10883 bytes)
[ok ] node WITH a Longhorn disk: byte-identical (11982 bytes)
cloud-config renderers agree
```

It earns its place regularly. It has caught a change landing in one
implementation and not the other, and a pre-existing divergence where the
Ansible path never rendered a bootstrap credential at all — a cluster that would
have come up unable to issue certificates or take backups, with everything
reporting healthy.

Run it as `.venv/bin/python3 ansible/check_render.py` — it needs the repo's own
virtualenv.

## The gate

`gate.py verify` asserts six things, chosen because each one has been silently
false at some point on a cluster that otherwise looked perfect:

```
[PASS] nodes Ready
[PASS] system pods healthy
[PASS] cluster DNS resolving          from inside a pod, not from a node
[PASS] flux reconciling
[PASS] api-server -> pod tunnel
[PASS] required secrets present       via the ExternalSecret, not the Secret
```

The recurring lesson behind every one of them: **a check that confirms a system
is running is not a check that it works.**

## Layout

| Path | |
|---|---|
| `provision.py` | the Python implementation — cloud-config, VM lifecycle, node join |
| `ansible/` | the Ansible implementation, plus the render-equality test |
| `gate.py` | destroy-and-rebuild verification |
| `hosts.py`, `siteconfig.py` | fleet definition, read from `site.yml` |
| `versions.yml` | every external artifact, pinned and checksummed |
| `deploy-cplb.py` | HAProxy + keepalived control-plane load balancer |
| `jit-admin.py` | time-boxed cluster-admin grants |
| `create-client-cert.py` | mint a scoped kubeconfig identity via the CSR API |
| `posture-check.py` | daily assertion of the cluster's security invariants |

## Configuration

Everything site-specific — addresses, hostnames, credentials, which machine
hosts what — lives in `site.yml`, which is **gitignored**. `site.example.yml` is
the committed template.

That split is deliberate: this repo is meant to be readable in public, and a
build repo should not double as a map of a private network. The companion repo
[`substrate_config`](https://github.com/bradpenney/substrate_config) holds what
runs *on* the cluster and stays private for the same reason.

```bash
cp site.example.yml site.yml     # then edit
python3 -m venv .venv && .venv/bin/pip install ansible-core
.venv/bin/python3 ansible/check_render.py
```

## Nothing is unpinned

`versions.yml` pins every external artifact by version **and checksum**. The tag
makes it readable; the checksum is what actually makes a rebuild months from now
install the same bytes. Two scheduled workflows watch upstream and open the bump
as a change to review, rather than letting `latest` decide.

## Security posture

Every control below is **asserted continuously**, not configured once.
`posture-check.py` runs on a timer and fails loudly if any of these stops being
true — 14 invariants at present. The distinction matters: most of the defects
found while building this were controls that were installed and *not working*.

| Control | How it is enforced |
|---|---|
| Pod Security Standards | Every namespace labelled; enforcement asserted, not assumed |
| Network policy | Default-deny in every namespace |
| Admission control | ValidatingAdmissionPolicy + CEL, `Deny` for authored namespaces |
| Cluster admin | No standing `system:masters`. A scoped read-only identity by default; writes are a time-boxed grant that expires on its own |
| Client certificates | Short-lived, and never bound to standing write access — Kubernetes has no revocation |
| Secrets at rest | Encrypted with an explicit provider config, not the default plaintext |
| API audit | Explicit audit policy, retained on disk |
| Supply chain | Config delivered as a signed OCI artifact; the signature is verified against a pinned OIDC identity, issuer **and** subject |
| Host OS | SELinux `enforcing` on both hypervisors — zero permissive domains, zero custom modules |
| Privilege on hosts | No standing `NOPASSWD`. Deployments escalate once, per host, and say so |
| Ingress | Origin locked so the public path cannot be bypassed |

### What is tested

| Layer | What it proves |
|---|---|
| `pytest` | Unit and **regression** tests — every one written against a defect that actually occurred |
| `shellcheck -S style` | The scripts that run as root on every hypervisor and drain cluster nodes |
| `check_render.py` | Both bootstrap implementations render byte-identical cloud-config |
| `ansible --syntax-check` | The second implementation still parses |
| `gate.py verify` | Six live checks against a real cluster |
| `gate.py rebuild` + `compare` | The whole thing, from nothing, both ways — end states compared field by field |

The test suite's specification is the bug log. When something breaks, the fix
ships with the test that would have caught it; tests written against imagined
failures become decoration, tests written against real ones do not.

**The coverage badge says "logic coverage" deliberately.** It measures lines
executed by `pytest`, which is not the same as how much of this system is
tested. `posture-check.py` reads 0% and runs nightly against a live cluster;
`gate.py` reads 18% and is exercised end to end by every rebuild; the static
rules over the systemd units contribute nothing to the number and catch defects
that shipped. Most of what is uncovered drives real hosts over ssh and kubectl,
where a unit test would assert only that the code calls the commands it calls.

Coverage is enforced **per module** rather than as one global number: 95% on the
logic modules, and the orchestration reported but not gated, because driving
`virsh` and `ssh` to 95% would mean stubbing a hypervisor and asserting that the
code calls the commands it calls. Logic sits at 99%.

### Lint and format

`pylint` is a **10.00/10 hard gate on the source**. Every disable in
`.pylintrc` is justified in place, and the rule applied throughout is that a
check is silenced only where the code is right and pylint's model of it is
wrong — anything it found that was a genuine defect was fixed rather than
suppressed. That included 45 `subprocess.run` calls given an explicit
`check=False`, three text files opened without an encoding, an unchained
`raise`, and a duplicate import.

Test files are deliberately **not** held to 10/10: pytest idioms — fixtures
shadowing names, tests exercising private helpers — would otherwise force
weakening the rules that apply to the code that runs in anger.

`black` owns formatting, including line length. Two tools disagreeing about the
same property means one must yield, and the formatter is the one that can
actually fix it.

**Every function and class in the source carries a multi-line docstring** — 103
of them, no one-liners. The house style is to say why the code is shaped the way
it is, not to restate its name.

## Design notes

Decisions are recorded as ADRs, including the ones that were wrong first time.
The ones most worth reading if you are doing something similar:

- **Two failure domains cannot survive losing one.** Five etcd members across
  two hypervisors is not a highly-available cluster, and saying so plainly is
  more useful than a diagram implying otherwise.
- **konnectivity needs one agent connection per server**, which a VRRP virtual
  IP does not provide — that is failover, not distribution. The fix was a real
  load balancer in front of the control plane.
- **On an immutable OS, permission syntax differs between `stages` and
  `write_files`**, and getting it backwards is a silent no-op rather than an
  error. The node comes up with no network and nothing in any log.

## Licence

MIT — see [LICENSE](LICENSE). Copy it, adapt it, run it. If any of it saves you
an evening, that is the whole point.
