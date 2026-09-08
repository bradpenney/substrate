"""The cloud-config each node archetype must receive, pinned to the byte.

WHY THESE EXIST
---------------
ADR-020 guaranteed correctness by writing the build twice — Python and Ansible —
and proving the two rendered byte-identical output. That guarantee has a hole:
**two implementations agreeing does not prove either is right.** They can agree
on a wrong answer, and `check_render.py` then reports "renderers agree".

That is not hypothetical. Both renderers hardcoded the cosign identity of a
PRIVATE config repository, and the equivalence check was green the whole time
because both were wrong in the same way. The golden files caught it on the day
they were introduced (ADR-094).

So the goldens are not a convenience. They cover the failure mode the dual
implementation structurally cannot see, and they are what lets Ansible be
removed without losing ground (ADR-093).

HOW THEY ARE KEPT HONEST
------------------------
- Rendered through `render-cloud-config.py`, a CLI, not by importing
  `provision`. The contract is the command, so a Rust renderer slots in without
  touching this file.
- Rendered against `tests/fixtures/site.yml`, forced — never the real config,
  which would write real addresses and a real key into a committed file.
- Regenerated only by running `tests/golden/regenerate.py` on purpose, which
  refuses to write a golden the two renderers disagree about.

Read the diff when one of these fails. A golden changing is either a deliberate
change to what a node is, or a bug — there is no third case.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "golden"))

import regenerate  # noqa: E402  pylint: disable=wrong-import-position

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


@pytest.mark.parametrize(
    "archetype", regenerate.ARCHETYPES, ids=lambda a: a["file"].removesuffix(".yaml")
)
def test_renderer_reproduces_the_golden(archetype, tmp_path):
    """The renderer must produce the committed bytes exactly.

    Byte equality, not a parsed comparison: the Kairos gotchas this repo has
    collected — unquoted octal in `stages`, `Name=` vs `Type=ether`, the
    16-space `pullSecret` indent — are all invisible to a YAML-level diff and
    all fail silently on the node.
    """
    stack: list[Path] = []
    try:
        site_file = regenerate.site_file_for(archetype, stack)
        rendered = regenerate.render_python(archetype, site_file)
    finally:
        for path in stack:
            path.unlink(missing_ok=True)

    golden = GOLDEN_DIR / archetype["file"]
    assert (
        golden.exists()
    ), f"{archetype['file']} is missing. Run tests/golden/regenerate.py"
    if golden.read_text() != rendered:
        (tmp_path / "rendered.yaml").write_text(rendered)
        pytest.fail(
            f"{archetype['file']} no longer matches the renderer.\n"
            f"  If this change is intended, run tests/golden/regenerate.py and "
            f"READ THE DIFF.\n"
            f"  diff {golden} {tmp_path / 'rendered.yaml'}"
        )


def test_goldens_carry_no_real_identity():
    """A committed rendered config must not leak the real estate.

    This is the check that would have caught the hardcoded cosign subject
    (ADR-094) at review time rather than by inspection. `substrate` is going
    public; a golden is a rendered node config, which is precisely the sort of
    file that quietly accumulates a real address or an org name.
    """
    forbidden = ("bradpenney", "penney", "192.168.", "substrate_config")
    offenders = []
    for path in sorted(GOLDEN_DIR.glob("*.yaml")):
        text = path.read_text()
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.name} contains {needle!r}")
    assert not offenders, (
        "golden files leak real identity into a repo that is going public:\n  "
        + "\n  ".join(offenders)
    )


def test_the_private_artifact_archetype_actually_renders_a_pull_secret():
    """Guard the guard.

    The committed fixture has an empty `ghcr_token`, so three of the four
    archetypes render NO pull secret. If the private-artifact variant silently
    stopped overriding it, that archetype would become a duplicate of `joiner`
    and its whole reason for existing — the 16-space `pullSecret` indent bug,
    which existed on this path only — would be covered by nothing while the
    suite stayed green.
    """
    private = GOLDEN_DIR / "joiner_private_artifact.yaml"
    plain = GOLDEN_DIR / "joiner.yaml"
    assert "pullSecret: ghcr-auth" in private.read_text()
    assert "pullSecret: ghcr-auth" not in plain.read_text()


def test_regenerate_refuses_when_the_renderers_disagree():
    """The generator must not capture a golden from one implementation alone.

    A golden written while the two renderers disagree records a guess. This
    asserts the refusal path exists and is wired to the comparison, so that
    when Ansible is removed the deletion is a deliberate act rather than a
    check that had quietly stopped running.
    """
    source = (GOLDEN_DIR / "regenerate.py").read_text()
    assert "if python_out != jinja_out:" in source
    assert "refusing to " in source


def test_render_cli_rejects_a_bootstrap_node_with_a_join_token():
    """The bootstrap node comes up alone and joins nothing.

    Accepting both would render a config that silently contradicts itself, and
    the node would come up looking fine.
    """
    repo = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [
            sys.executable,
            str(repo / "render-cloud-config.py"),
            "--name",
            "x",
            "--ip",
            "192.0.2.1",
            "--hypervisor",
            "hvA",
            "--bootstrap",
            "--join-token",
            "nope",
        ],
        capture_output=True,
        text=True,
        env=regenerate.env_for(str(regenerate.FIXTURE)),
        check=False,
    )
    assert proc.returncode == 2
    assert "mutually exclusive" in proc.stderr


# --------------------------------------------------------- the CLI contract
#
# The tests above drive `render-cloud-config.py` as a subprocess, which is the
# right seam for the goldens — it is what a Rust binary will replace. But
# coverage cannot see inside a subprocess, so the module reads 0% while being
# thoroughly exercised. These import it directly, which both fixes the
# attribution and tests the thing that actually matters about a CLI: its
# argument names. Those names are the contract a reimplementation must honour,
# so renaming one silently is a break worth failing on.


@pytest.fixture(name="cli")
def _cli():
    """Import the hyphenated CLI by path. Same pattern as posture-check."""
    import importlib.util

    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "render_cloud_config", repo / "render-cloud-config.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["render_cloud_config"] = module
    spec.loader.exec_module(module)
    return module


def test_cli_exposes_the_documented_options(cli):
    """Every field a node can override must be reachable from the command line.

    A renderer that cannot express a storage disk or a join token is not a
    drop-in for the one it replaces, and the gap would only show up at
    provisioning time.
    """
    options = {
        action.option_strings[0]
        for action in cli.build_parser()._actions  # pylint: disable=protected-access
        if action.option_strings
    }
    assert {
        "--name",
        "--ip",
        "--hypervisor",
        "--bootstrap",
        "--memory-mib",
        "--vcpu",
        "--storage-disk-gb",
        "--join-token",
    } <= options


def test_cli_renders_a_bootstrap_node(cli, capsys):
    """The happy path, in-process."""
    assert (
        cli.main(
            ["--name", "n1", "--ip", "192.0.2.50", "--hypervisor", "hvA", "--bootstrap"]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert out.startswith("#cloud-config\n")
    assert "hostname: n1\n" in out


def test_cli_output_has_no_trailing_blank_line(cli, capsys):
    """`print` would add a second newline and put every golden one byte out.

    Worth its own test: the failure is a single invisible character, and it
    would be attributed to the renderer rather than to the CLI wrapping it.
    """
    assert (
        cli.main(
            ["--name", "n1", "--ip", "192.0.2.50", "--hypervisor", "hvA", "--bootstrap"]
        )
        == 0
    )
    assert not capsys.readouterr().out.endswith("\n\n")


def test_cli_passes_the_join_token_through(cli, capsys):
    """A joining node's token must reach the rendered config verbatim."""
    assert (
        cli.main(
            [
                "--name",
                "n2",
                "--ip",
                "192.0.2.51",
                "--hypervisor",
                "hvB",
                "--join-token",
                "TOK99",
            ]
        )
        == 0
    )
    assert "TOK99" in capsys.readouterr().out


def test_cli_refuses_a_bootstrap_node_that_also_joins(cli, capsys):
    """In-process twin of the subprocess check, for the exit-code path."""
    code = cli.main(
        [
            "--name",
            "n1",
            "--ip",
            "192.0.2.50",
            "--hypervisor",
            "hvA",
            "--bootstrap",
            "--join-token",
            "t",
        ]
    )
    assert code == 2
    assert "mutually exclusive" in capsys.readouterr().err


# The Rust renderer is asserted RUST-NATIVELY, in
# `crates/substrate/tests/golden.rs`, against these same golden files and the
# same `archetypes.yaml`. It is deliberately not driven from here: a port whose
# only proof of correctness runs in the language being replaced is not finished,
# and `cargo test` has to stand on its own once Python goes (ADR-095).
