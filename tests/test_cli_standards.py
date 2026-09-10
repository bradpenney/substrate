"""Every entry point must be safe to ASK about, and every writer previewable.

WHY THIS FILE EXISTS
On 2026-09-10 `deploy_updates.py --help` deployed to both hypervisors. It had
no argument parsing at all, so every argument — including the one universally
understood to mean "tell me what you do without doing it" — was silently
ignored. It stopped only because sudo happened to prompt for a password.

`provision.py` was the same, and worse: it creates VMs, mints join tokens and
rewrites the operator's kubeconfig.

Four more advertised

    exec$(cd $(dirname $0); pwd)/.venv/bin/python3-u$0$@

as their description, because the `"exec" "$(...)"` shebang trick is a run of
ADJACENT STRING LITERALS that Python concatenates into the module docstring —
so `__doc__` was a shell fragment.

These tests read the source rather than executing it: running the real thing
means provisioning a fleet or writing to two hypervisors.
"""

from __future__ import annotations

import ast
import os
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent

# Entry points: a module that runs something when executed directly.
ENTRY_POINTS = sorted(p for p in REPO.glob("*.py") if "__main__" in p.read_text())

# Tools that reach ANOTHER machine over SSH. Every one of them stages as the
# ordinary user and escalates remotely, so running the whole thing under local
# `sudo` makes it SSH as root — which has no key — and fail with an unhelpful
# "Permission denied (publickey)" after the first connection attempt.
SSH_TOOLS = {
    "provision.py",
    "deploy_updates.py",
    "deploy-observability.py",
    "deploy-cplb.py",
    "gate.py",
}

# The ones that change something outside this repository. A --dry-run on these
# is not a convenience; it is the only way to see what they would do without
# finding out.
WRITERS = {
    "provision.py",  # creates VMs, mints join tokens, rewrites kubeconfig
    "deploy_updates.py",  # writes to both hypervisors, enables timers
    "deploy-observability.py",  # writes units, dashboards and alert rules
    "deploy-cplb.py",  # writes the control-plane load balancer
    "gate.py",  # can DESTROY and rebuild the fleet
}


def _source(p: pathlib.Path) -> str:
    return p.read_text()


def test_every_entry_point_parses_its_arguments():
    """Without argparse, `--help` DOES the thing instead of describing it.

    That is not a style point. `deploy_updates.py --help` deployed to two
    hypervisors, and `provision.py --help` would have built a cluster.
    """
    missing = [p.name for p in ENTRY_POINTS if "argparse" not in _source(p)]
    assert not missing, (
        f"entry points with no argument parsing: {missing}. "
        "`--help` on these runs them."
    )


def test_every_entry_point_rejects_unknown_arguments():
    """argparse gives this for free — the test is that nothing bypasses it.

    A script reading `sys.argv` by hand can silently ignore a typo, which is
    how a mistyped flag becomes a deployment.
    """
    for p in ENTRY_POINTS:
        src = _source(p)
        if "parse_known_args" in src:
            raise AssertionError(
                f"{p.name} uses parse_known_args, which IGNORES unknown "
                "arguments — the behaviour this standard exists to prevent"
            )


def test_every_writer_can_be_previewed():
    """A tool that changes the fleet must be able to say what it would change.

    TWO ACCEPTABLE SHAPES, and the second is stronger:

      --dry-run   acts by default, previews on request
      --apply     PREVIEWS by default, acts on request

    `deploy-cplb.py` uses the second, and this test originally demanded the
    first — which would have pushed a safe-by-default tool toward a less safe
    convention in the name of consistency. The property being protected is
    "cannot change anything without an explicit signal", not a particular
    spelling.
    """
    missing = []
    for name in sorted(WRITERS):
        src = _source(REPO / name)
        if "--dry-run" not in src and '"--apply"' not in src:
            missing.append(name)
    assert not missing, (
        f"writers with no way to preview: {missing}. "
        "Add --dry-run, or make the tool preview by default and require --apply."
    )


def test_no_entry_point_derives_its_help_from___doc__():
    """`__doc__` is the SHELL FRAGMENT on any file using the exec-shebang trick.

    Adjacent string literals concatenate, so

        "exec" "$(cd $(dirname $0); pwd)/.venv/bin/python3" "-u" "$0" "$@"

    becomes the module docstring. Four operational tools advertised that as
    their purpose. Descriptions are explicit strings now, and this test keeps
    them that way rather than trusting each author to remember why.
    """
    offenders = []
    for p in ENTRY_POINTS:
        src = _source(p)
        # ONLY the exec-shebang files. On an ordinary module `__doc__` is the
        # real docstring and passing it is correct and idiomatic —
        # `jit-admin.py` does exactly that and its help reads properly. Banning
        # it everywhere would be a rule that punishes the right thing.
        uses_exec_trick = src.lstrip().startswith("#!/bin/sh") and '"exec"' in src
        if uses_exec_trick and "description=__doc__" in src:
            offenders.append(p.name)
    assert not offenders, (
        f"{offenders} pass __doc__ to argparse while using the exec-shebang "
        "trick, where __doc__ is a shell fragment. Use an explicit description."
    )


def test_the_dry_run_flag_is_spelled_consistently():
    """`--dry-run` everywhere, never --dryrun or --plan.

    An operator reaching for the safe flag under pressure should not have to
    remember which spelling this particular tool chose.
    """
    for name in sorted(WRITERS):
        src = _source(REPO / name)
        for wrong in ("--dryrun", "--dry_run", "--plan-only", "--noop"):
            assert wrong not in src, (
                f"{name} uses {wrong}; the spellings are --dry-run "
                "(acts by default) or --apply (previews by default)"
            )


def test_entry_points_are_syntactically_valid():
    """A cheap guard: this suite reads source, so a broken file must not pass
    silently by simply failing to contain the strings being looked for."""
    for p in ENTRY_POINTS:
        try:
            ast.parse(_source(p))
        except SyntaxError as e:
            raise AssertionError(f"{p.name} does not parse: {e}") from e


def test_every_ssh_tool_refuses_to_run_as_root():
    """The failure is understood, documented, and used to arrive as a symptom.

    On 2026-09-10 `sudo deploy_updates.py --dry-run` produced

        brad@192.168.2.200: Permission denied (publickey).

    which names the symptom, not the cause, and only after an SSH round trip.
    The docstring said "Do NOT run it under sudo" — in a file nobody reads at
    the moment of failure.
    """
    missing = [
        name
        for name in sorted(SSH_TOOLS)
        if "refuse_if_root" not in _source(REPO / name)
        and "geteuid" not in _source(REPO / name)
    ]
    assert not missing, (
        f"SSH tools with no root check: {missing}. Under sudo these fail with "
        "an unhelpful publickey error instead of saying what was done wrong."
    )


def test_the_root_check_immediately_follows_argument_parsing():
    """A refusal after the first SSH attempt is most of the delay and all of
    the confusion — it must be the first thing that happens.

    Checked as "within a few lines of parse_args", NOT as a byte offset. The
    first version of this test compared the position of the check against the
    first occurrence of `"ssh"` in the file, and failed on deploy-cplb.py —
    which DEFINES its ssh helpers above main(). A definition is not an
    execution, and a test that cannot tell them apart is asserting something
    other than the property it claims.
    """
    for name in sorted(SSH_TOOLS):
        src = _source(REPO / name)
        if "refuse_if_root" not in src:
            continue  # deploy-observability.py inlines the check; covered above
        lines = src.splitlines()
        parse_at = [i for i, l in enumerate(lines) if "parse_args(" in l]
        check_at = [i for i, l in enumerate(lines) if "refuse_if_root(" in l]
        assert parse_at and check_at, f"{name}: expected both parse_args and the check"
        # The check must sit close after SOME parse_args call.
        assert any(0 < c - pa <= 8 for pa in parse_at for c in check_at), (
            f"{name}: the root check is not adjacent to argument parsing; "
            "it must run before anything reaches the network"
        )


def test_the_root_check_message_names_the_fix_not_just_the_problem():
    """ "Do not run as root" without "run it like THIS" leaves the reader where
    they started."""
    import siteconfig

    old = os.geteuid
    try:
        os.geteuid = lambda: 0
        try:
            siteconfig.refuse_if_root("./the-tool")
            raise AssertionError("refuse_if_root did not refuse")
        except SystemExit as e:
            msg = str(e)
    finally:
        os.geteuid = old

    assert "sudo" in msg, "must say what was done wrong"
    assert "./the-tool" in msg, "must say how to run it correctly"
    assert "publickey" in msg, "must connect the refusal to the error they saw"
