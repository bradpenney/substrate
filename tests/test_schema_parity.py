"""The Python and Rust site.yml schemas must declare the same fields.

`site.yml` is parsed twice: by pydantic in `models.py` and by serde in
`crates/substrate-core/src/config.rs`. BOTH reject unknown fields. So a field
added to one and not the other does not degrade gracefully — it makes the
fleet's own configuration unparseable by half its tooling.

That happened twice in one evening. `failure_prone` was added to the Python
side and CI caught it, because the golden tests render the FIXTURE. Then
`observability.github_org` turned out to have been missing from the Rust schema
for some time and CI could NOT catch it, because the fixture never carried that
field and CI has no real site.yml to try.

This test needs neither file. It compares the two schemas directly, so it holds
in CI, and it fails on the mismatch itself rather than on a config that happens
to exercise it.
"""

import inspect
import re
from pathlib import Path

import pytest

import models

RUST_CONFIG = (
    Path(__file__).resolve().parent.parent
    / "crates"
    / "substrate-core"
    / "src"
    / "config.rs"
)


def _rust_structs() -> dict[str, set[str]]:
    """Struct name -> its field names, read from the serde definitions."""
    src = RUST_CONFIG.read_text(encoding="utf-8")
    return {
        m.group(1): set(re.findall(r"\n\s+pub (\w+)\s*:", m.group(2)))
        for m in re.finditer(r"pub struct (\w+)\s*\{(.*?)\n\}", src, re.S)
    }


def _python_models() -> dict[str, set[str]]:
    """Pydantic model name -> its field names."""
    return {
        name: set(obj.model_fields)
        for name, obj in inspect.getmembers(models, inspect.isclass)
        if hasattr(obj, "model_fields") and obj.__module__ == models.__name__
    }


def test_the_rust_config_file_is_where_we_think_it_is():
    """A moved file would make every comparison below vacuously pass."""
    assert RUST_CONFIG.is_file(), f"{RUST_CONFIG} not found"
    assert _rust_structs(), "no structs parsed — the regex has gone stale"


@pytest.mark.parametrize("struct", sorted(set(_rust_structs()) & set(_python_models())))
def test_both_schemas_declare_the_same_fields(struct):
    """Neither parser may know a field the other does not."""
    rust = _rust_structs()[struct]
    python = _python_models()[struct]
    only_python = python - rust
    only_rust = rust - python
    assert not only_python, (
        f"{struct}: {sorted(only_python)} declared in models.py but not in "
        f"config.rs — the Rust renderer will reject a site.yml using them"
    )
    assert not only_rust, (
        f"{struct}: {sorted(only_rust)} declared in config.rs but not in "
        f"models.py — the Python tooling will reject a site.yml using them"
    )


def test_the_shared_structs_are_not_a_trivial_set():
    """Guard the guard: if the name matching broke, this suite proves nothing."""
    shared = set(_rust_structs()) & set(_python_models())
    assert len(shared) >= 8, f"only {len(shared)} structs matched by name: {shared}"
