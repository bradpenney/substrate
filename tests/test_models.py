"""The typed site.yml models (ADR-089).

These replaced a hand-written validator that indexed a bare dict. The properties
worth pinning are the ones that used to fail late and vaguely: a misspelled key
silently ignored, a wrong type surviving until something tried to use it, and an
optional section being absent meaning "crash" rather than "skip that feature".
"""

from __future__ import annotations

import copy

import pytest
import yaml
from pydantic import ValidationError

import models
import siteconfig


@pytest.fixture(scope="module")
def raw():
    """The fixture config as a plain dict, exactly as YAML delivers it."""
    return yaml.safe_load(
        (siteconfig.REPO_ROOT / "tests/fixtures/site.yml").read_text(encoding="utf-8")
    )


def test_the_fixture_validates(raw):
    cfg = models.SiteConfig(**raw)
    assert len(cfg.nodes) == 5
    assert len(cfg.hypervisors) == 2


def test_typed_access_replaces_string_indexing(raw):
    """The point of the exercise: `cfg.network.gateway` is checked at load,
    where `cfg["network"]["gateway"]` is checked when something happens to
    read it."""
    cfg = models.SiteConfig(**raw)
    assert isinstance(cfg.network.gateway, str)
    assert isinstance(cfg.defaults.memory_mib, int)
    assert isinstance(cfg.nodes["b-vm1"].bootstrap, bool)


def test_a_misspelled_key_is_rejected_not_ignored(raw):
    """extra="forbid" is the whole reason these models exist. Without it a typo
    leaves the default in place and the config appears to work — the same
    failure kubeconform was added to catch on the manifests side."""
    bad = copy.deepcopy(raw)
    bad["network"]["gatway"] = bad["network"].pop("gateway")
    with pytest.raises(ValidationError) as e:
        models.SiteConfig(**bad)
    msg = str(e.value)
    assert "gatway" in msg and "gateway" in msg


def test_a_missing_required_section_is_rejected(raw):
    bad = copy.deepcopy(raw)
    del bad["network"]
    with pytest.raises(ValidationError):
        models.SiteConfig(**bad)


def test_optional_sections_may_be_absent(raw):
    """A fleet with no control-plane LB, no External Secrets and no public site
    is a valid smaller deployment; the tooling skips those checks rather than
    refusing to start."""
    minimal = copy.deepcopy(raw)
    for section in (
        "control_plane",
        "external_secrets",
        "api_hardening",
        "posture",
        "dns",
    ):
        minimal.pop(section, None)
    cfg = models.SiteConfig(**minimal)
    assert cfg.posture.public_hostname is None
    assert cfg.control_plane.vip is None


def test_node_sizing_overrides_are_optional(raw):
    """Omitted sizing means "use defaults" — modelled as None rather than 0, so
    "not specified" and "explicitly zero" stay distinguishable."""
    bare = copy.deepcopy(raw)
    bare["nodes"]["b-vm2"] = {"hypervisor": "hvB", "ip": "10.99.0.99"}
    cfg = models.SiteConfig(**bare)
    assert cfg.nodes["b-vm2"].memory_mib is None
    assert cfg.nodes["b-vm2"].storage_disk_gb is None


def test_a_wrong_type_is_rejected(raw):
    """YAML is hand-edited, and the cost of a wrong type is discovering it three
    minutes into a provisioning run."""
    bad = copy.deepcopy(raw)
    bad["defaults"]["vcpu"] = "four"
    with pytest.raises(ValidationError):
        models.SiteConfig(**bad)


def test_load_model_and_load_agree():
    """Both run the same validation, so they cannot disagree about what is
    valid — which is what makes migrating callers one at a time safe."""
    as_dict = siteconfig.load()
    as_model = siteconfig.load_model()
    assert as_model.admin_user == as_dict["admin_user"]
    assert as_model.network.gateway == as_dict["network"]["gateway"]
    assert set(as_model.nodes) == set(as_dict["nodes"])


def test_the_merged_version_fields_are_modelled():
    """load() merges the committed versions.yml into flux/kairos. The models
    describe the object callers RECEIVE, not just the raw file."""
    cfg = siteconfig.load_model()
    assert cfg.kairos.iso_sha256
    assert cfg.flux.operator_version


# --------------------------------------------------- the reformatted error path


def test_shape_errors_are_reported_readably_not_as_a_traceback(raw, monkeypatch):
    """pydantic reports a field path; this file's other messages explain what to
    do. Whoever hits this is usually mid-provision, so the error is reformatted
    into the same style as the rest — and every offending field is listed, not
    just the first."""
    bad = copy.deepcopy(raw)
    bad["network"]["gatway"] = bad["network"].pop("gateway")
    bad["defaults"]["vcpu"] = "four"

    with pytest.raises(SystemExit) as e:
        siteconfig._validate_shape(bad)

    msg = str(e.value)
    assert "does not match the expected schema" in msg
    assert "network.gateway" in msg  # the missing required field
    assert "network.gatway" in msg  # the typo that caused it
    assert "defaults.vcpu" in msg  # and the unrelated type error


def test_shape_validation_passes_a_good_config(raw):
    """Guard against the check becoming unconditionally noisy."""
    siteconfig._validate_shape(copy.deepcopy(raw))
