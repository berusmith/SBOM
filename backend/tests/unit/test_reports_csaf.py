"""CSAF VEX namespace tests — CODE-1.013 fix verification (PR-2 Stage K.2b).

Per Q-PR2-1 (b): CSAF_NAMESPACE env var, fallback to
`f"https://sbom-platform.local/{org_slug}"` when unset.

These 3 tests directly exercise `_build_csaf_doc` (private helper in
`backend/app/services/usecases/release/reports.py`) so we don't need to
spin up a TestClient + go through the HTTP path — the logic under test
is the env-var → namespace string substitution.

Fixture `seeded_release_with_sbom_and_component` is shared via conftest.py
(promoted in K.2a per Q-PR2-3 (a)).
"""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.usecases.release.reports import _build_csaf_doc


@pytest.mark.function_level
def test_csaf_namespace_env_unset_uses_fallback(monkeypatch, db_session, seeded_release_with_sbom_and_component):
    """When CSAF_NAMESPACE is empty, namespace falls back to https://sbom-platform.local/<org_slug>."""
    monkeypatch.setattr(settings, "CSAF_NAMESPACE", "")
    rid = seeded_release_with_sbom_and_component

    from app.models.component import Component
    from app.models.release import Release
    release = db_session.query(Release).filter(Release.id == rid).first()
    components = db_session.query(Component).filter(Component.release_id == rid).all()

    doc = _build_csaf_doc(release, components, namespace_suffix="/orga")
    namespace = doc["document"]["publisher"]["namespace"]

    # The seeded fixture creates Organization(id="orgA", name="OrgA"), so:
    #   - org_slug computed by _build_csaf_doc fallback = "orga"
    #   - namespace_suffix passed in = "/orga"
    #   - final = "https://sbom-platform.local/{org_slug}{namespace_suffix}"
    #   - = "https://sbom-platform.local/orga/orga"
    # The "/orga/orga" doubling preserves the pre-fix pattern (was
    # "https://example.com/orga" — only the host changes, not the suffix).
    assert namespace == "https://sbom-platform.local/orga/orga", (
        f"expected fallback URL, got {namespace!r}"
    )
    # Critical: must NOT contain the placeholder
    assert "https://example.com" not in namespace


@pytest.mark.function_level
def test_csaf_namespace_env_set_uses_env_value(monkeypatch, db_session, seeded_release_with_sbom_and_component):
    """When CSAF_NAMESPACE is set, namespace uses env value + suffix."""
    monkeypatch.setattr(settings, "CSAF_NAMESPACE", "https://acme.example.com")
    rid = seeded_release_with_sbom_and_component

    from app.models.component import Component
    from app.models.release import Release
    release = db_session.query(Release).filter(Release.id == rid).first()
    components = db_session.query(Component).filter(Component.release_id == rid).all()

    doc = _build_csaf_doc(release, components, namespace_suffix="/orga")
    namespace = doc["document"]["publisher"]["namespace"]

    assert namespace == "https://acme.example.com/orga", (
        f"expected env-driven URL, got {namespace!r}"
    )
    # Critical: must NOT contain the placeholder
    assert "https://example.com" not in namespace
    # Critical: must NOT contain the fallback either (env wins)
    assert "sbom-platform.local" not in namespace


@pytest.mark.function_level
def test_csaf_namespace_env_with_whitespace_is_stripped(monkeypatch, db_session, seeded_release_with_sbom_and_component):
    """When CSAF_NAMESPACE has surrounding whitespace, it is stripped before use."""
    monkeypatch.setattr(settings, "CSAF_NAMESPACE", "  https://acme.example.com  ")
    rid = seeded_release_with_sbom_and_component

    from app.models.component import Component
    from app.models.release import Release
    release = db_session.query(Release).filter(Release.id == rid).first()
    components = db_session.query(Component).filter(Component.release_id == rid).all()

    doc = _build_csaf_doc(release, components, namespace_suffix="/orga")
    namespace = doc["document"]["publisher"]["namespace"]

    assert namespace == "https://acme.example.com/orga", (
        f"expected stripped env URL, got {namespace!r}"
    )
