"""
Shared pytest fixtures for backend/tests/unit/.

Two flavours of test live here:
  - function_level — pytest marker; tests call helpers directly (e.g.
    is_suppressed(vuln)).  No FastAPI app, no DB session needed unless the
    helper takes one.  Counts toward AC-T1 (≥ 1/3 of new tests).
  - http — pytest marker; tests use the `client` fixture (FastAPI TestClient,
    in-process, no network).  Captures HTTP contract for refactor safety.

The db_session fixture provides an isolated SQLite :memory: with all ORM
tables created.  Each test gets a fresh DB; nothing persists between tests.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend/ is on sys.path so `from app.X import Y` works regardless of
# pytest invocation cwd.  Mirrors the pattern already in
# tests/test_endpoint_decorator_enforcement.py.
_BACKEND = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_engine():
    """Fresh in-memory SQLite engine per test, with all ORM tables created."""
    # Import here (not at module top) so app.main module-level migrations
    # don't fire against :memory: at import time.
    from app.core.database import Base
    # Force-import every model module so Base.metadata knows about all tables
    # (mirrors the noqa: F401 imports in app/main.py).
    import app.models.vulnerability  # noqa: F401
    import app.models.release        # noqa: F401
    import app.models.product        # noqa: F401
    import app.models.organization   # noqa: F401
    import app.models.component      # noqa: F401
    import app.models.user           # noqa: F401
    import app.models.cra_incident   # noqa: F401
    import app.models.audit_event    # noqa: F401
    import app.models.api_token      # noqa: F401
    import app.models.alert_config   # noqa: F401
    import app.models.brand_config   # noqa: F401
    import app.models.policy_rule    # noqa: F401
    import app.models.license_rule   # noqa: F401
    import app.models.share_link     # noqa: F401
    import app.models.password_reset_token  # noqa: F401
    import app.models.revoked_token  # noqa: F401
    import app.models.firmware_scan  # noqa: F401
    import app.models.tisax          # noqa: F401
    import app.models.vex            # noqa: F401
    import app.models.vex_history    # noqa: F401
    import app.models.compliance     # noqa: F401

    # CRITICAL: `sqlite:///:memory:` creates a SEPARATE database per connection.
    # Two pool checkouts → two independent empty databases → tables missing in
    # the second one.  StaticPool forces every "connection" to be the same
    # underlying sqlite3.Connection, so all sessions see the same in-memory DB.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """Per-test SQLAlchemy Session bound to an in-memory engine."""
    SessionLocal = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    """FastAPI TestClient with get_db overridden to use the test session.

    Use for HTTP-level characterization tests.  Function-level tests do NOT
    need this — they import the helper directly.
    """
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.database import get_db

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass  # session lifecycle managed by the db_session fixture above

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)
