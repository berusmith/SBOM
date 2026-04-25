#!/usr/bin/env python3
"""
SQLite → PostgreSQL data migration for SBOM Platform.

Reads from a source SQLite DB and copies all rows into a destination Postgres
database, in foreign-key dependency order.  Schema on the destination is built
from the current SQLAlchemy models (Base.metadata.create_all) so the migration
also acts as a fresh-init for an empty Postgres.

Usage:
    # From repo root.  Source defaults to backend/sbom.db; dest is required.
    python deploy/migrate-sqlite-to-postgres.py \\
        --dest "postgresql+psycopg2://sbom_user:PASS@127.0.0.1:5432/sbom"

    # With explicit source and force-overwrite of existing dest data:
    python deploy/migrate-sqlite-to-postgres.py \\
        --source "sqlite:///path/to/sbom.db" \\
        --dest   "postgresql+psycopg2://sbom_user:PASS@127.0.0.1:5432/sbom" \\
        --force

Behavior:
    * Builds destination schema via Base.metadata.create_all (idempotent).
    * Refuses to migrate if dest tables already contain rows, unless --force
      is given (in which case rows are DELETEd in reverse FK order).
    * Skips source tables that don't exist (older schemas, partial setups).
    * Only copies columns present in BOTH source and dest (forwards-compatible
      with schema additions).
    * Wraps the entire copy in a single transaction — partial failure rolls back.

Note: This is a one-shot tool, not a continuous replication system.  Stop the
backend before running so no writes happen during migration.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# ── Bootstrap: make `app.*` imports work without running main.py side effects ──
REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# Importing app.core.database touches DATABASE_URL at module load.  Force a safe
# in-memory SQLite default so this script doesn't accidentally connect to the
# user's real DB just by being loaded.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

# Register every model on Base.metadata.  Some are exported by app.models
# already; the others must be imported explicitly so their tables exist.
from app.core.database import Base  # noqa: E402
from app.models import (  # noqa: F401, E402
    organization, product, release, component, vulnerability, compliance, vex,
)
from app.models import alert_config as _alert_config  # noqa: F401, E402
from app.models import api_token as _api_token  # noqa: F401, E402
from app.models import audit_event as _audit_event  # noqa: F401, E402
from app.models import brand_config as _brand_config  # noqa: F401, E402
from app.models import cra_incident as _cra_incident  # noqa: F401, E402
from app.models import firmware_scan as _firmware_scan  # noqa: F401, E402
from app.models import license_rule as _license_rule  # noqa: F401, E402
from app.models import password_reset_token as _password_reset_token  # noqa: F401, E402
from app.models import policy_rule as _policy_rule  # noqa: F401, E402
from app.models import revoked_token as _revoked_token  # noqa: F401, E402
from app.models import share_link as _share_link  # noqa: F401, E402
from app.models import tisax as _tisax  # noqa: F401, E402
from app.models import user as _user  # noqa: F401, E402
from app.models import vex_history as _vex_history  # noqa: F401, E402


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", default=f"sqlite:///{BACKEND_DIR / 'sbom.db'}",
                   help="Source DB DSN (default: sqlite:///<repo>/backend/sbom.db)")
    p.add_argument("--dest", required=True,
                   help="Destination Postgres DSN (postgresql+psycopg2://user:pass@host/db)")
    p.add_argument("--force", action="store_true",
                   help="DELETE existing rows in dest before copying (DESTRUCTIVE)")
    p.add_argument("--dry-run", action="store_true",
                   help="Show row counts that WOULD be copied; don't write anything")
    return p.parse_args()


def assert_dest_clean_or_force(dst_engine, sorted_tables, force: bool) -> None:
    with dst_engine.connect() as conn:
        non_empty = []
        for tbl in sorted_tables:
            count = conn.execute(select(tbl).with_only_columns(*[tbl.c[next(iter(tbl.c.keys()))]])).fetchall()
            # Cheap row count: SELECT 1 LIMIT 1
            row = conn.execute(tbl.select().limit(1)).first()
            if row is not None:
                non_empty.append(tbl.name)
        if non_empty:
            if not force:
                print(f"\nERROR: destination already has data in: {', '.join(non_empty)}")
                print("Pass --force to DELETE existing rows before migration (DESTRUCTIVE).")
                sys.exit(1)
            print(f"--force: will delete existing rows in {len(non_empty)} table(s) before copy.")


def truncate_dest(conn, sorted_tables) -> None:
    """DELETE rows in reverse FK order so children go before parents."""
    for tbl in reversed(list(sorted_tables)):
        conn.execute(tbl.delete())


def copy_table(src_conn, dst_conn, tbl, src_inspector, dry_run: bool) -> int:
    """Copy one table, intersecting columns of source and dest. Returns row count."""
    if not src_inspector.has_table(tbl.name):
        return -1  # sentinel: source table missing

    src_cols = {c["name"] for c in src_inspector.get_columns(tbl.name)}
    dst_cols = set(tbl.c.keys())
    common = src_cols & dst_cols
    missing_in_src = dst_cols - src_cols
    missing_in_dst = src_cols - dst_cols

    if not common:
        return -2  # sentinel: no common columns (broken)

    select_cols = [tbl.c[name] for name in common]
    rows = list(src_conn.execute(select(*select_cols)).mappings())

    suffix = ""
    if missing_in_src:
        suffix += f" [src missing: {','.join(sorted(missing_in_src))}]"
    if missing_in_dst:
        suffix += f" [src extra (skipped): {','.join(sorted(missing_in_dst))}]"

    if not rows:
        print(f"  {tbl.name:<30} 0 rows{suffix}")
        return 0

    if not dry_run:
        # mappings() returns RowMapping objects; insert() accepts a list of dicts
        dst_conn.execute(tbl.insert(), [dict(r) for r in rows])

    print(f"  {tbl.name:<30} {len(rows):>6} rows{suffix}")
    return len(rows)


def main() -> int:
    args = parse_args()

    print("=== SBOM SQLite → Postgres migration ===")
    print(f"  source: {args.source}")
    print(f"  dest:   {args.dest}")
    print(f"  force:  {args.force}")
    print(f"  dry-run: {args.dry_run}")
    print()

    if not args.dest.startswith(("postgresql://", "postgresql+")):
        print("ERROR: --dest must be a postgresql:// DSN (got: %r)" % args.dest)
        return 2
    if not args.source.startswith("sqlite"):
        print("ERROR: --source must be a sqlite:// DSN (got: %r)" % args.source)
        return 2

    src_engine = create_engine(args.source)
    dst_engine = create_engine(args.dest)

    # Probe dest reachability early
    try:
        with dst_engine.connect() as c:
            c.execute(select(1))
    except Exception as e:
        print(f"ERROR: cannot connect to dest: {e}")
        return 3

    # Build dest schema (idempotent)
    print("Creating destination schema (Base.metadata.create_all) ...")
    Base.metadata.create_all(dst_engine, checkfirst=True)
    print(f"Schema has {len(Base.metadata.sorted_tables)} tables.\n")

    sorted_tables = Base.metadata.sorted_tables

    if not args.dry_run:
        assert_dest_clean_or_force(dst_engine, sorted_tables, args.force)

    src_inspector = inspect(src_engine)

    print("Copying tables (FK-dependency order):")
    total = 0
    skipped_missing = 0
    skipped_broken = 0

    with src_engine.connect() as src_conn, dst_engine.begin() as dst_conn:
        if args.force and not args.dry_run:
            truncate_dest(dst_conn, sorted_tables)

        for tbl in sorted_tables:
            n = copy_table(src_conn, dst_conn, tbl, src_inspector, args.dry_run)
            if n == -1:
                print(f"  {tbl.name:<30} (not in source, skipped)")
                skipped_missing += 1
            elif n == -2:
                print(f"  {tbl.name:<30} (no common columns, skipped)")
                skipped_broken += 1
            else:
                total += n

    print()
    print("=" * 60)
    if args.dry_run:
        print(f"DRY-RUN: would copy {total} rows across "
              f"{len(sorted_tables) - skipped_missing - skipped_broken} tables.")
    else:
        print(f"Migration complete: {total} rows copied across "
              f"{len(sorted_tables) - skipped_missing - skipped_broken} tables.")
    if skipped_missing:
        print(f"  ({skipped_missing} table(s) absent in source — skipped)")
    if skipped_broken:
        print(f"  ({skipped_broken} table(s) with no common columns — skipped)")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
