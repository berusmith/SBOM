from sqlalchemy import create_engine, event, func
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")


def days_between(later, earlier):
    """Cross-DB SQL expression for the number of days between two DateTime columns.

    SQLite has julianday() but no extract(); Postgres has extract() but no julianday().
    Use this helper instead of either dialect-specific function when computing
    elapsed days inside a query (e.g. average days-to-fix).
    """
    if _is_sqlite:
        return func.julianday(later) - func.julianday(earlier)
    return func.extract("epoch", later - earlier) / 86400.0

if _is_sqlite:
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA journal_mode=WAL")
        dbapi_conn.execute("PRAGMA busy_timeout=5000")

else:
    # Postgres (or any other dialect)
    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,   # detect stale connections
        pool_recycle=1800,    # recycle every 30 min
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
