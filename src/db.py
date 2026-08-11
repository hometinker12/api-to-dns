import os

from sqlalchemy.orm import sessionmaker
from sqlmodel import Session, SQLModel, create_engine

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/app.db")

if DATABASE_URL.startswith("sqlite:///"):
    data_dir = os.path.dirname(DATABASE_URL.replace("sqlite:///", ""))
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite:///") else {},
)
SessionLocal = sessionmaker(class_=Session, autoflush=False, bind=engine)


def init_db() -> None:
    from . import models  # noqa: F401 — register SQLModel subclasses before create_all

    SQLModel.metadata.create_all(engine)
    _migrate_add_user_roles_column()
    _migrate_add_user_disabled_column()
    _migrate_add_user_session_version_column()
    _migrate_activity_log_category_column()
    _migrate_alert_rule_category_column()
    _migrate_activity_log_indexes()
    _migrate_add_api_key_prefix_column()
    _migrate_add_api_key_access_mode_column()
    _migrate_hash_plaintext_api_keys()
    _migrate_rate_limit_bucket_table()


def _migrate_add_api_key_prefix_column() -> None:
    """Add ``key_prefix`` for displaying API keys without storing plaintext."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "apikey" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("apikey")}
    if "key_prefix" in columns:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE apikey ADD COLUMN key_prefix VARCHAR DEFAULT ''"))


def _migrate_add_api_key_access_mode_column() -> None:
    """Add access mode while preserving full access for existing API keys."""
    from sqlalchemy import inspect, text

    from .models import API_KEY_ACCESS_READ_WRITE

    inspector = inspect(engine)
    if "apikey" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("apikey")}
    with engine.begin() as conn:
        if "access_mode" not in columns:
            conn.execute(
                text(
                    f"ALTER TABLE apikey ADD COLUMN access_mode VARCHAR DEFAULT '{API_KEY_ACCESS_READ_WRITE}' NOT NULL"
                )
            )
        conn.execute(
            text(
                "UPDATE apikey "
                f"SET access_mode = '{API_KEY_ACCESS_READ_WRITE}' "
                "WHERE access_mode IS NULL OR TRIM(access_mode) = ''"
            )
        )


def _migrate_hash_plaintext_api_keys() -> None:
    """Hash any legacy plaintext API keys still stored in ``apikey.key``."""
    from sqlmodel import select

    from .models import ApiKey
    from .security import api_key_prefix, hash_api_key, is_api_key_hash

    with Session(engine) as db:
        changed = False
        for row in db.exec(select(ApiKey)).all():
            raw = row.key or ""
            if is_api_key_hash(raw):
                if not (row.key_prefix or "").strip():
                    # Prefix is unrecoverable once hashed; keep a stable marker.
                    row.key_prefix = "hashed"
                    db.add(row)
                    changed = True
                continue
            row.key_prefix = api_key_prefix(raw)
            row.key = hash_api_key(raw)
            db.add(row)
            changed = True
        if changed:
            db.commit()


def _migrate_add_user_roles_column() -> None:
    """Add the `roles` column to existing `user` tables created before role support."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "user" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("user")}
    if "roles" in columns:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE user ADD COLUMN roles VARCHAR DEFAULT ''"))


def _migrate_add_user_disabled_column() -> None:
    """Add the `disabled` column to existing `user` tables created before account disabling."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "user" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("user")}
    if "disabled" in columns:
        return
    with engine.begin() as conn:
        default_value = "false" if engine.dialect.name != "sqlite" else "0"
        conn.execute(text(f"ALTER TABLE user ADD COLUMN disabled BOOLEAN DEFAULT {default_value} NOT NULL"))


def _migrate_add_user_session_version_column() -> None:
    """Add ``session_version`` so password/role changes can invalidate cookies."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "user" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("user")}
    if "session_version" in columns:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE user ADD COLUMN session_version INTEGER DEFAULT 0 NOT NULL"))


def _migrate_rate_limit_bucket_table() -> None:
    """Ensure the shared rate-limit table exists (create_all covers new installs)."""
    from sqlalchemy import inspect

    from .models import RateLimitBucket

    inspector = inspect(engine)
    if RateLimitBucket.__tablename__ in inspector.get_table_names():
        return
    RateLimitBucket.__table__.create(bind=engine, checkfirst=True)


def _migrate_activity_log_indexes() -> None:
    """Ensure indexes on ``activity_log`` exist for tables created before logging."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "activity_log" not in inspector.get_table_names():
        return
    existing = {idx["name"] for idx in inspector.get_indexes("activity_log")}
    wanted = {
        "ix_activity_log_timestamp": "timestamp",
        "ix_activity_log_event_type": "event_type",
        "ix_activity_log_level": "level",
        "ix_activity_log_category": "category",
        "ix_activity_log_zone_name": "zone_name",
    }
    with engine.begin() as conn:
        for index_name, column_name in wanted.items():
            if index_name in existing:
                continue
            conn.execute(text(f"CREATE INDEX {index_name} ON activity_log ({column_name})"))


def _migrate_activity_log_category_column() -> None:
    """Add the `category` column to existing activity log tables."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "activity_log" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("activity_log")}
    if "category" in columns:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE activity_log ADD COLUMN category VARCHAR"))


def _migrate_alert_rule_category_column() -> None:
    """Add the `category` column to existing alert rule tables."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "alert_rule" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("alert_rule")}
    if "category" in columns:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE alert_rule ADD COLUMN category VARCHAR"))
