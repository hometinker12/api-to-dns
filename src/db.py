import os
from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.orm import sessionmaker

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
