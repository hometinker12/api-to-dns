from typing import Optional

from sqlmodel import select

from .models import Setting
from .security import decrypt_value, encrypt_value


def get_setting(db, name: str) -> Optional[str]:
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    return decrypt_value(record.value) if record else None


def set_setting(db, name: str, value: str) -> None:
    encrypted = encrypt_value(value)
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    if record:
        record.value = encrypted
    else:
        db.add(Setting(name=name, value=encrypted))
    db.commit()


def delete_setting(db, name: str) -> None:
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    if record:
        db.delete(record)
    db.commit()
