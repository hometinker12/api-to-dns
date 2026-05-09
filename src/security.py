import os
import secrets
from passlib.context import CryptContext
from cryptography.fernet import Fernet

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if ENCRYPTION_KEY is None:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
fernet = Fernet(ENCRYPTION_KEY.encode())


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def encrypt_value(value: str) -> str:
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    return fernet.decrypt(value.encode()).decode()
